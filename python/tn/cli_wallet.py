"""``tn wallet ...`` CLI verbs — vault link/unlink/sync/status/pull-prefs,
multi-device restore (mnemonic, account-bound loopback, passphrase fallback),
and mnemonic export.

Thin over the wallet SDK surface (`tn.wallet`, `tn.wallet_pull`,
`tn.wallet_restore*`): these verbs resolve the identity + ceremony, drive the
push/pull/restore engines, and narrate progress. `_pull_absorb_step` is the
shared pull+absorb leg used by both `tn wallet sync` and the library
warm-attach path (`tn init`), so cli_init imports it from here.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import webbrowser
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Any
from urllib.parse import quote

import tn

from . import admin as _admin
from . import wallet as _wallet
from . import wallet_restore as _wallet_restore
from . import wallet_restore_loopback as _wallet_restore_loopback
from . import wallet_restore_passphrase as _wallet_restore_passphrase
from .awk_pickup import resolve_cached_awk
from .cli_common import (
    _die,
    _is_tty,
    _load_identity_or_die,
    _print_mnemonic_banner,
    _resolve_yaml_or_discover,
)
from .identity import Identity, IdentityError, _default_identity_path
from .signing import DeviceKey as _DeviceKey
from .sync_state import get_account_id, is_account_bound
from .vault_client import VaultClient, resolve_vault_url
from .wallet_pull import pull_and_absorb, stage_account_inbox

# ---------------------------------------------------------------------
# `tn wallet status`
# ---------------------------------------------------------------------


def cmd_wallet_status(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    if not identity_path.exists():
        print(f"No identity at {identity_path}. Run `tn init <project>` first.")
        return 0
    identity = Identity.load(identity_path)
    print(f"Identity: {identity.did}")
    print(f"  file:    {identity_path}")
    print(f"  linked:  {identity.linked_vault or '(not linked)'}")
    print(f"  prefs:   default_new_ceremony_mode={identity.prefs.default_new_ceremony_mode}")
    print(f"           prefs_version={identity.prefs_version}")

    if args.yaml:
        yaml_path = Path(args.yaml).resolve()
        if not yaml_path.exists():
            print(f"Ceremony: (no yaml at {yaml_path})")
            return 0
        tn.init(yaml_path, identity=identity)
        cfg = tn.current_config()
        print(f"Ceremony: {cfg.ceremony_id}")
        print(f"  yaml:            {yaml_path}")
        print(f"  mode:            {cfg.mode}")
        print(f"  cipher:          {cfg.cipher_name}")
        print(f"  linked_vault:    {cfg.linked_vault or '(none)'}")
        print(f"  linked_project:  {cfg.linked_project_id or '(none)'}")
        print(f"  groups:          {list(cfg.groups.keys())}")
        # Pending autosync failures
        pending = _wallet.read_sync_queue(cfg.ceremony_id)
        if pending:
            print(f"  pending_sync:    {len(pending)} queued failure(s)")
            latest = pending[-1]
            print(f"    latest:        {latest.get('error', '(no message)')}")
            print(f"    run:           tn wallet sync {args.yaml} --drain-queue")
        else:
            print("  pending_sync:    (queue empty)")
        tn.flush_and_close()
    return 0


# ---------------------------------------------------------------------
# `tn wallet link <yaml>`
# ---------------------------------------------------------------------


def cmd_wallet_link(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)

    vault_url = args.vault or identity.linked_vault
    if not vault_url:
        _die("--vault <url> is required (no vault cached in identity.json)")

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path, identity=identity)
    cfg = tn.current_config()

    client = VaultClient.for_identity(identity, vault_url)
    try:
        # 0.4.2a9: omit explicit project_name so wallet.link_ceremony
        # uses cfg.project_name when present, falls back to ceremony_id
        # otherwise. Legacy ceremonies with no project_name field keep
        # linking under their random ceremony_id label.
        _wallet.link_ceremony(cfg, client)
        result = _wallet.sync_ceremony(cfg, client)
        print(f"Linked {cfg.ceremony_id} -> {vault_url}/projects/{cfg.linked_project_id}")
        print(f"  uploaded {len(result.uploaded)} files")
        if result.errors:
            print(f"  WARN {len(result.errors)} errors: {result.errors}")

        # Cache the vault URL in identity.json if this is the first link.
        if identity.linked_vault != vault_url:
            identity.linked_vault = vault_url
            identity.ensure_written(identity_path)
    finally:
        client.close()
        tn.flush_and_close()
    return 0


# ---------------------------------------------------------------------
# `tn wallet unlink <yaml>`
# ---------------------------------------------------------------------


def cmd_wallet_unlink(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path, identity=identity)
    cfg = tn.current_config()
    prior_vault = cfg.linked_vault
    _admin.set_link_state(cfg, mode="local")
    print(f"Unlinked {cfg.ceremony_id} (was {prior_vault or 'not linked'})")
    tn.flush_and_close()
    return 0


# ---------------------------------------------------------------------
# `tn wallet sync <yaml>`
# ---------------------------------------------------------------------


def cmd_wallet_sync(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path, identity=identity)
    cfg = tn.current_config()

    # --pull is independent of the linked-vault push state: receive-side
    # parity. The DID was bound to a vault account via `tn account
    # connect`, so we can hit /api/v1/account/inbox over that DID's
    # challenge-issued JWT and stage every snapshot addressed to any of
    # the account's owned DIDs (the dashboard does the same aggregation).
    if getattr(args, "pull", False):
        return _cmd_wallet_sync_pull(cfg, identity, yaml_path)

    push_only = getattr(args, "push_only", False)
    drain_queue = getattr(args, "drain_queue", False)
    # Account passphrase: derives the AWK that wraps the project BEK for the
    # AWK/BEK whole-body push (the passphrase fallback to the device-seed
    # path). Accept it from --passphrase or the TN_ACCOUNT_PASSPHRASE env
    # var so headless runs don't echo it on argv.
    passphrase = getattr(args, "passphrase", None) or os.environ.get(
        "TN_ACCOUNT_PASSPHRASE"
    )
    # Normalized vault coordinates: the project-level ``vault:`` block is
    # authoritative (a declared-but-disabled vault means NO push), with the
    # legacy ``ceremony.linked_*`` fields as fallback.
    link = _wallet.vault_link_info(cfg)

    # Resolve cached AWK for unattended sync.
    # Only used when no explicit passphrase was supplied — the passphrase
    # path derives its own AWK inline inside sync_ceremony.
    account_id = get_account_id(yaml_path) or (
        identity.linked_account_id if identity else None
    )
    # Drain this device's AWK inbox then read the cache.
    # The browser sealed a pickup to this device DID at
    # claim/approve time; draining it caches the AWK so the push below can
    # wrap the BEK without a passphrase. Shared with the library autosync hook
    # (tn.admin._maybe_autosync) via resolve_cached_awk so a running logger and
    # the CLI behave identically. Skipped when an explicit passphrase was given
    # (that path derives its own AWK inside sync_ceremony).
    awk: bytes | None = None
    if not passphrase:
        drain_url = link.url or (identity.linked_vault if identity else None)
        if drain_url:
            awk, account_id = resolve_cached_awk(
                vault_url=drain_url,
                device_seed=identity.device_private_key_bytes(),
                account_id_hint=account_id,
            )
            if account_id and identity and not identity.linked_account_id:
                identity.linked_account_id = account_id
                identity.ensure_written(identity_path)
    try:
        # Step 1 (two-way sync): pull the account inbox and ABSORB it
        # before pushing, so a revocation another device/publisher made
        # is merged into local state first and an informed re-add is
        # surfaced. Skipped for --push-only and for the drain-queue retry.
        if not push_only and not drain_queue:
            _pull_absorb_step(cfg, identity, yaml_path)

        # Step 2: push (backup keystore + yaml to the linked vault). The
        # normalized ``link`` view gates the push: vault sync disabled or
        # URL-less means nothing to push (main's guard semantics).
        if not link.enabled or not link.url:
            if push_only:
                _die(f"ceremony {cfg.ceremony_id} is not linked; nothing to push")
            if not is_account_bound(yaml_path):
                _die(
                    f"ceremony {cfg.ceremony_id} is not linked and not "
                    f"account-bound; nothing to sync. Run `tn wallet link` "
                    f"and/or `tn account connect <code>`.",
                )
            print(
                "  (push skipped: ceremony not linked to a vault; "
                "run `tn wallet link` to enable backup)"
            )
            return 0

        client = VaultClient.for_identity(identity, link.url)
        try:
            if drain_queue:
                pending_before = len(_wallet.read_sync_queue(cfg.ceremony_id))
                result = _wallet.drain_sync_queue(cfg, client, passphrase=passphrase)
                pending_after = len(_wallet.read_sync_queue(cfg.ceremony_id))
                print(f"Drained sync queue for {cfg.ceremony_id}")
                print(f"  pending before: {pending_before}, after: {pending_after}")
                print(f"  uploaded {len(result.uploaded)} files")
                if result.errors:
                    print(f"  WARN {len(result.errors)} still failing: {result.errors}")
                    return 1
                return 0

            # Author the group-keys snapshot AS the identity the `client`
            # authenticates as (DID challenge) — the vault's inbox POST
            # requires manifest.publisher_identity == auth_did. Mirrors the
            # TS `publishGroupKeys(client, identity, ...)` author key.
            identity_signer = _DeviceKey.from_private_bytes(
                identity.device_private_key_bytes()
            )
            result = _wallet.sync_ceremony(
                cfg,
                client,
                passphrase=passphrase,
                sign_with=identity_signer,
                author_did=identity.did,
                awk=awk,
            )
            print(f"Synced {cfg.ceremony_id} -> {link.url}")
            print(f"  uploaded {len(result.uploaded)} files: {result.uploaded}")
            if result.published_groups:
                print(
                    "  published group keys to own inbox: "
                    f"{result.published_groups}"
                )
            if result.publish_warning:
                print(f"  WARN group-keys publish failed: {result.publish_warning}")
            if result.errors:
                print(f"  WARN {len(result.errors)} errors: {result.errors}")
                return 1
        finally:
            client.close()
    finally:
        tn.flush_and_close()
    return 0


def _pull_absorb_step(cfg: Any, identity: Identity, yaml_path: Path) -> int:
    """`tn wallet sync` pull+absorb leg — pull the account inbox, ABSORB
    each staged snapshot (the merge), and surface INFORMED leaf-reuse.

    Thin CLI wrapper over :func:`tn.wallet_pull.pull_and_absorb`, passing
    ``print`` so progress is narrated. The engine is shared with the
    library init path (``_init_attach.attach_or_sync``) so the CLI and the
    notebook ``tn.init()`` reconcile identically.
    """
    return pull_and_absorb(cfg, identity, yaml_path, report=print)


def _cmd_wallet_sync_pull(cfg: Any, identity: Identity, yaml_path: Path) -> int:
    """`tn wallet sync --pull`: stage the account inbox WITHOUT absorbing.

    Back-compat escape hatch: the operator inspects the staged files and
    runs ``tn absorb <path>`` separately. (Bare ``tn wallet sync`` now
    absorbs for you — see :func:`_pull_absorb_step`.)
    """
    staged_result = stage_account_inbox(cfg, identity, yaml_path)
    if staged_result is None:
        tn.flush_and_close()
        _die(
            "no account binding for this ceremony. Run "
            "`tn account connect <code>` first to bind this DID to a "
            "vault account.",
            code=2,
        )
    staged, skipped = staged_result
    tn.flush_and_close()
    for p in staged:
        print(f"staged -> {p}")
    print(
        f"Pulled {len(staged)} snapshot(s); run `tn absorb <path>` "
        f"on each to materialize."
    )
    if skipped:
        print(f"  ({skipped} already staged locally and skipped)")
    return 0


# ---------------------------------------------------------------------
# `tn wallet pull-prefs`
# ---------------------------------------------------------------------


def cmd_wallet_pull_prefs(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)

    vault_url = args.vault or identity.linked_vault
    if not vault_url:
        _die("--vault <url> required (no vault cached in identity.json)")

    client = VaultClient.for_identity(identity, vault_url)
    try:
        prefs = client.get_prefs()
        identity.prefs.default_new_ceremony_mode = prefs["default_new_ceremony_mode"]
        identity.prefs_version = int(prefs["prefs_version"])
        identity.ensure_written(identity_path)
        print(f"Pulled prefs from {vault_url}:")
        print(f"  default_new_ceremony_mode: {identity.prefs.default_new_ceremony_mode}")
        print(f"  prefs_version: {identity.prefs_version}")
    finally:
        client.close()
    return 0


# ---------------------------------------------------------------------
# `tn wallet restore --mnemonic "..."`
# ---------------------------------------------------------------------


def _is_new_flow_restore(args: argparse.Namespace) -> bool:
    """Detect the account-bound / passphrase-fallback restore path.

    The legacy mnemonic flow is selected by passing ``--mnemonic`` /
    ``--mnemonic-file``; the absence of either, combined with an
    ``--out-dir`` (or the ``--passphrase`` flag), routes us to the new
    flow handler in :func:`_cmd_wallet_restore_account_bound`.
    """
    return (
        args.mnemonic is None
        and args.mnemonic_file is None
        and (args.out_dir is not None or getattr(args, "passphrase", False))
    )


def _resolve_restore_mnemonic(args: argparse.Namespace) -> str:
    """Resolve the 12/24-word recovery phrase from CLI args.

    Precedence: ``--mnemonic-file`` > ``--mnemonic`` > interactive
    prompt. In non-TTY contexts (CI, docker, ssh-without-tty) the
    prompt path is forbidden and we exit with code 2 so the operator
    fixes their invocation instead of the script hanging on stdin.
    """
    if args.mnemonic_file is not None:
        return Path(args.mnemonic_file).read_text(encoding="utf-8").strip()
    if args.mnemonic is not None:
        return args.mnemonic.strip()
    if not _is_tty():
        _die(
            "--mnemonic or --mnemonic-file required in non-TTY contexts "
            "(or pass an output directory to use the new account-bound flow)",
            code=2,
        )
    return getpass.getpass("Enter your 12/24-word recovery phrase: ").strip()


def _restore_identity_only(
    identity: Identity, identity_path: Path, vault_url: str | None
) -> int:
    """Write the recovered identity to disk and stop.

    Used in the vault-less case (no ``--vault`` passed): we restore
    just the device key from the mnemonic and exit so the operator can
    bootstrap a fresh ceremony manually.
    """
    if vault_url is not None:
        identity.linked_vault = vault_url
    identity.ensure_written(identity_path)
    print(f"Identity restored to {identity_path}")
    print(f"  DID: {identity.did}")
    if vault_url is not None:
        print(f"  vault: {vault_url}")
    return 0


def _select_projects_to_restore(
    args: argparse.Namespace, projects: list[dict[str, Any]]
) -> set[Any]:
    """Pick which vault-side projects to pull.

    Precedence: ``--project-ids`` > ``--all-projects`` (or non-TTY) >
    interactive comma-separated indexes prompt. Always returns a set
    of project ids that the caller can intersect against the
    ``projects`` list.
    """
    if args.project_ids:
        return set(args.project_ids.split(","))
    if args.all_projects or not _is_tty():
        return {p.get("id") or p.get("_id") for p in projects}
    picks = input("Enter comma-separated indexes to restore (or 'all'): ").strip()
    if picks.lower() == "all":
        return {p.get("id") or p.get("_id") for p in projects}
    idx = [int(x) for x in picks.split(",") if x.strip()]
    return {(projects[i].get("id") or projects[i].get("_id")) for i in idx}


def _pull_selected_projects(
    client: VaultClient,
    projects: list[dict[str, Any]],
    selected_ids: set[Any],
    out_dir: Path,
) -> None:
    """For each selected project, fetch its ceremony bundle into a
    sibling directory under ``out_dir`` and print a per-project summary.

    Errors are surfaced inline as ``WARN`` lines rather than raised —
    one bad project shouldn't block the others.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    for p in projects:
        pid = p.get("id") or p.get("_id")
        if pid is None or pid not in selected_ids:
            continue
        target = out_dir / str(p.get("name") or pid)
        print(f"Restoring {pid} -> {target}")
        result = _wallet.restore_ceremony(client, str(pid), target_dir=target)
        print(f"  pulled {len(result.files_restored)} files: {result.files_restored}")
        if result.errors:
            print(f"  WARN {len(result.errors)} errors: {result.errors}")


def cmd_wallet_restore(args: argparse.Namespace) -> int:
    """Restore a ceremony from the vault.

    Two flows:

    * **Account-bound (default)**: opens a browser to the vault's
      ``/restore`` page, completes OAuth + passkey unlock, and the
      browser POSTs a transfer token (vault JWT + raw BEK) back to a
      one-shot loopback server on 127.0.0.1. The CLI then fetches the
      encrypted blob and decrypts. See spec section 9.9.

    * **Legacy mnemonic**: ``--mnemonic`` / ``--mnemonic-file`` keeps
      the original mode for backups produced by the pre-account-bound
      SDK.
    """
    # Reconcile positional out_dir with the legacy --out-dir flag.
    if getattr(args, "out_dir_flag", None) and not args.out_dir:
        args.out_dir = args.out_dir_flag

    if _is_new_flow_restore(args):
        return _cmd_wallet_restore_account_bound(args)

    # Legacy mnemonic path. Resolve the phrase, build the identity,
    # refuse to clobber an existing one without --force, then either
    # stop (no vault) or list+select+restore projects.
    mnemonic = _resolve_restore_mnemonic(args)
    try:
        identity = Identity.from_mnemonic(mnemonic)
    except IdentityError as e:
        _die(f"bad mnemonic: {e}")

    identity_path = _default_identity_path()
    if identity_path.exists() and not args.force:
        _die(
            f"{identity_path} already exists. Use --force to overwrite "
            f"(existing identity will be destroyed).",
            code=2,
        )

    if args.vault is None:
        print("No --vault passed; restoring identity only (no ceremonies).")
        return _restore_identity_only(identity, identity_path, vault_url=None)

    _restore_identity_only(identity, identity_path, vault_url=args.vault)

    client = VaultClient.for_identity(identity, args.vault)
    try:
        projects = client.list_projects()
        if not projects:
            print("No linked ceremonies on the vault. Restore complete.")
            return 0

        print(f"Found {len(projects)} linked ceremonies:")
        for i, p in enumerate(projects):
            pid = p.get("id") or p.get("_id")
            print(f"  [{i}] {pid}  name={p.get('name', '(unnamed)')}")

        selected_ids = _select_projects_to_restore(args, projects)
        base_restore_dir = Path(args.out_dir or "./restored").resolve()
        _pull_selected_projects(client, projects, selected_ids, base_restore_dir)
    finally:
        client.close()
    return 0


# ---------------------------------------------------------------------
# `tn wallet restore` — account-bound flow. See spec section 9.9.
# ---------------------------------------------------------------------


def _cmd_wallet_restore_account_bound(args: argparse.Namespace) -> int:
    """New flow: browser does OAuth + passkey + unwrap, CLI gets BEK.

    The restore is account-bound (not package-bound) and handler-driven:
    keys are per-account AWK wrapping a per-project BEK, with a passphrase
    fallback when the device seed is unavailable.
    """
    out_dir = Path(args.out_dir).resolve() if args.out_dir else None
    if out_dir is None:
        _die("an output directory is required for account-bound restore")

    vault_url = resolve_vault_url(args.vault).rstrip("/")

    # ── Passphrase path (fallback when the device seed is unavailable) ──
    if getattr(args, "passphrase", False):
        return _restore_via_passphrase(
            vault_url=vault_url,
            out_dir=out_dir,
            credential_id=getattr(args, "credential_id", None),
            project_id=getattr(args, "project_id", None),
            session_token=getattr(args, "session_token", None),
        )

    # ── Loopback path (default) ──
    timeout = float(getattr(args, "timeout", 0) or 300.0)
    # Pass the vault origin so the loopback server emits CORS headers.
    # The browser fetch can then run mode:"cors" and observe a real
    # status code instead of the opaque "no-cors" success, which would
    # otherwise mask a failed POST back to the CLI.
    receiver = _wallet_restore_loopback.LoopbackReceiver.start(
        port=getattr(args, "port", None) or None,
        allow_origin=vault_url,
    )
    print(f"Loopback receiver listening on {receiver.callback_url}")
    print(f"State nonce: {receiver.state[:8]}...")

    # Open the browser to the vault /restore page. The page reads the
    # query string for return_to + state, runs OAuth + passkey, and
    # POSTs the transfer token back to our loopback.
    restore_url = (
        f"{vault_url}/restore?return_to={quote(receiver.callback_url, safe='')}"
        f"&state={quote(receiver.state, safe='')}"
    )
    print(f"Open this URL to continue: {restore_url}")
    try:
        webbrowser.open(restore_url, new=1)
    except Exception:  # noqa: BLE001 — non-fatal; user can still copy
        print("(could not auto-open a browser; paste the URL above manually)")

    print(f"Waiting for browser handoff (timeout {timeout:.0f}s)…")
    try:
        token = receiver.wait_for_token(timeout_seconds=timeout)
    except TimeoutError as e:
        receiver.shutdown()
        _die(str(e), code=2)
    except Exception as e:  # noqa: BLE001 — propagate as a clean exit
        receiver.shutdown()
        _die(f"loopback receive failed: {e}")
    finally:
        receiver.shutdown()

    print(f"Token received from browser. project_id={token.project_id}")

    try:
        result = _wallet_restore._restore_with_token(
            vault_url=vault_url,
            token=token,
            out_dir=out_dir,
        )
    except _wallet_restore.RestoreError as e:
        _die(f"restore failed: {e}")

    print(f"Restored to {result.out_dir}")
    print(f"  account_id: {result.account_id}")
    print(f"  project_id: {result.project_id}")
    for note in result.notes:
        print(f"  note: {note}")
    for f in result.files_written:
        print(f"  wrote: {f}")
    return 0


def _restore_via_passphrase(
    *,
    vault_url: str,
    out_dir,
    credential_id: str | None,
    project_id: str | None,
    session_token: str | None,
) -> int:
    """Passphrase fallback: derive credential key locally, unwrap BEK."""
    if not session_token:
        _die(
            "--session-token is required for passphrase-only restore. Obtain one "
            "by running OAuth in a browser and copying the token from "
            "the response (or use the loopback flow instead).",
            code=2,
        )

    if not project_id:
        # Pull the list and ask the user which one.
        try:
            list_url = f"{vault_url.rstrip('/')}/api/v1/account/projects"
            code, body = _wallet_restore_passphrase._bearer_get(list_url, session_token)
        except _wallet_restore.RestoreError as e:
            _die(str(e))
        if code != 200:
            _die(
                f"projects list returned HTTP {code}: "
                f"{body[:200].decode('utf-8', errors='replace')}",
            )
        rows = json.loads(body.decode("utf-8"))
        if not rows:
            _die("no restorable projects on this account")
        for i, r in enumerate(rows):
            label = r.get("label") or r.get("project_id")
            print(f"  [{i}] {r.get('project_id')}  {label}")
        if not _is_tty():
            _die("--project-id is required in non-TTY contexts", code=2)
        choice = input("Pick a project index: ").strip()
        try:
            picked = rows[int(choice)].get("project_id")
        except (ValueError, IndexError):
            _die("invalid project pick", code=2)
        # project_id is the vault-side project identity — without it there is
        # no wrapped-key / blob to fetch. Enforce it rather than letting a
        # None slip into the BEK derivation (which builds /projects/<id>/...).
        if not picked:
            _die("selected project has no project_id", code=2)
        project_id = str(picked)

    if not _is_tty():
        _die("passphrase prompt requires a TTY", code=2)
    passphrase = getpass.getpass("Enter your account passphrase: ")
    if not passphrase:
        _die("empty passphrase", code=2)

    try:
        bek = _wallet_restore_passphrase._derive_bek_via_passphrase(
            vault_url=vault_url,
            bearer=session_token,
            project_id=project_id,
            passphrase=passphrase,
            credential_id=credential_id,
        )
    except _wallet_restore.RestoreError as e:
        _die(f"derivation failed: {e}")

    # Build a synthetic transfer token for _restore_with_token.
    token = _wallet_restore_loopback.TransferToken(
        vault_jwt=session_token,
        account_id="(passphrase-flow)",
        project_id=project_id,
        raw_bek_b64=urlsafe_b64encode(bek).decode("ascii").rstrip("="),
    )
    try:
        result = _wallet_restore._restore_with_token(
            vault_url=vault_url,
            token=token,
            out_dir=out_dir,
        )
    except _wallet_restore.RestoreError as e:
        _die(f"restore failed: {e}")

    print(f"Restored to {result.out_dir}")
    print(f"  project_id: {result.project_id}")
    for f in result.files_written:
        print(f"  wrote: {f}")
    return 0


# ---------------------------------------------------------------------
# `tn wallet watch`
# ---------------------------------------------------------------------


def cmd_wallet_watch(args: argparse.Namespace) -> int:
    """Periodic unattended sync. Honors vault_sync_interval_seconds (default
    600s). Uses the cached AWK; Ctrl-C to stop."""
    import time

    yaml_path = _resolve_yaml_or_discover(getattr(args, "yaml", None))
    identity_path = _default_identity_path()
    while True:
        rc = cmd_wallet_sync(argparse.Namespace(
            yaml=str(yaml_path) if yaml_path is not None else None,
            pull=False,
            push_only=False,
            drain_queue=False,
            passphrase=None,
            vault=getattr(args, "vault", None),
        ))
        try:
            identity = _load_identity_or_die(identity_path)
            tn.init(yaml_path, identity=identity)
            cfg = tn.current_config()
            interval = getattr(cfg, "vault_sync_interval_seconds", 600) or 600
        except Exception:  # noqa: BLE001 — non-fatal; fall back to default cadence
            interval = 600
        finally:
            tn.flush_and_close()
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[tn wallet watch] stopped.")
            return 0


# ---------------------------------------------------------------------
# `tn wallet export-mnemonic`
# ---------------------------------------------------------------------


def cmd_wallet_export_mnemonic(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)
    if not identity.mnemonic_stored:
        _die(
            "no mnemonic stored on this machine. identity.json was "
            "created without --keep-mnemonic (the default and safer "
            "path), so the recovery phrase was only shown once at "
            "`tn init` time. Record it elsewhere when you first see it.\n"
            "\n"
            "If you want future `tn wallet export-mnemonic` calls to "
            "work, re-run `tn init <new-project> --keep-mnemonic` on a "
            "fresh project — this stores the phrase in identity.json "
            "(trades some security for recovery convenience).",
            code=2,
        )
    if not args.yes:
        print(
            "ABOUT TO DISPLAY YOUR RECOVERY PHRASE.\n"
            "Anyone watching your screen can steal your identity.\n"
            "Re-run with --yes to confirm, or Ctrl-C to abort.",
        )
        return 2
    _print_mnemonic_banner(identity.mnemonic_stored)
    return 0
