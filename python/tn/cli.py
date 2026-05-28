"""TN command-line interface.

Top-level verbs (CI-shaped — every verb runs unattended, machine output,
no interactive prompts unless a TTY is detected):

    tn init <project>        One-time scaffold of identity + ceremony.
                             Generates a BIP-39 mnemonic; in a TTY it's
                             shown once on stdout, in CI / non-TTY it's
                             persisted into identity.json and a one-line
                             status is printed (treat identity.json as
                             a secret then). Creates <project>/tn.yaml
                             + <project>/.tn/tn/keys/ and writes
                             identity.json to $XDG_DATA_HOME/tn/.

    tn add_recipient         One-shot mint+bundle for a new recipient.
        <group> <did|label>  Friendly wrapper over tn.pkg.bundle_for_recipient
        [--out path]         (the explicit verb is `tn bundle`).

    tn bundle <did> <out>    Mint a kit_bundle .tnpkg for one recipient.
        [--groups a,b,c]     Defaults to every non-internal group.

    tn rotate [<group>]      The deploy primitive. Bumps each target
        [--groups a,b,c]     group's index_epoch via tn.admin.rotate,
        [--out path]         then emits one kit_bundle .tnpkg per
                             surviving recipient — the artifact CI
                             uploads (or the publisher hands off
                             directly) so recipients get the new keys.
                             No arg = rotate every non-internal group.
                             Vault-linked ceremonies push state to the
                             vault as a side effect (autosync hook).

    tn absorb <package>      Install a .tnpkg into the active ceremony.
                             Bootstrap kinds (project_seed, identity_seed)
                             auto-bind the runtime when no init is bound.

    tn read [<log>]          Print a log in flat decoded form.

    tn streams ...           Multi-ceremony stream listing / validation.
    tn validate ...          Schema / catalog validation helpers.
    tn show ...              Reflective inspection (env, config, etc.).

    tn wallet ...            Subcommands for an already-scaffolded identity:
        link <yaml>          Create a vault project + flip ceremony to
                             mode=linked + initial sealed upload.
        unlink <yaml>        Flip back to mode=local (vault data untouched).
        sync <yaml>          Force-push current ceremony state to vault.
        status [<yaml>]      Summary: DID, linked vault, ceremony state.
        pull-prefs           Refresh cached account prefs from vault.
        restore              Pull identity + ceremonies down on a fresh
                             machine (--mnemonic "...").
        export-mnemonic      Re-display the current identity's mnemonic
                             (requires mnemonic-sealed storage or ABORTS
                             if identity.json doesn't keep it).

Python module entry point: `python -m tn.cli [verb] ...`
Installed console script: `tn [verb] ...`
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

import httpx

from . import admin as _admin
from . import wallet as _wallet
from . import wallet_restore as _wallet_restore
from . import wallet_restore_loopback as _wallet_restore_loopback
from . import wallet_restore_passphrase as _wallet_restore_passphrase
from .identity import Identity, IdentityError, _default_identity_path
from .vault_client import VaultClient, VaultError, resolve_vault_url

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _is_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _die(msg: str, code: int = 1) -> NoReturn:
    print(f"tn: error: {msg}", file=sys.stderr)
    sys.exit(code)


def _print_mnemonic_banner(mnemonic: str) -> None:
    bar = "=" * 76
    print()
    print(bar)
    print("  WRITE THIS DOWN NOW. You will NOT see it again without")
    print("  explicit re-display, and without it you CANNOT recover")
    print("  your TN identity if this machine is lost.")
    print(bar)
    print()
    print(f"  {mnemonic}")
    print()
    print(bar)
    print()


# ---------------------------------------------------------------------
# `tn init <project>`
# ---------------------------------------------------------------------


def _stamp_project_labels(
    yaml_path: Path,
    project_name: str | None,
    version_name: str | None,
) -> None:
    """Stamp ``ceremony.project_name`` / ``ceremony.version_name`` into
    an existing yaml. No-op when both are None. Used by ``tn init``
    to record the operator-chosen vault label at mint time.

    Read-modify-write via PyYAML to preserve every other key as the
    init machinery left it.
    """
    if project_name is None and version_name is None:
        return
    import yaml as _yaml
    with yaml_path.open("r", encoding="utf-8") as fh:
        doc = _yaml.safe_load(fh) or {}
    ceremony = doc.setdefault("ceremony", {})
    if project_name is not None:
        ceremony["project_name"] = project_name
    if version_name is not None:
        ceremony["version_name"] = version_name
    with yaml_path.open("w", encoding="utf-8") as fh:
        _yaml.safe_dump(doc, fh, sort_keys=False)


def _format_expires_local(expires_iso: str) -> str:
    """Render the vault's ISO-8601 UTC `expires_at` as local-time + UTC offset.

    Falls back to the raw ISO string on any parse failure so the operator
    is never deprived of the value just because the local-tz lookup hiccupped.
    """
    from datetime import datetime
    try:
        # Python 3.11+ handles trailing 'Z' and +00:00 the same way.
        dt = datetime.fromisoformat(expires_iso.replace("Z", "+00:00"))
        local = dt.astimezone()
        tz_label = local.strftime("%Z") or local.strftime("%z")
        return f"{local.strftime('%Y-%m-%d %H:%M:%S')} {tz_label}".strip()
    except (TypeError, ValueError):
        return expires_iso


def _try_warm_attach(
    yaml_path: Path, identity: Identity, vault_url: str, cipher: str | None
) -> bool:
    """Attach a freshly-minted ceremony to the device's vault account.

    The warm counterpart to the pending-claim/claim-URL flow. Reuses the
    authenticated wallet path: a DID-challenge JWT (the device key is a
    minted DID on the account) authorises ``link_ceremony`` to register
    the project and ``sync_ceremony`` to upload the initial backup — the
    same work the browser claim performs, minus the browser.

    Returns True when the project is linked under the account; False on
    any pre-binding failure (auth or link), so the caller can fall back
    to minting a claim URL. Never raises.
    """
    from . import current_config, flush_and_close
    from . import init as tn_init

    try:
        client = VaultClient.for_identity(identity, vault_url)
    except Exception as e:  # noqa: BLE001 — auth failure must not break init
        print(f"[tn init] WARN account auth failed ({e}); using claim URL instead")
        return False

    try:
        tn_init(yaml_path, cipher=cipher or "btn", identity=identity, link=False)
        cfg = current_config()
        _wallet.link_ceremony(cfg, client)
    except Exception as e:  # noqa: BLE001 — pre-binding failure -> cold fallback
        print(f"[tn init] WARN account attach failed ({e}); using claim URL instead")
        try:
            client.close()
        except Exception:
            pass
        return False

    # Past link_ceremony the project row exists; we are committed to the
    # warm path. sync errors are reported but don't revert to claim URL
    # (that would double-register the project).
    try:
        result = _wallet.sync_ceremony(cfg, client)
        print()
        print("[tn init] Attached to your vault account (no browser needed).")
        print(f"[tn init]   project:  {cfg.project_name or cfg.ceremony_id}")
        print(f"[tn init]   linked:   {vault_url}/projects/{cfg.linked_project_id}")
        print(f"[tn init]   uploaded: {len(result.uploaded)} file(s)")
        if result.errors:
            print(f"[tn init]   WARN {len(result.errors)} upload error(s): {result.errors}")
        print()
    finally:
        try:
            client.close()
        except Exception:
            pass
        flush_and_close()
    return True


def cmd_init(args: argparse.Namespace) -> int:
    """Scaffold identity (if absent) + ceremony at <project>/tn.yaml."""
    # Quiet the stdout handler by default: it echoes every log envelope
    # as JSON, which is useful for debugging but ruinous for the
    # human-facing CLI output (the user just wants the claim URL). Use
    # ``setdefault`` so an explicit ``TN_NO_STDOUT=0`` from the caller
    # still wins — same convention ``python -m tn`` uses (see
    # ``tn/__main__.py``).
    import os
    os.environ.setdefault("TN_NO_STDOUT", "1")

    # In non-TTY contexts (CI, container builds, scripts), `tn init` runs
    # unattended: no Enter-prompt to wait for, no mnemonic banner printed
    # to logs (which would leak the recovery phrase into CI artifacts).
    # The mnemonic is instead persisted into identity.json so the operator
    # can recover it later via `tn wallet export-mnemonic`. Identity.json
    # is then the secret-handling boundary — protect it the way you'd
    # protect any other secret material.
    #
    # Pre-existing identities skip this entirely: nothing is generated and
    # nothing is printed.
    non_tty_provision = (
        not _is_tty()
        and args.mnemonic_file is None
        and not _default_identity_path().exists()
    )
    if non_tty_provision:
        args.skip_confirm = True
        args.keep_mnemonic = True
        # Suppress the mnemonic banner; it would land in CI logs.
        global _print_mnemonic_banner  # noqa: PLW0603 — local override for non-TTY init
        _print_mnemonic_banner = lambda _m: None  # type: ignore[assignment]
        print(
            "[tn init] non-interactive mode: mnemonic will be persisted "
            "into identity.json (treat that file as a secret).",
        )

    # 0.5.0a2 layout: the ceremony lives at <cwd>/.tn/<project>/ — the
    # project name IS the ceremony name, all of it nested under a single
    # .tn/ at the cwd. (Prior layout put .tn under a per-project dir:
    # <cwd>/<project>/.tn/default/.) `project` may be passed as a bare
    # name or a path; only the basename is used as the ceremony name.
    from ._layout import (
        ceremony_yaml_path as _ceremony_yaml_path,
        is_valid_ceremony_name as _is_valid_ceremony_name,
        tn_root as _tn_root,
    )

    _project_arg = Path(args.project)
    ceremony_name = _project_arg.name
    if not _is_valid_ceremony_name(ceremony_name):
        _die(
            f"invalid project name {ceremony_name!r}: use letters, digits, "
            f"underscore, or dash (must not start with a dash, and 'tn' is "
            f"reserved)."
        )
    # Root the .tn/ at the parent of the project path. A bare name
    # (`tn init Foo`) roots at cwd -> ./.tn/Foo/. A path
    # (`tn init /abs/proj`) roots at its parent -> /abs/.tn/proj/.
    project_dir = (_project_arg.parent if str(_project_arg.parent) != "." else Path.cwd()).resolve()
    _tn_root(project_dir).mkdir(parents=True, exist_ok=True)

    identity_path = _default_identity_path()

    # -- Load or create identity ------------------------------------
    if identity_path.exists():
        identity = Identity.load(identity_path)
        print(f"[tn init] Reusing identity at {identity_path}")
        print(f"[tn init]   DID: {identity.did}")
    else:
        if args.mnemonic_file is not None:
            words = Path(args.mnemonic_file).read_text(encoding="utf-8").strip()
            identity = Identity.from_mnemonic(words)
            if args.keep_mnemonic:
                identity.mnemonic_stored = words
                identity._mnemonic = words
            print(f"[tn init] Identity derived from {args.mnemonic_file}")
        else:
            identity = Identity.create_new(word_count=args.words)
            _print_mnemonic_banner(identity._mnemonic or "")
            if args.keep_mnemonic:
                identity.mnemonic_stored = identity._mnemonic
                print(
                    "[tn init] --keep-mnemonic is SET: the recovery phrase "
                    "will be stored in identity.json alongside your keys.\n"
                    "[tn init] Anyone with read access to that file can steal "
                    "your identity. Use ONLY on hardware you trust.",
                )
            if not args.skip_confirm:
                _ = input("Press Enter after you have recorded the mnemonic... ")

        identity.ensure_written(identity_path)
        print(f"[tn init] New identity written to {identity_path}")
        print(f"[tn init]   DID: {identity.did}")

    # -- Create or attach to ceremony -------------------------------
    # 0.5.0a2: the ceremony is rooted at <cwd>/.tn/<project>/ — the
    # project name IS the ceremony name. Re-running `tn init <same name>`
    # is idempotent: re-attach instead of erroring. `--force` nukes and
    # re-mints (with a backup of the prior material into
    # `.tn/_overwritten_<UTC>/`).
    from . import current_config, flush_and_close
    from . import init as tn_init
    from ._multi import _ensure_ceremony_on_disk

    ceremony_d = _tn_root(project_dir) / ceremony_name
    yaml_path = ceremony_d / "tn.yaml"

    if yaml_path.exists() and args.force:
        # Move the existing ceremony aside so --force never deletes data
        # silently. The operator can recover by hand from the backup dir.
        import shutil
        from datetime import datetime, timezone
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = _tn_root(project_dir) / f"_overwritten_{ceremony_name}_{stamp}"
        shutil.move(str(ceremony_d), str(backup))
        print(f"[tn init] --force: prior ceremony moved to {backup}")

    if yaml_path.exists():
        # Idempotent re-attach. Matches Python `tn.init()`'s behaviour:
        # if the ceremony is already there, attach to it; don't mint a
        # second one and don't error.
        tn_init(yaml_path, identity=identity, link=False)
        cfg = current_config()
        print(f"[tn init] Reusing ceremony {cfg.ceremony_id} at {yaml_path}")
        print(f"[tn init]   cipher: {cfg.cipher_name}")
        print(f"[tn init]   keystore: {cfg.keystore}")
        flush_and_close()
        return 0

    # Mint the ceremony as a ROOT (its own keystore) under the project
    # name. `as_root=True` makes _ensure_ceremony_on_disk mint keys even
    # though the name isn't the literal "default".
    _ensure_ceremony_on_disk(
        ceremony_name,
        as_root=True,
        project_dir=project_dir,
        device_did=identity.did,
        profile=None,
        cipher=args.cipher,
        link=False,
    )
    # 0.5.0a2: the positional `project` IS the project name (no separate
    # --project-name flag). Stamp it into the freshly-minted yaml so the
    # vault link (next step) uses the human name instead of the random
    # ceremony_id.
    project_name = ceremony_name
    version_name = args.version_name  # None → wallet falls through to project_name
    _stamp_project_labels(yaml_path, project_name, version_name)
    tn_init(yaml_path, identity=identity, link=False)
    cfg = current_config()
    print(f"[tn init] Ceremony {cfg.ceremony_id} created at {yaml_path}")
    if cfg.project_name:
        print(f"[tn init]   project: {cfg.project_name}"
              + (f" (version: {cfg.version_name})" if cfg.version_name else ""))
    print(f"[tn init]   cipher: {cfg.cipher_name}")
    print(f"[tn init]   keystore: {cfg.keystore}")
    flush_and_close()

    # -- Auto-mint pending-claim + initial backup ------------------
    #
    # Resolution order for the vault URL:
    #   1. ``--link <url>``                  (explicit override)
    #   2. ``identity.linked_vault``         (remembered from a prior init)
    #   3. ``TN_VAULT_URL`` env var          (machine-wide default)
    #   4. ``https://vault.tn-proto.org``    (hosted tn-proto vault)
    #
    # ``--no-link`` opts out entirely (offline-only ceremonies).
    #
    # We use the pending-claim flow (``vault_push.init_upload``) rather
    # than the authenticated wallet flow because the canonical UX is:
    # fresh DID has no account on the vault yet, the user wants ONE link
    # they can paste into a browser to claim the project under their
    # (Google / passphrase) account in one shot. The endpoint is
    # unauthenticated by design (D-19); the BEK travels in the URL
    # fragment so the vault never sees it (D-5). The browser claim page
    # then handles OAuth/passkey-PRF and binds the project to the
    # account.
    #
    # If the vault is unreachable we warn loudly but don't fail the
    # init: the on-disk ceremony is still valid.
    if not args.no_link:
        vault_url = args.link or identity.linked_vault or resolve_vault_url(None)
        if identity.linked_vault is None:
            identity.linked_vault = vault_url
            identity.ensure_written(identity_path)

        # Warm path: if this device already belongs to a vault account,
        # attach the new project to that account over the device DID's
        # challenge-issued JWT — no browser claim needed. The warm signal
        # is TN_API_KEY in the environment (wins) or, as a fallback, the
        # account remembered in identity.json from a prior
        # `tn account connect`. Falls through to the claim-URL flow if
        # the authenticated attach can't be completed.
        warm_signal = os.environ.get("TN_API_KEY") or identity.linked_account_id
        if warm_signal and _try_warm_attach(yaml_path, identity, vault_url, args.cipher):
            return 0

        client = None
        try:
            from .handlers.vault_push import init_upload, _default_client_factory
            client = _default_client_factory(vault_url, identity)
            # Re-open cfg so init_upload reads the just-written ceremony.
            tn_init(yaml_path, cipher=args.cipher, identity=identity, link=False)
            cfg = current_config()
            result = init_upload(cfg, client, vault_base=vault_url)
            print()
            print(f"[tn init] Backed up to {vault_url}")
            print(f"[tn init]   vault_id:   {result['vault_id']}")
            print(f"[tn init]   expires:    {_format_expires_local(result['expires_at'])}")
            if result.get("reused"):
                print(f"[tn init]   (reusing live pending-claim within TTL)")
            print()
            print("[tn init] CLAIM URL - open this in your browser to attach the project to your account:")
            print(f"  {result['claim_url']}")
            print()
            print("[tn init] Already have a vault account, or want to attach this project later?")
            print(f"[tn init]   1. Sign in at {vault_url}/account")
            print(f"[tn init]   2. On the Projects tab, mint a connect code")
            print(f"[tn init]   3. Run:  tn account connect <code> --yaml {yaml_path}")
            print()
        except Exception as e:
            print(f"[tn init] WARN backup to vault failed: {e}")
            print(f"[tn init]   The ceremony at {yaml_path} is still valid; retry with")
            print(f"[tn init]   ``tn wallet link {yaml_path} --vault {vault_url}``.")
        finally:
            if client is not None:
                # _SnapshotPostingClient wraps a VaultClient; reach through.
                try:
                    client._vc.close()
                except Exception:
                    pass
            flush_and_close()

    return 0


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
        from . import current_config, flush_and_close
        from . import init as tn_init

        yaml_path = Path(args.yaml).resolve()
        if not yaml_path.exists():
            print(f"Ceremony: (no yaml at {yaml_path})")
            return 0
        tn_init(yaml_path, identity=identity)
        cfg = current_config()
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
        flush_and_close()
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

    from . import current_config, flush_and_close
    from . import init as tn_init

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn_init(yaml_path, identity=identity)
    cfg = current_config()

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
        flush_and_close()
    return 0


# ---------------------------------------------------------------------
# `tn wallet unlink <yaml>`
# ---------------------------------------------------------------------


def cmd_wallet_unlink(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)

    from . import current_config, flush_and_close
    from . import init as tn_init

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn_init(yaml_path, identity=identity)
    cfg = current_config()
    prior_vault = cfg.linked_vault
    _admin.set_link_state(cfg, mode="local")
    print(f"Unlinked {cfg.ceremony_id} (was {prior_vault or 'not linked'})")
    flush_and_close()
    return 0


# ---------------------------------------------------------------------
# `tn wallet sync <yaml>`
# ---------------------------------------------------------------------


def cmd_wallet_sync(args: argparse.Namespace) -> int:
    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)

    from . import current_config, flush_and_close
    from . import init as tn_init

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn_init(yaml_path, identity=identity)
    cfg = current_config()

    # --pull is independent of the linked-vault push state: receive-side
    # parity. The DID was bound to a vault account via `tn account
    # connect`, so we can hit /api/v1/account/inbox over that DID's
    # challenge-issued JWT and stage every snapshot addressed to any of
    # the account's owned DIDs (the dashboard does the same aggregation).
    if getattr(args, "pull", False):
        return _cmd_wallet_sync_pull(cfg, identity, yaml_path)

    if not cfg.is_linked():
        _die(f"ceremony {cfg.ceremony_id} is not linked; run `tn wallet link` first")

    if cfg.linked_vault is None:
        _die(f"ceremony {cfg.ceremony_id} reports linked but linked_vault is empty")
    client = VaultClient.for_identity(identity, cfg.linked_vault)
    try:
        if args.drain_queue:
            pending_before = len(_wallet.read_sync_queue(cfg.ceremony_id))
            result = _wallet.drain_sync_queue(cfg, client)
            pending_after = len(_wallet.read_sync_queue(cfg.ceremony_id))
            print(f"Drained sync queue for {cfg.ceremony_id}")
            print(f"  pending before: {pending_before}, after: {pending_after}")
            print(f"  uploaded {len(result.uploaded)} files")
            if result.errors:
                print(f"  WARN {len(result.errors)} still failing: {result.errors}")
                return 1
            return 0

        result = _wallet.sync_ceremony(cfg, client)
        print(f"Synced {cfg.ceremony_id} -> {cfg.linked_vault}")
        print(f"  uploaded {len(result.uploaded)} files: {result.uploaded}")
        if result.errors:
            print(f"  WARN {len(result.errors)} errors: {result.errors}")
            return 1
    finally:
        client.close()
        flush_and_close()
    return 0


def _cmd_wallet_sync_pull(cfg: Any, identity: Identity, yaml_path: Path) -> int:
    """Drain the vault's account-scoped inbox into the local inbox dir.

    Reuses the dashboard's account aggregator
    (``GET /api/v1/account/inbox``) so a CLI operator sees the same
    listing the browser does — every snapshot addressed to any DID in
    ``accounts.minted_dids[]`` belonging to this account.

    Per the receive-side parity brief: we intentionally do NOT call
    ``tn.absorb`` here. The handler-resident ``pull_inbox`` does that
    (it's the scheduled daemon path), but the CLI verb stops at staging
    so the operator can inspect the file and run ``tn absorb`` as a
    separate, observable step. This also keeps the verb usable for
    `tn sync --pull && for f in ...; do tn absorb "$f"; done` shell
    scripts without re-implementing absorb's manifest checks.

    Each snapshot lands at
    ``<conventions.inbox_dir(yaml_path)>/<from_did>/<ceremony_id>/<ts>.tnpkg``,
    mirroring the vault's URL shape so the absorb step is just a file
    path. Already-staged files are skipped (idempotent).
    """
    from . import flush_and_close
    from .conventions import inbox_dir
    from .sync_state import get_account_id, is_account_bound

    account_id = get_account_id(yaml_path)
    if not is_account_bound(yaml_path) or not account_id:
        flush_and_close()
        _die(
            "no account binding for this ceremony. Run "
            "`tn account connect <code>` first to bind this DID to a "
            "vault account.",
            code=2,
        )

    vault_url = identity.linked_vault or resolve_vault_url(None)
    client = VaultClient.for_identity(identity, vault_url)
    staged: list[Path] = []
    skipped = 0
    try:
        listing = _list_account_inbox(client)
        items = listing.get("items") or []
        if not items:
            print(f"Pulled 0 snapshot(s) for account {account_id}.")
            return 0

        target_root = inbox_dir(yaml_path)
        for item in items:
            if item.get("consumed_at"):
                # Already absorbed by another device / the dashboard;
                # don't re-stage.
                continue
            from_did = item.get("publisher_identity")
            ceremony_id = item.get("ceremony_id")
            ts = item.get("ts")
            if not (
                isinstance(from_did, str)
                and isinstance(ceremony_id, str)
                and isinstance(ts, str)
            ):
                continue

            dest_dir = target_root / _safe_path_seg(from_did) / _safe_path_seg(
                ceremony_id
            )
            dest = dest_dir / f"{ts}.tnpkg"
            if dest.exists():
                skipped += 1
                continue

            body = _download_account_inbox_snapshot(
                client, from_did=from_did, ceremony_id=ceremony_id, ts=ts
            )
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            staged.append(dest)

            kind = item.get("kind") or "?"
            size = item.get("byte_size") or len(body)
            print(
                f"staged {kind} from {from_did[:24]}... "
                f"({size} bytes) -> {dest}"
            )
    finally:
        client.close()
        flush_and_close()

    print(
        f"Pulled {len(staged)} snapshot(s); run `tn absorb <path>` "
        f"on each to materialize."
    )
    if skipped:
        print(f"  ({skipped} already staged locally and skipped)")
    return 0


def _safe_path_seg(seg: str) -> str:
    """Path-sanitize a DID / ceremony_id / ts segment.

    DIDs contain ':' which is illegal in Windows path components, and
    we don't want a malicious server-supplied value to escape the inbox
    root via '/' or '..'. Replace path-reserved chars with '_' and
    reject anything that walks above the inbox root.
    """
    cleaned = seg.replace(":", "_").replace("/", "_").replace("\\", "_")
    if cleaned in ("", ".", "..") or cleaned.startswith(".."):
        raise ValueError(f"unsafe path segment: {seg!r}")
    return cleaned


def _list_account_inbox(client: VaultClient) -> dict:
    """GET /api/v1/account/inbox using the client's existing bearer."""
    resp = client._request("GET", "/api/v1/account/inbox")
    client._raise_for_status(resp)
    return resp.json()


def _download_account_inbox_snapshot(
    client: VaultClient, *, from_did: str, ceremony_id: str, ts: str
) -> bytes:
    """Download the raw .tnpkg body via the account-auth route."""
    path = f"/api/v1/account/inbox/{from_did}/{ceremony_id}/{ts}.tnpkg"
    resp = client._request("GET", path)
    client._raise_for_status(resp)
    return resp.content


# ---------------------------------------------------------------------
# `tn account connect <code>` — bind this device's DID to a vault account
# ---------------------------------------------------------------------


def cmd_account_connect(args: argparse.Namespace) -> int:
    """Redeem a connect code against the vault and persist the binding.

    The receive-side dashboard mints a single-use ``tn_connect_<random>``
    code when the operator clicks "Connect a new app or device". The
    CLI counterpart pastes that code here. We load the device key from
    ``identity.json``, sign SHA-256 of the code with it, POST
    ``{code, did, signature_b64}`` to
    ``/api/v1/account/connect-codes/redeem``, and on success persist the
    returned ``account_id`` into the ceremony's sync state so subsequent
    verbs (``tn sync --pull``, ``tn absorb``) know which account this
    DID belongs to.

    The endpoint is intentionally unauthenticated — the code + signature
    are the authorization. Once the bind lands the DID is in the
    account's ``minted_dids[]`` and subsequent DID-challenge auth calls
    against ``/account/*`` routes work for this DID.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from .sync_state import mark_account_bound
    from .vault_client import redeem_connect_code

    identity_path = _default_identity_path()
    identity = _load_identity_or_die(identity_path)

    yaml_path = _resolve_yaml_or_discover(args.yaml)

    sk = Ed25519PrivateKey.from_private_bytes(identity.device_private_key_bytes())
    base_url = args.vault or identity.linked_vault

    try:
        resp = redeem_connect_code(args.code, identity.did, sk, base_url=base_url)
    except VaultError as exc:
        _die(
            f"connect-code redeem failed (status={exc.status}): {exc.body or exc}",
            code=1,
        )

    account_id = resp.get("account_id")
    if not isinstance(account_id, str) or not account_id:
        _die(
            "vault accepted the redeem but the response did not include "
            f"an account_id: {resp!r}",
        )

    # Persist the account binding into the ceremony's sync state so
    # subsequent CLI verbs (sync --pull, absorb -> /received-kits) can
    # find the bound account without re-reading the connect-code.
    mark_account_bound(yaml_path, account_id)

    # Also remember the account globally in identity.json so a later
    # `tn init` of a *different* project can auto-attach to this same
    # account (warm path) instead of minting a browser claim URL.
    if identity.linked_account_id != account_id:
        identity.linked_account_id = account_id
        identity.ensure_written(identity_path)

    print(f"Connected to vault account {account_id}")
    project_id = resp.get("project_id")
    project_name = resp.get("project_name")
    if project_id:
        print(f"  project_id:   {project_id}")
    if project_name:
        print(f"  project_name: {project_name}")
    print(f"  did:          {identity.did}")
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
      encrypted blob and decrypts. Resolves O-2; spec section 9.9.

    * **Legacy mnemonic**: ``--mnemonic`` / ``--mnemonic-file`` keeps
      the original mode for backups produced by the pre-account-bound
      SDK.

    Refs: D-3, D-19, D-20, D-22; plan
    ``docs/superpowers/plans/2026-04-29-multi-device-restore.md``.
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
# `tn wallet restore` — account-bound flow (Session 10).
# Resolves O-2; spec §9.9.
# ---------------------------------------------------------------------


def _cmd_wallet_restore_account_bound(args: argparse.Namespace) -> int:
    """New flow: browser does OAuth + passkey + unwrap, CLI gets BEK.

    Refs: D-3 (account vs package), D-19 (handler-driven sync), D-20
    (per-account AWK / per-project BEK), D-22 (passphrase fallback).
    """
    import webbrowser
    from pathlib import Path

    out_dir = Path(args.out_dir).resolve() if args.out_dir else None
    if out_dir is None:
        _die("an output directory is required for account-bound restore")

    vault_url = resolve_vault_url(args.vault).rstrip("/")

    # ── Passphrase path (D-22 fallback) ──
    if getattr(args, "passphrase", False):
        return _restore_via_passphrase(
            vault_url=vault_url,
            out_dir=out_dir,
            credential_id=getattr(args, "credential_id", None),
            project_id=getattr(args, "project_id", None),
            jwt=getattr(args, "jwt", None),
        )

    # ── Loopback path (default) ──
    timeout = float(getattr(args, "timeout", 0) or 300.0)
    # S2/S4 fix: pass the vault origin so the loopback server emits
    # CORS headers. The browser fetch can then run mode:"cors" and
    # observe a real status code instead of the opaque "no-cors"
    # success that masked failures in Session 10.
    receiver = _wallet_restore_loopback.LoopbackReceiver.start(
        port=getattr(args, "port", None) or None,
        allow_origin=vault_url,
    )
    print(f"Loopback receiver listening on {receiver.callback_url}")
    print(f"State nonce: {receiver.state[:8]}...")

    # Open the browser to the vault /restore page. The page reads the
    # query string for return_to + state, runs OAuth + passkey, and
    # POSTs the transfer token back to our loopback.
    from urllib.parse import quote

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
    jwt: str | None,
) -> int:
    """Passphrase fallback: derive credential key locally, unwrap BEK."""
    if not jwt:
        _die(
            "--jwt is required for passphrase-only restore. Obtain one "
            "by running OAuth in a browser and copying the token from "
            "the response (or use the loopback flow instead).",
            code=2,
        )

    if not project_id:
        # Pull the list and ask the user which one.
        try:
            list_url = f"{vault_url.rstrip('/')}/api/v1/account/projects"
            code, body = _wallet_restore_passphrase._bearer_get(list_url, jwt)
        except _wallet_restore.RestoreError as e:
            _die(str(e))
        if code != 200:
            _die(
                f"projects list returned HTTP {code}: "
                f"{body[:200].decode('utf-8', errors='replace')}",
            )
        import json as _json
        rows = _json.loads(body.decode("utf-8"))
        if not rows:
            _die("no restorable projects on this account")
        for i, r in enumerate(rows):
            label = r.get("label") or r.get("project_id")
            print(f"  [{i}] {r.get('project_id')}  {label}")
        if not _is_tty():
            _die("--project-id is required in non-TTY contexts", code=2)
        choice = input("Pick a project index: ").strip()
        try:
            project_id = rows[int(choice)]["project_id"]
        except (ValueError, IndexError):
            _die("invalid project pick", code=2)

    if not _is_tty():
        _die("passphrase prompt requires a TTY", code=2)
    passphrase = getpass.getpass("Enter your account passphrase: ")
    if not passphrase:
        _die("empty passphrase", code=2)

    try:
        bek = _wallet_restore_passphrase._derive_bek_via_passphrase(
            vault_url=vault_url,
            bearer=jwt,
            project_id=project_id,
            passphrase=passphrase,
            credential_id=credential_id,
        )
    except _wallet_restore.RestoreError as e:
        _die(f"derivation failed: {e}")

    # Build a synthetic transfer token for _restore_with_token.
    from base64 import urlsafe_b64encode

    token = _wallet_restore_loopback.TransferToken(
        vault_jwt=jwt,
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


# ---------------------------------------------------------------------
# `tn bundle <yaml> <recipient_did> <out>`
# `tn absorb <yaml> <package>`
# `tn read   <yaml> [<log>]`
# Three small recipient-flow verbs that mirror the cookbook §7 path so
# the cash-_register Stage 6 workflow is one CLI call per step. Closes
# FINDINGS #9.
# ---------------------------------------------------------------------


def _resolve_yaml_or_discover(arg: str | None) -> Path:
    """Resolve a yaml path: explicit arg if given; otherwise walk the same
    discovery chain ``tn.init()`` uses (``$TN_YAML``, ``./tn.yaml``,
    ``$TN_HOME/tn.yaml``), then fall back to any single ``*.yaml`` in
    the cwd that looks like a TN ceremony (top-level ``ceremony:`` AND
    ``me:`` blocks). Lets the recipient-flow verbs (S6.4) work as one
    bare command in a project dir whose yaml isn't called ``tn.yaml``
    — e.g. the cash-_register assignment's ``_register.yaml``.

    Errors loudly if nothing's found or multiple ceremonies tie. CLI
    verbs are operator actions, not onboarding flows; auto-creating a
    fresh ceremony from the CLI would surprise the caller."""
    if arg:
        p = Path(arg).resolve()
        if not p.exists():
            _die(f"yaml not found: {p}")
        return p
    from ._autoinit import _resolve_existing_yaml

    discovered = _resolve_existing_yaml()
    if discovered is not None:
        return discovered

    # Final fallback: any *.yaml in cwd that smells like a ceremony.
    cwd_candidates: list[Path] = []
    for entry in sorted(Path.cwd().iterdir()):
        if not entry.is_file() or entry.suffix not in (".yaml", ".yml"):
            continue
        try:
            head = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "ceremony:" in head and "me:" in head and "did:" in head:
            cwd_candidates.append(entry.resolve())
    if len(cwd_candidates) == 1:
        return cwd_candidates[0]
    if len(cwd_candidates) > 1:
        names = ", ".join(p.name for p in cwd_candidates)
        _die(
            f"multiple ceremony yamls in cwd ({names}). Pass --yaml to disambiguate."
        )
    _die(
        "no yaml found. Looked at $TN_YAML, ./tn.yaml, ~/.tn/tn.yaml, and "
        "any *.yaml in the cwd with a ceremony: block. Pass --yaml or `cd` "
        "into a project directory."
    )


def cmd_bundle(args: argparse.Namespace) -> int:
    from . import current_config, flush_and_close
    from . import init as tn_init
    from .pkg import bundle_for_recipient

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn_init(yaml_path)
    try:
        groups = args.groups.split(",") if args.groups else None
        out = bundle_for_recipient(
            args.recipient_did,
            args.out,
            groups=groups,
            seal_for_recipient=getattr(args, "seal_for_recipient", False),
        )
        cfg = current_config()
        # The bundle was just minted — every requested group has a fresh
        # tn.recipient.added event in the log. Print a one-line summary
        # the user can hand off alongside the .tnpkg.
        print(f"[tn bundle] wrote {out}")
        print(f"[tn bundle]   recipient: {args.recipient_did}")
        print(f"[tn bundle]   ceremony:  {cfg.ceremony_id}  (cipher={cfg.cipher_name})")
        print(f"[tn bundle]   groups:    {groups or sorted(g for g in cfg.groups if g != 'tn.agents')}")
    finally:
        flush_and_close()
    return 0


def cmd_add_recipient(args: argparse.Namespace) -> int:
    """Friendlier shape that matches the cash-_register assignment's
    expected line (FINDINGS S6.4)::

        python -m tn add_recipient <group> <did-or-label> [--out path]

    A bare label like ``professor`` is allowed — when it doesn't look
    like a DID we synthesize a fake one (``did:key:zLabel-<label>``) so
    the attestation event still records *something* identifiable. For
    real workflows, pass the recipient's actual DID.

    Output filename defaults to ``./<safe-label>.tnpkg`` so the student's
    one-line workflow ``... add_recipient default professor`` works as
    written. The yaml is auto-discovered via the standard chain.
    """
    import re as _re

    from . import flush_and_close
    from . import init as tn_init
    from .pkg import bundle_for_recipient

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    label = args.recipient
    if label.startswith("did:"):
        recipient_did = label
        out_default_stem = _re.sub(r"[^A-Za-z0-9._-]", "_", label.split(":")[-1])
    else:
        # Stable placeholder DID from the label — recorded on the
        # attestation event so the kit-recipient lookup works.
        recipient_did = f"did:key:zLabel-{label}"
        out_default_stem = _re.sub(r"[^A-Za-z0-9._-]", "_", label) or "recipient"

    # --seal-for-recipient needs a real key-DID to wrap the body under
    # the recipient's actual public key. A friendly label like
    # `did:key:zLabel-foo` has no embedded base58 public key, so the
    # seal path would fail deep inside `_did_key_to_ed25519_pub`. Reject
    # the combination here with a clear message.
    if getattr(args, "seal_for_recipient", False) and (
        not label.startswith("did:") or recipient_did.startswith("did:key:zLabel-")
    ):
        print(
            "[tn add_recipient] error: --seal-for-recipient requires a real "
            "key-DID for the recipient (one with an embedded base58 public "
            "key). Friendly labels synthesize a placeholder DID that has no "
            f"public key, so the seal step has nothing to wrap under. Got "
            f"{label!r}. Pass the recipient's real did:key:z... instead, or "
            "drop --seal-for-recipient to ship an unsealed kit bundle.",
            file=sys.stderr,
        )
        return 2

    out_path = Path(args.out).resolve() if args.out else Path.cwd() / f"{out_default_stem}.tnpkg"

    tn_init(yaml_path)
    try:
        groups = [args.group]
        out = bundle_for_recipient(
            recipient_did,
            out_path,
            groups=groups,
            seal_for_recipient=getattr(args, "seal_for_recipient", False),
        )
        print(f"[tn add_recipient] wrote {out}")
        print(f"[tn add_recipient]   group:     {args.group}")
        print(f"[tn add_recipient]   recipient: {recipient_did}")
    finally:
        flush_and_close()
    return 0


def cmd_absorb(args: argparse.Namespace) -> int:
    from . import current_config, flush_and_close
    from . import init as tn_init
    from .pkg import absorb

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    package = Path(args.package).resolve()
    if not package.exists():
        _die(f"package not found: {package}")

    tn_init(yaml_path)
    # 0.4.2a9: reject self-absorb. A .tnpkg whose `from_did` matches the
    # active ceremony's DID means the publisher is trying to absorb a
    # bundle they just minted — that overwrites their OWN publisher
    # keystore with a reader-kit copy. The absorb path warns on the
    # collision but proceeds; that's a foot-cannon in a CLI. Block it
    # at the verb so the user has to use `--allow-self-absorb` (escape
    # hatch for tests).
    import json
    import zipfile
    try:
        with zipfile.ZipFile(package) as zf:
            if "manifest.json" in zf.namelist():
                m = json.loads(zf.read("manifest.json").decode("utf-8"))
                from_did = m.get("publisher_identity")
                local_did = current_config().device.did
                if from_did and from_did == local_did and not getattr(
                    args, "allow_self_absorb", False
                ):
                    flush_and_close()
                    _die(
                        f"refusing to absorb a package this ceremony minted "
                        f"(from_did={from_did}). Absorbing it would overwrite "
                        f"the publisher's own keystore with a reader-kit "
                        f"copy. Pass --allow-self-absorb if you actually "
                        f"intend to do this (tests, recovery flows).",
                        code=2,
                    )
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError):
        # Not a zip / no manifest / bad JSON — let the real absorb path
        # produce its own error message about the corrupt package.
        pass

    try:
        receipt = absorb(package)
    finally:
        flush_and_close()

    kind = getattr(receipt, "kind", "?")
    accepted = getattr(receipt, "accepted_count", 0)
    skipped = getattr(receipt, "deduped_count", 0)
    print(f"[tn absorb] kind={kind} accepted={accepted} skipped={skipped}")
    replaced = list(getattr(receipt, "replaced_kit_paths", []) or [])
    if replaced:
        print(f"[tn absorb] WARN: overwrote {len(replaced)} existing kit file(s):")
        for p in replaced:
            print(f"             {p}")
        print(
            "[tn absorb] prior bytes preserved at <name>.previous.<UTC_TS> "
            "in the same directory."
        )
    return 0 if accepted >= 0 else 1


def cmd_rotate(args: argparse.Namespace) -> int:
    """Rotate group key material and emit per-recipient kit_bundle .tnpkg
    artifacts so the publisher can hand new kits to surviving recipients.

    The rotation primitive is the deploy event for a TN ceremony: it
    bumps the per-group ``index_epoch``, regenerates the publisher's
    self-kit, renames the prior key material to ``.revoked.<ts>`` (the
    publisher keeps the file on disk for keywalk exercises across
    rotation boundaries), and appends a ``tn.rotation.completed``
    attestation to the admin log. Recipients receive the new kit but
    keep their old ones too — also kept on disk for keywalk.

    Rotation is *not* eviction. The same recipient set carries
    forward; both pre- and post-rotation kits successfully decrypt
    both pre- and post-rotation entries. The new kit exists so the
    publisher can hand it to new recipients added after this point,
    and so the keystore generation count moves forward for
    audit/key-hygiene purposes. To actually remove a recipient,
    revoke them via ``admin_revoke_recipient`` before rotating.

    Vault-linked ceremonies push the new state on autosync as a side
    effect of the underlying ``tn.admin.rotate`` call (see
    ``_maybe_autosync``); the vault then drives recipient notification.
    Vault-less ceremonies rely on this CLI's per-recipient .tnpkg
    artifacts as the distribution channel — upload the directory as a
    CI artifact (``actions/upload-artifact`` or equivalent) and hand the
    individual files to recipients out-of-band.

    Group selection (in priority order):

      * positional ``<group>`` — single group only
      * ``--groups a,b,c``    — explicit subset
      * neither              — every non-internal group in the ceremony
                               (excludes ``tn.agents``, same convention
                               as ``tn bundle``).

    Output (``--out``):

      * absent                       → ``./rotated_<UTC_TS>/`` directory,
                                       one ``<recipient_safe>.tnpkg`` per
                                       surviving recipient.
      * existing directory           → same shape, in that directory.
      * path ending in ``.tnpkg``    → that exact file. Single-recipient
                                       only; rejected if the rotation
                                       affected more than one recipient.
    """
    import re
    import time

    from . import current_config, flush_and_close
    from . import init as tn_init
    from .pkg import bundle_for_recipient

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn_init(yaml_path)
    try:
        cfg = current_config()
        if cfg.cipher_name != "btn":
            _die(
                f"tn rotate currently supports btn ceremonies only; "
                f"this ceremony uses {cfg.cipher_name!r}.",
                code=2,
            )

        if args.group is not None and args.groups is not None:
            _die(
                "pass either a positional <group> or --groups, not both.",
                code=2,
            )
        if args.group is not None:
            target_groups = [args.group]
        elif args.groups is not None:
            target_groups = [g.strip() for g in args.groups.split(",") if g.strip()]
        else:
            target_groups = [g for g in cfg.groups if g != "tn.agents"]

        unknown = [g for g in target_groups if g not in cfg.groups]
        if unknown:
            _die(
                f"unknown group(s) {unknown!r}; ceremony declares "
                f"{sorted(cfg.groups)}.",
                code=2,
            )

        # Snapshot surviving recipients PRE-rotation so we know who to
        # mint new kits for. (Post-rotation the recipient list is
        # unchanged for btn — recipients are still active in the new
        # epoch — but reading the snapshot here makes the intent
        # explicit and survives any future semantic change.)
        recipient_groups: dict[str, list[str]] = {}
        for g in target_groups:
            for rec in _admin.recipients(g):
                if rec.get("revoked"):
                    continue
                rdid = rec.get("recipient_identity")
                if not isinstance(rdid, str):
                    continue
                recipient_groups.setdefault(rdid, []).append(g)

        # Rotate each group. Each call also fires _maybe_autosync, so
        # vault-linked ceremonies push state as a side effect.
        rotated: list[tuple[str, int]] = []
        for g in target_groups:
            res = _admin.rotate(g)
            rotated.append((g, res.generation or 0))

        # Resolve output destination.
        if not recipient_groups:
            print(
                "[tn rotate] rotated "
                f"{len(rotated)} group(s); no surviving recipients to "
                "bundle for. New kits will be minted on the next "
                "`tn add_recipient` / `tn bundle` call.",
            )
            for g, gen in rotated:
                print(f"             {g}: epoch={gen}")
            return 0

        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        out_arg = Path(args.out).resolve() if args.out else None
        if out_arg is None:
            out_dir = Path.cwd() / f"rotated_{ts}"
            single_file = None
        elif out_arg.suffix == ".tnpkg":
            if len(recipient_groups) > 1:
                _die(
                    f"--out {out_arg.name} is a single .tnpkg path but "
                    f"this rotation has {len(recipient_groups)} surviving "
                    "recipient(s). Pass a directory path (or omit --out) "
                    "to write one .tnpkg per recipient.",
                    code=2,
                )
            out_dir = out_arg.parent
            single_file = out_arg
        else:
            out_dir = out_arg
            single_file = None
        out_dir.mkdir(parents=True, exist_ok=True)

        # Bundle per recipient. bundle_for_recipient internally loops
        # admin.add_recipient (which mints fresh kits using the
        # post-rotation key material), so the artifact contains kits
        # the recipient can absorb to read post-rotation entries.
        artifacts: list[Path] = []
        for rdid, groups in recipient_groups.items():
            if single_file is not None:
                pkg_path = single_file
            else:
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", rdid)
                pkg_path = out_dir / f"{safe}.tnpkg"
            written = bundle_for_recipient(rdid, pkg_path, groups=groups)
            artifacts.append(Path(written))

        print(
            f"[tn rotate] rotated {len(rotated)} group(s); "
            f"emitted {len(artifacts)} .tnpkg artifact(s) "
            f"into {out_dir}",
        )
        for g, gen in rotated:
            print(f"             {g}: epoch={gen}")
        for art in artifacts:
            print(f"             -> {art.name}")
        return 0
    finally:
        flush_and_close()


def cmd_read(args: argparse.Namespace) -> int:
    from . import flush_and_close
    from . import init as tn_init
    from . import read as tn_read
    from ._multi import ceremony_yaml_path

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn_init(yaml_path)
    # 0.4.2a9: `tn read <name>` resolves a stream/ceremony name from the
    # local project's `.tn/<name>/tn.yaml` registry before falling back
    # to treating the positional as a literal log path. Matches what
    # `tn streams` lists. The lookup is anchored at the discovered
    # yaml's parent (the project root) so it works regardless of cwd.
    log_path = None
    if args.log:
        as_name = args.log
        # First, see if it's a registered stream name.
        project_dir = yaml_path.parent.parent.parent  # .tn/default/tn.yaml -> project root
        try:
            candidate_yaml = ceremony_yaml_path(as_name, project_dir=project_dir)
        except Exception:  # noqa: BLE001 — invalid name, fall through to path mode
            candidate_yaml = None
        if candidate_yaml is not None and candidate_yaml.is_file():
            # It IS a stream name. Re-init against that stream's yaml so
            # tn.read decrypts with the right per-stream config, then
            # read its main log file directly.
            tn_init(candidate_yaml)
            log_path = None  # use the stream's own resolved log path
        else:
            log_path = Path(args.log).resolve()
    try:
        for entry in tn_read(log=log_path, all_runs=args.all_runs):
            ts = entry.timestamp.isoformat() if entry.timestamp else "?"
            level = entry.level or ""
            et = entry.event_type or "?"
            # Inline user-emitted kwargs so the operator can eyeball the
            # log without piping to jq for every command. Envelope /
            # chain plumbing (did, sequence, hashes, signature, run_id,
            # hidden_groups) lives on typed attributes and is omitted
            # from the one-line view by design.
            extra_str = " ".join(f"{k}={v!r}" for k, v in entry.fields.items())
            print(f"{ts}  {level:<7} {et}  {extra_str}".rstrip())
    finally:
        flush_and_close()
    return 0


# ---------------------------------------------------------------------
# `tn show env` — reflective env-var inventory
# ---------------------------------------------------------------------
#
# Source of truth lives in two places:
#   1. ``docs/env-schema.md`` — the human reference.
#   2. ``_ENV_SCHEMA`` below — what the CLI reflects at runtime.
#
# Keep them in sync. Adding a new env-var read in ``tn/`` means a row in
# both. The ``read_today`` field controls whether a row shows up as a
# live environment knob or a *(proposed)* future binding.
#
# Reflective-only by design: this verb does NOT install any new env-var
# behavior. It reads what's already wired and prints. YAML-sourced rows
# (``yaml_field`` set) are best-effort: the verb tries to load the
# auto-discovered ceremony to fill in current values, but a missing /
# unparseable yaml is non-fatal — those cells just render ``(unset)``.

# Categories used for the human table. Order matters — we render in
# this sequence.
_ENV_CATEGORIES: tuple[str, ...] = (
    "identity",
    "vault",
    "ceremony",
    "runtime",
    "logging",
    "deployment",
    "handlers",
)


# Each entry: name, category, purpose, read_today flag, default-string,
# secret flag, precedence string, and an optional yaml_field for rows
# whose authoritative value lives in tn.yaml today.
#
# ``read_today`` carries the file:line of the first authoritative read
# when wired, or ``None`` when this is a *(proposed)* future binding.
_ENV_SCHEMA: tuple[dict[str, Any], ...] = (
    # -- identity -----------------------------------------------------
    {
        "name": "TN_IDENTITY_DIR",
        "category": "identity",
        "purpose": "Override the directory holding identity.json.",
        "read_today": "tn/identity.py:97",
        "default": "OS data dir + /tn",
        "secret": False,
        "precedence": "env > XDG_DATA_HOME > APPDATA > home",
    },
    {
        "name": "XDG_DATA_HOME",
        "category": "identity",
        "purpose": "POSIX user-data root; TN appends /tn.",
        "read_today": "tn/identity.py:100",
        "default": "~/.local/share",
        "secret": False,
        "precedence": "TN_IDENTITY_DIR > env > home",
    },
    {
        "name": "APPDATA",
        "category": "identity",
        "purpose": "Windows roaming profile root; TN appends \\tn.",
        "read_today": "tn/identity.py:104",
        "default": "~/AppData/Roaming",
        "secret": False,
        "precedence": "TN_IDENTITY_DIR > XDG_DATA_HOME > env > home",
    },
    {
        "name": "TN_IDENTITY_DID",
        "category": "identity",
        "purpose": "Pin which DID this process uses when multiple identities are on disk.",
        "read_today": None,
        "default": "first identity in TN_IDENTITY_DIR",
        "secret": False,
        "precedence": "env > implicit-single-identity",
    },
    {
        "name": "TN_IDENTITY_PASSPHRASE",
        "category": "identity",
        "purpose": "Unlock a passphrase-sealed identity.json non-interactively.",
        "read_today": None,
        "default": "TTY prompt",
        "secret": True,
        "precedence": "env > prompt",
    },
    # -- vault --------------------------------------------------------
    {
        "name": "TN_VAULT_URL",
        "category": "vault",
        "purpose": "Base URL for the cloud vault (auth, sealed blobs, projects).",
        "read_today": "tn/vault_client.py:49",
        "default": "https://vault.tn-proto.org",
        "secret": False,
        "precedence": "explicit arg > env > default",
    },
    {
        "name": "TN_VAULT_DEFAULT_BASE",
        "category": "vault",
        "purpose": "Base for did:web identity vault discovery.",
        "read_today": "tn/identity.py:410",
        "default": "https://vault.tn-proto.org",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_VAULT_PROJECT_ID",
        "category": "vault",
        "purpose": "Pin the linked vault project id.",
        "read_today": None,
        "default": "from yaml: linked_project_id",
        "secret": False,
        "precedence": "env > yaml > unset",
        "yaml_field": "linked_project_id",
    },
    {
        "name": "TN_VAULT_JWT",
        "category": "vault",
        "purpose": "Pre-auth JWT for non-interactive vault calls.",
        "read_today": None,
        "default": "challenge/verify on demand",
        "secret": True,
        "precedence": "env > interactive challenge",
    },
    {
        "name": "TN_VAULT_TIMEOUT",
        "category": "vault",
        "purpose": "HTTP timeout (seconds) for the vault client.",
        "read_today": None,
        "default": "30.0",
        "secret": False,
        "precedence": "env > default",
    },
    # -- ceremony / config -------------------------------------------
    {
        "name": "TN_YAML",
        "category": "ceremony",
        "purpose": "Explicit path to tn.yaml for autoinit / discovery.",
        "read_today": "tn/_autoinit.py:180",
        "default": "discovery chain",
        "secret": False,
        "precedence": "env > ./tn.yaml > $TN_HOME/tn.yaml > mint-fresh",
    },
    {
        "name": "TN_HOME",
        "category": "ceremony",
        "purpose": "Root for shared TN state; holds tn.yaml when minted fresh.",
        "read_today": "tn/_autoinit.py:89",
        "default": "~/.tn",
        "secret": False,
        "precedence": "env > home fallback",
    },
    {
        "name": "TN_STRICT",
        "category": "ceremony",
        "purpose": "Block ceremony auto-discovery; init() needs an explicit yaml.",
        "read_today": "tn/_autoinit.py:66",
        "default": "unset (autodiscover allowed)",
        "secret": False,
        "precedence": "python override > env > default",
    },
    {
        "name": "TN_RUN_ID",
        "category": "ceremony",
        "purpose": "Run id shared between Python and Rust runtimes; stamped on envelopes.",
        "read_today": "tn/__init__.py:209 (write)",
        "default": "minted per tn.init()",
        "secret": False,
        "precedence": "parent env > minted",
    },
    {
        "name": "TN_AUTOINIT_QUIET",
        "category": "ceremony",
        "purpose": "Silence the loud autoinit / fresh-ceremony banner.",
        "read_today": "tn/_autoinit.py:96",
        "default": "unset (banner on)",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_CEREMONY_ID",
        "category": "ceremony",
        "purpose": "Pin the ceremony id without round-tripping through tn.yaml.",
        "read_today": None,
        "default": "from yaml: ceremony.id",
        "secret": False,
        "precedence": "env > yaml",
        "yaml_field": "ceremony_id",
    },
    # -- runtime / dispatch ------------------------------------------
    {
        "name": "TN_FORCE_PYTHON",
        "category": "runtime",
        "purpose": "Disable the Rust extension; pure-Python emit/read paths.",
        "read_today": "tn/_dispatch.py:43",
        "default": "unset (Rust if available)",
        "secret": False,
        "precedence": "env > available-extension",
    },
    {
        "name": "TN_READER_LEGACY",
        "category": "runtime",
        "purpose": "Revert tn.read to legacy flat-tuple shape (pre-WS-G).",
        "read_today": "tn/reader.py:42",
        "default": "unset (new shape)",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_CLAIM_ON_MISSING_IDENTITY",
        "category": "runtime",
        "purpose": "Auto-claim a fresh identity if init's yaml DID isn't on disk.",
        "read_today": "tn/logger.py:430",
        "default": "unset (raise IdentityError)",
        "secret": False,
        "precedence": "explicit arg > env > default",
    },
    {
        "name": "TN_WALLET_AUTOSYNC",
        "category": "runtime",
        "purpose": "After every emit, push the new envelope to the linked vault.",
        "read_today": "tn/admin/__init__.py:537",
        "default": "unset (manual sync)",
        "secret": False,
        "precedence": "env > default",
    },
    # -- logging / observability -------------------------------------
    {
        "name": "TN_NO_STDOUT",
        "category": "logging",
        "purpose": "Suppress the default-on stdout JSON envelope mirror.",
        "read_today": "tn/logger.py:542",
        "default": "unset (stdout handler attached)",
        "secret": False,
        "precedence": "explicit arg > env > default",
    },
    {
        "name": "TN_SURFACE_LOG",
        "category": "logging",
        "purpose": "File path: append every public-API ENTER/EXIT to this file.",
        "read_today": "tn/__init__.py:88",
        "default": "unset (no surface log)",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_LOG_PATH",
        "category": "logging",
        "purpose": "Override logs.path (main log file destination).",
        "read_today": None,
        "default": "from yaml: logs.path",
        "secret": False,
        "precedence": "env > yaml > default",
        "yaml_field": "log_path",
    },
    {
        "name": "TN_ADMIN_LOG_PATH",
        "category": "logging",
        "purpose": "Override admin.log path (admin / state ndjson).",
        "read_today": None,
        "default": "./.tn/admin/admin.ndjson",
        "secret": False,
        "precedence": "env > yaml > default",
        "yaml_field": "admin_log_location",
    },
    {
        "name": "TN_LOG_LEVEL",
        "category": "logging",
        "purpose": "Surface logger verbosity (info / debug / trace).",
        "read_today": None,
        "default": "info",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_DEBUG",
        "category": "logging",
        "purpose": "Master debug switch — enable verbose internal traces.",
        "read_today": None,
        "default": "unset",
        "secret": False,
        "precedence": "env > default",
    },
    # -- deployment / storage ---------------------------------------
    {
        "name": "TN_STATE_DIR",
        "category": "deployment",
        "purpose": "Override the per-user state dir (sync-failure queue, etc.).",
        "read_today": "tn/admin/__init__.py:570",
        "default": "XDG_STATE_HOME/tn or %APPDATA%/tn",
        "secret": False,
        "precedence": "env > XDG_STATE_HOME > APPDATA > home",
    },
    {
        "name": "XDG_STATE_HOME",
        "category": "deployment",
        "purpose": "POSIX user-state root; TN appends /tn.",
        "read_today": "tn/admin/__init__.py:574",
        "default": "~/.local/state",
        "secret": False,
        "precedence": "TN_STATE_DIR > env > home",
    },
    {
        "name": "TN_CACHE_DIR",
        "category": "deployment",
        "purpose": "Override cache root (admin state cache, manifest cache).",
        "read_today": None,
        "default": "derived from yaml dir",
        "secret": False,
        "precedence": "env > yaml > default",
    },
    {
        "name": "TN_KEYS_DIR",
        "category": "deployment",
        "purpose": "Override keys/ path (per-group keys).",
        "read_today": None,
        "default": "from yaml: ./keys/",
        "secret": False,
        "precedence": "env > yaml > default",
        "yaml_field": "keystore",
    },
    {
        "name": "TN_OUTBOX_DIR",
        "category": "deployment",
        "purpose": "Override durable outbox root (durable handler queue).",
        "read_today": None,
        "default": "./.tn/outbox/durable",
        "secret": False,
        "precedence": "env > yaml > default",
    },
    # -- handlers (env:NAME indirection) -----------------------------
    {
        "name": "TN_KAFKA_BOOTSTRAP",
        "category": "handlers",
        "purpose": "Kafka handler bootstrap.servers.",
        "read_today": "tn/handlers/kafka.py:26 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_KAFKA_USERNAME",
        "category": "handlers",
        "purpose": "SASL username for Kafka handler.",
        "read_today": "tn/handlers/kafka.py:26 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_KAFKA_PASSWORD",
        "category": "handlers",
        "purpose": "SASL password for Kafka handler.",
        "read_today": "tn/handlers/kafka.py:26 (indirect)",
        "default": "none",
        "secret": True,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_ENDPOINT",
        "category": "handlers",
        "purpose": "S3 handler endpoint URL (e.g. MinIO / R2).",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "AWS default",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_BUCKET",
        "category": "handlers",
        "purpose": "Destination bucket for the S3 handler.",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_ACCESS_KEY_ID",
        "category": "handlers",
        "purpose": "S3 access key id.",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "AWS default chain",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_SECRET_ACCESS_KEY",
        "category": "handlers",
        "purpose": "S3 secret access key.",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "AWS default chain",
        "secret": True,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_DELTA_TOKEN",
        "category": "handlers",
        "purpose": "Databricks Delta personal access token.",
        "read_today": "tn/handlers/delta.py:63 (indirect)",
        "default": "none",
        "secret": True,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_DELTA_HOST",
        "category": "handlers",
        "purpose": "Databricks workspace host.",
        "read_today": "tn/handlers/delta.py:63 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
)


def _resolve_yaml_values() -> dict[str, str]:
    """Best-effort: load the auto-discovered ceremony and pull yaml-sourced
    fields so ``tn show env`` can render them as ``(from yaml: ...)``.

    Returns an empty dict when no ceremony is reachable. Never raises —
    a malformed yaml or missing keystore must not break the inventory
    output.
    """
    out: dict[str, str] = {}
    try:
        import os as _os
        from . import _autoinit
        from . import config as _config

        path = _autoinit._resolve_existing_yaml()
        if path is None:
            return out
        # Load yaml without env substitution failures masking the call:
        # if any required env-var ref is missing, _substitute_env_vars
        # raises ValueError. Treat that as "yaml unavailable".
        try:
            cfg = _config.load(path)
        except Exception:
            return out
        out["ceremony_id"] = cfg.ceremony_id
        out["log_path"] = str(cfg.resolve_log_path())
        out["admin_log_location"] = cfg.admin_log_location
        out["keystore"] = str(cfg.keystore)
        if cfg.linked_project_id:
            out["linked_project_id"] = cfg.linked_project_id
        if cfg.linked_vault:
            out["linked_vault"] = cfg.linked_vault
    except Exception:
        # Defensive: any import / discovery error must not break the verb.
        return out
    return out


def _redact(value: str) -> str:
    """Render a secret value as ``*** (length: N)`` for human display."""
    return f"*** (length: {len(value)})"


def _resolve_entry_value(
    entry: dict[str, Any],
    env: dict[str, str],
    yaml_vals: dict[str, str],
) -> tuple[str, str]:
    """Return ``(value, source)`` for one schema row.

    ``source`` is one of ``"env"``, ``"yaml"``, ``"unset"``. ``"unset"`` carries
    the row's documented default in parentheses for human display.
    """
    name = entry["name"]
    if name in env and env[name] != "":
        return env[name], "env"
    yaml_field = entry.get("yaml_field")
    if yaml_field and yaml_field in yaml_vals:
        return yaml_vals[yaml_field], "yaml"
    return "", "unset"


def _render_human(
    schema: tuple[dict[str, Any], ...],
    env: dict[str, str],
    yaml_vals: dict[str, str],
) -> str:
    lines: list[str] = []
    lines.append("# tn show env — canonical TN_* environment surface")
    lines.append("# Reflective only. Secrets are redacted; use --format=env to paste.")
    lines.append("")
    by_cat: dict[str, list[dict[str, Any]]] = {c: [] for c in _ENV_CATEGORIES}
    for entry in schema:
        by_cat.setdefault(entry["category"], []).append(entry)

    name_w = max(len(e["name"]) for e in schema)
    val_w = 28

    for cat in _ENV_CATEGORIES:
        rows = by_cat.get(cat, [])
        if not rows:
            continue
        lines.append(f"## {cat}")
        lines.append("")
        for entry in rows:
            value, source = _resolve_entry_value(entry, env, yaml_vals)
            proposed = entry.get("read_today") is None
            if source == "unset":
                shown = "(unset)"
                tail = f"  default: {entry['default']}"
            else:
                if entry.get("secret") and value:
                    shown = _redact(value)
                else:
                    shown = value if value else "(empty)"
                if source == "yaml":
                    tail = f"  (from yaml: {entry.get('yaml_field')})"
                else:
                    tail = ""
            tags = " (proposed)" if proposed else ""
            lines.append(
                f"  {entry['name']:<{name_w}}  {shown:<{val_w}}{tail}"
            )
            lines.append(
                f"  {'':<{name_w}}  {entry['purpose']}{tags}"
            )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_env_format(
    schema: tuple[dict[str, Any], ...],
    env: dict[str, str],
    yaml_vals: dict[str, str],
) -> str:
    """Bash-style block: ``TN_FOO=value`` per line, secrets fully present.

    Only emits rows with a resolvable value (env or yaml). Unset rows are
    skipped so the output is paste-able straight into a shell or .env file.
    """
    out_lines: list[str] = []
    for entry in schema:
        value, source = _resolve_entry_value(entry, env, yaml_vals)
        if source == "unset":
            continue
        out_lines.append(f"{entry['name']}={value}")
    return "\n".join(out_lines) + ("\n" if out_lines else "")


def _render_json(
    schema: tuple[dict[str, Any], ...],
    env: dict[str, str],
    yaml_vals: dict[str, str],
    *,
    redact_secrets: bool,
) -> str:
    import json as _json

    rows: list[dict[str, Any]] = []
    for entry in schema:
        value, source = _resolve_entry_value(entry, env, yaml_vals)
        rendered: str | None
        if source == "unset":
            rendered = None
        elif entry.get("secret") and redact_secrets and value:
            rendered = _redact(value)
        else:
            rendered = value
        rows.append(
            {
                "name": entry["name"],
                "category": entry["category"],
                "purpose": entry["purpose"],
                "value": rendered,
                "source": source,
                "secret": bool(entry.get("secret")),
                "read_today": entry.get("read_today"),
                "default": entry["default"],
                "precedence": entry.get("precedence"),
                "yaml_field": entry.get("yaml_field"),
                "proposed": entry.get("read_today") is None,
            }
        )
    return _json.dumps({"entries": rows}, indent=2, sort_keys=False) + "\n"


def cmd_show_env(args: argparse.Namespace) -> int:
    import os

    env = dict(os.environ)
    yaml_vals = _resolve_yaml_values()

    fmt = getattr(args, "format", "human") or "human"
    if fmt == "human":
        sys.stdout.write(_render_human(_ENV_SCHEMA, env, yaml_vals))
    elif fmt == "env":
        # Deploy-paste form: secrets fully present.
        sys.stdout.write(_render_env_format(_ENV_SCHEMA, env, yaml_vals))
    elif fmt == "json":
        sys.stdout.write(
            _render_json(_ENV_SCHEMA, env, yaml_vals, redact_secrets=True)
        )
    else:
        _die(f"unknown --format: {fmt!r}. Use human / env / json.")
    return 0


def cmd_show_profiles(args: argparse.Namespace) -> int:
    """Print the profile catalog.

    DX review #22: the curated profile bundle (encrypts / signs /
    chains / flush / default_sink / intended_use) is the right
    metadata to expose for "what should I init with?" decisions.
    The data has lived in ``tn._profiles._CATALOG`` since 0.3.0 but
    had no CLI surface — users were reaching into the private module
    to discover the bundles. This verb is the proper public reflection.
    """
    import json as _json

    from . import _profiles

    fmt = getattr(args, "format", "human") or "human"
    names = list(_profiles.all_profile_names())
    profiles = [_profiles.get(n) for n in names]

    if fmt == "json":
        payload = [
            {
                "name": p.name,
                "encrypts": p.encrypts,
                "signs": p.signs,
                "chains": p.chains,
                "flush": p.flush,
                "default_sink": p.default_sink,
                "intended_use": p.intended_use,
                "default": p.name == _profiles.DEFAULT_PROFILE,
            }
            for p in profiles
        ]
        sys.stdout.write(_json.dumps({"profiles": payload}, indent=2) + "\n")
        return 0

    # human table
    cols = [
        ("NAME", 12),
        ("ENCRYPTS", 8),
        ("SIGNS", 5),
        ("CHAINS", 6),
        ("FLUSH", 8),
        ("SINK", 14),
    ]
    header = "  ".join(f"{name:<{w}}" for name, w in cols)
    sys.stdout.write(header + "\n")
    sys.stdout.write(
        "  ".join("-" * w for _name, w in cols) + "\n"
    )
    for p in profiles:
        marker = "*" if p.name == _profiles.DEFAULT_PROFILE else " "
        sys.stdout.write(
            f"{p.name + marker:<12}  "
            f"{'yes' if p.encrypts else 'no':<8}  "
            f"{'yes' if p.signs else 'no':<5}  "
            f"{'yes' if p.chains else 'no':<6}  "
            f"{p.flush:<8}  "
            f"{p.default_sink:<14}\n"
        )
    sys.stdout.write("\n* = catalog default (used when tn.init() is called with no profile=).\n\n")
    # Intended-use details below the table.
    for p in profiles:
        sys.stdout.write(f"{p.name}: {p.intended_use}\n\n")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """DX review #21: ``tn show`` with no subverb dispatches to the
    most-useful default rather than spitting an argparse usage error.
    Today that default is ``env``; if a future ``show`` verb becomes
    the obvious entrypoint, repoint here. Explicit subverbs
    (``tn show env``, ``tn show profiles``) take precedence.
    """
    return cmd_show_env(args)


# ---------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------


def _load_identity_or_die(path: Path) -> Identity:
    try:
        return Identity.load(path)
    except IdentityError as e:
        _die(
            f"{e}. Run `tn init <project>` to create one, or "
            f"`tn wallet restore --mnemonic ...` on a fresh machine.",
        )
        raise  # unreachable


# ---------------------------------------------------------------------
# tn streams / tn validate — multi-ceremony introspection
# ---------------------------------------------------------------------


def cmd_streams(args: argparse.Namespace) -> int:
    """List ceremonies declared under ``.tn/`` for the project.

    Reads ``.tn/<name>/tn.yaml`` for each subdirectory and surfaces
    name, stamped profile (if any), and yaml path. Cheap, read-only.
    """
    import json as _json
    from pathlib import Path as _Path

    import yaml as _yaml

    from . import _layout

    project_dir = _Path(args.project_dir).resolve() if args.project_dir else _Path.cwd()
    names = _layout.list_ceremonies_on_disk(project_dir)

    rows: list[dict] = []
    for name in names:
        yaml_path = _layout.ceremony_yaml_path(name, project_dir=project_dir)
        profile: str | None = None
        try:
            with yaml_path.open("r", encoding="utf-8") as fh:
                doc = _yaml.safe_load(fh) or {}
            profile = (doc.get("ceremony") or {}).get("profile")
        except (OSError, _yaml.YAMLError):
            pass
        rows.append(
            {
                "name": name,
                "profile": profile or "(unspecified)",
                "yaml_path": str(yaml_path),
            }
        )

    if args.format == "json":
        print(_json.dumps(rows, indent=2))
        return 0

    # Human format: simple aligned table.
    if not rows:
        print(f"(no ceremonies found under {project_dir / '.tn'})")
        return 0
    name_w = max(len("NAME"), max(len(r["name"]) for r in rows))
    prof_w = max(len("PROFILE"), max(len(r["profile"]) for r in rows))
    print(f"{'NAME':<{name_w}}  {'PROFILE':<{prof_w}}  YAML")
    print(f"{'-' * name_w}  {'-' * prof_w}  {'-' * 4}")
    for r in rows:
        print(f"{r['name']:<{name_w}}  {r['profile']:<{prof_w}}  {r['yaml_path']}")
    return 0


def _validate_resolve_keystore_pub(
    *,
    yaml_path: Path,
    yaml_doc: dict,
    project_dir: Path,  # noqa: ARG001 — kept for symmetry / future absolute paths
) -> Path | None:
    """Resolve the path to ``local.public`` for the ceremony at
    ``yaml_path``. Used by ``cmd_validate`` to compare
    yaml.device.device_identity against the keystore's recorded did:key.

    Resolution order:

    1. ``yaml_doc['keystore']['path']`` if present (relative to the
       yaml's directory) — named streams point at default's keystore
       via this field.
    2. ``<yaml_dir>/keys/local.public`` fallback (the default
       ceremony layout).

    Returns ``None`` if neither resolves to a path that could
    plausibly hold a keystore (caller can ignore this ceremony's
    DID-consistency check).
    """
    yaml_dir = yaml_path.parent
    keystore_section = yaml_doc.get("keystore") or {}
    raw_path = keystore_section.get("path") if isinstance(
        keystore_section, dict
    ) else None
    if isinstance(raw_path, str) and raw_path:
        # Stream yaml relative paths are interpreted relative to the
        # stream's own yaml directory (matches what the runtime does).
        keystore_dir = (yaml_dir / raw_path).resolve()
    else:
        keystore_dir = yaml_dir / "keys"
    pub = keystore_dir / "local.public"
    return pub


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate the project's ``.tn/`` configuration tree.

    Read-only checks:
      - every ``.tn/<name>/tn.yaml`` parses as a mapping
      - every stamped ceremony.profile is in the SDK catalog
      - the default ceremony exists if any others do (identity must
        live at the project root)
      - the on-disk ``me.did`` in each ``tn.yaml`` matches the
        ``keys/local.public`` did:key for that ceremony (the basic
        keystore-yaml consistency invariant — DX review #2)

    Returns 0 if everything is well-formed; 1 with errors printed
    to stderr otherwise. Suitable for use in a pre-commit hook or
    CI pipeline. Adds a non-zero exit on the *first* error so CI
    output stays compact.
    """
    import sys
    from pathlib import Path as _Path

    import yaml as _yaml

    from . import _layout, _profiles

    project_dir = _Path(args.project_dir).resolve() if args.project_dir else _Path.cwd()
    root = project_dir / _layout.TN_ROOT_DIRNAME

    errors: list[str] = []
    warnings: list[str] = []

    if not root.is_dir():
        print(f"(no .tn/ directory at {project_dir} — nothing to validate)")
        return 0

    names = _layout.list_ceremonies_on_disk(project_dir)
    if not names:
        print(f"(no ceremonies under {root} — nothing to validate)")
        return 0

    if "default" not in names:
        warnings.append(
            "no 'default' ceremony at .tn/default/. The project's "
            "identity should live there; named streams normally "
            "extend from it."
        )

    for name in names:
        yaml_path = _layout.ceremony_yaml_path(name, project_dir=project_dir)
        try:
            with yaml_path.open("r", encoding="utf-8") as fh:
                doc = _yaml.safe_load(fh)
        except OSError as exc:
            errors.append(f"{yaml_path}: read failed: {exc}")
            continue
        except _yaml.YAMLError as exc:
            errors.append(f"{yaml_path}: yaml parse failed: {exc}")
            continue

        if not isinstance(doc, dict):
            errors.append(f"{yaml_path}: top-level must be a mapping")
            continue

        # 0.4.2a9: structural validation. A yaml that parses but has a
        # typo in a key name (e.g. `keystore_typo:` instead of
        # `keystore:`) used to pass validate and then fail
        # confusingly at runtime with a FileNotFoundError on a path
        # the user never set. Validate now means "fully valid" —
        # required top-level sections must be present.
        #
        # Stream yamls (those with `extends:`) inherit identity /
        # groups / keystore from the parent, so their requirement
        # set is narrower. Check `extends:` first.
        is_stream = "extends" in doc
        required_top: list[str] = ["ceremony"]
        if not is_stream:
            required_top += ["logs", "keystore", "device", "groups"]
            if "me" in doc and "device" not in doc:
                errors.append(
                    f"{yaml_path}: legacy `me:` top-level block is no longer "
                    f"supported (0.4.3a1 renamed it to `device:`). Replace "
                    f"`device: {{device_identity: ...}}` with `device: {{device_identity: ...}}`."
                )
        for key in required_top:
            if key not in doc:
                errors.append(
                    f"{yaml_path}: missing required top-level key "
                    f"{key!r}. A yaml that parses but lacks "
                    f"required sections will fail at init time with "
                    f"a confusing error; declare {key!r} or add an "
                    f"`extends:` pointing at a yaml that does."
                )

        # Sub-keys we depend on at runtime.
        if isinstance(doc.get("ceremony"), dict):
            if "id" not in doc["ceremony"]:
                errors.append(f"{yaml_path}: ceremony.id is required")
        if not is_stream:
            if isinstance(doc.get("logs"), dict) and "path" not in doc["logs"]:
                errors.append(f"{yaml_path}: logs.path is required")
            if isinstance(doc.get("keystore"), dict) and "path" not in doc["keystore"]:
                errors.append(f"{yaml_path}: keystore.path is required")
            if isinstance(doc.get("device"), dict) and "device_identity" not in doc["device"]:
                errors.append(f"{yaml_path}: device.device_identity is required")

        profile = (doc.get("ceremony") or {}).get("profile")
        if profile is not None and not _profiles.is_known(profile):
            errors.append(
                f"{yaml_path}: unknown profile {profile!r}; "
                f"catalog: {list(_profiles.all_profile_names())}"
            )

        # 0.4.2a9: also check that the keystore actually contains the
        # publisher's self-kit material for every declared group. An
        # empty/missing `*.btn.mykit` file means the publisher can
        # encrypt-and-write but can't decrypt-and-read its own log
        # (the read silently returns `fields: {}` with the group
        # listed in `hidden_groups`). Catch it at validate time so
        # the operator sees the problem before silent data loss.
        groups_dict = doc.get("groups") if isinstance(doc.get("groups"), dict) else None
        keystore_block = doc.get("keystore") if isinstance(doc.get("keystore"), dict) else None
        if groups_dict and keystore_block and "path" in keystore_block:
            ks_path = _Path(keystore_block["path"])
            if not ks_path.is_absolute():
                ks_path = (yaml_path.parent / ks_path).resolve()
            for gname, gspec in groups_dict.items():
                if not isinstance(gspec, dict):
                    continue
                cipher = (gspec.get("cipher") or doc.get("ceremony", {}).get("cipher") or "btn")
                if cipher == "btn":
                    kit_file = ks_path / f"{gname}.btn.mykit"
                    if not kit_file.is_file():
                        errors.append(
                            f"{yaml_path}: group {gname!r} kit missing: "
                            f"{kit_file}. Without the publisher self-kit "
                            f"the runtime will silently fail to decrypt "
                            f"its own emits. Re-init the ceremony or "
                            f"absorb a fresh kit bundle."
                        )
                    elif kit_file.stat().st_size == 0:
                        errors.append(
                            f"{yaml_path}: group {gname!r} kit is empty: "
                            f"{kit_file}. Same effect as missing — "
                            f"emits will be unreadable by the publisher."
                        )

        # DX review #2: catch the keystore/yaml DID divergence that
        # `tn.init` previously surfaced as `ValueError: keystore DID
        # ... does not match yaml me.did`. The validator owes its
        # callers this check; it is the basic consistency invariant.
        keystore_pub = _validate_resolve_keystore_pub(
            yaml_path=yaml_path,
            yaml_doc=doc,
            project_dir=project_dir,
        )
        if keystore_pub is not None and keystore_pub.is_file():
            try:
                derived_did = keystore_pub.read_text(
                    encoding="ascii"
                ).strip()
            except OSError as exc:
                errors.append(
                    f"{yaml_path}: could not read keystore "
                    f"{keystore_pub}: {exc}"
                )
                continue
            yaml_did = (doc.get("device") or {}).get("device_identity")
            if yaml_did and derived_did and yaml_did != derived_did:
                errors.append(
                    f"{yaml_path}: yaml device.device_identity does not match keystore. "
                    f"yaml device.device_identity = {yaml_did}; "
                    f"keys/local.public = {derived_did}. "
                    "Reseat one to match the other before any further "
                    "writes — the runtime will refuse to load this "
                    "ceremony otherwise."
                )

    if warnings:
        for w in warnings:
            print(f"WARNING: {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"OK: {len(names)} ceremon{'y' if len(names) == 1 else 'ies'} valid.")
    return 0


# ---------------------------------------------------------------------
# Firehose verbs (gated behind TN_FIREHOSE_ENABLED=1)
# ---------------------------------------------------------------------
#
# Thin client over the Cloudflare ``firehose-worker`` deployment. The
# verbs are unmounted by default so a typical CLI user never sees them
# in ``tn --help``; only operators who opt in with
# ``TN_FIREHOSE_ENABLED=1`` get the surface.
#
# Required env:
#   TN_FIREHOSE_ENABLED=1          gate flag (presence of any verb)
#   TN_FIREHOSE_URL=<https://...>  base URL of the worker, no trailing /
#
# Optional env:
#   TN_FIREHOSE_TOKEN=<bearer>     required by /api/v1/inbox/* routes
#                                   (issued by the worker's
#                                   /api/v1/auth/verify endpoint)
#
# Tenant -> DID mapping:
#   v1 assumes ``did == tenant`` for the inbox routes. The worker's
#   /firehose and /stats routes take an opaque tenant id (any
#   alphanumeric, 1..64 chars); the /api/v1/inbox/* routes require a
#   ``did:key:<...>`` shape and check it against the bearer token's
#   bound DID. Callers can override with ``--did`` on list/get if their
#   tenant id is not the literal DID.
#   TODO: project-id-based tenants once routes_account_projects' DID
#   binding is the public mapping.


def _firehose_base() -> str:
    base = (os.environ.get("TN_FIREHOSE_URL") or "").rstrip("/")
    if not base:
        _die(
            "TN_FIREHOSE_URL is not set. Point it at the firehose-worker "
            "base URL (e.g. https://firehose-worker.<account>.workers.dev)."
        )
    return base


def _firehose_token() -> str | None:
    return os.environ.get("TN_FIREHOSE_TOKEN") or None


def _firehose_headers(*, require_token: bool) -> dict[str, str]:
    headers: dict[str, str] = {"accept": "application/json"}
    token = _firehose_token()
    if token:
        headers["authorization"] = f"Bearer {token}"
    elif require_token:
        _die(
            "TN_FIREHOSE_TOKEN is required for inbox routes. Mint one via "
            "the worker's /api/v1/auth/challenge + /api/v1/auth/verify "
            "handshake."
        )
    return headers


def cmd_firehose_stats(args: argparse.Namespace) -> int:
    base = _firehose_base()
    url = f"{base}/stats/{args.tenant}"
    try:
        resp = httpx.get(url, headers=_firehose_headers(require_token=False), timeout=10.0)
    except httpx.HTTPError as exc:
        _die(f"firehose stats request failed: {exc}")
    if resp.status_code != 200:
        _die(
            f"firehose stats returned {resp.status_code}: {resp.text[:200]}",
            code=2,
        )
    try:
        body = resp.json()
    except ValueError:
        print(resp.text)
        return 0
    print(json.dumps(body, indent=2, sort_keys=True))
    return 0


def cmd_firehose_list(args: argparse.Namespace) -> int:
    base = _firehose_base()
    did = args.did or args.tenant
    url = f"{base}/api/v1/inbox/{did}/incoming"
    try:
        resp = httpx.get(url, headers=_firehose_headers(require_token=True), timeout=15.0)
    except httpx.HTTPError as exc:
        _die(f"firehose list request failed: {exc}")
    if resp.status_code != 200:
        _die(
            f"firehose list returned {resp.status_code}: {resp.text[:200]}",
            code=2,
        )
    try:
        body = resp.json()
    except ValueError:
        print(resp.text)
        return 0
    print(json.dumps(body, indent=2, sort_keys=True))
    return 0


def cmd_firehose_get(args: argparse.Namespace) -> int:
    base = _firehose_base()
    did = args.did or args.tenant
    url = f"{base}/api/v1/inbox/{did}/snapshots/{args.ceremony}/{args.name}"
    try:
        resp = httpx.get(url, headers=_firehose_headers(require_token=True), timeout=60.0)
    except httpx.HTTPError as exc:
        _die(f"firehose get request failed: {exc}")
    if resp.status_code != 200:
        _die(
            f"firehose get returned {resp.status_code}: {resp.text[:200]}",
            code=2,
        )
    data = resp.content
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        print(f"wrote {len(data)} bytes to {out_path}")
    else:
        sys.stdout.buffer.write(data)
    return 0


def _firehose_enabled() -> bool:
    return os.environ.get("TN_FIREHOSE_ENABLED") == "1"


def _register_firehose_subcommands(sub: argparse._SubParsersAction) -> None:
    """Attach the ``tn firehose ...`` verb group when gated on.

    Called from ``build_parser`` only when ``TN_FIREHOSE_ENABLED=1`` at
    parser-construction time. When unset, the verb is invisible to
    ``tn --help`` and dispatch — same shape as ``TN_DEV_AUTH_BYPASS`` on
    the vault server.
    """
    p_fh = sub.add_parser(
        "firehose",
        help="Firehose worker probes (gated by TN_FIREHOSE_ENABLED=1).",
    )
    fhsub = p_fh.add_subparsers(dest="fhverb", required=True)

    p_stats = fhsub.add_parser(
        "stats", help="GET /stats/<tenant> from the firehose worker."
    )
    p_stats.add_argument("tenant", help="Tenant id known to the worker.")
    p_stats.set_defaults(func=cmd_firehose_stats)

    p_list = fhsub.add_parser(
        "list",
        help="List tnpkg snapshots in the worker inbox for <tenant>.",
    )
    p_list.add_argument("tenant", help="Tenant id; assumed to be the DID by default.")
    p_list.add_argument(
        "--did",
        default=None,
        help="Override the DID used for the inbox path (default: tenant).",
    )
    p_list.set_defaults(func=cmd_firehose_list)

    p_get = fhsub.add_parser(
        "get",
        help="Download a single tnpkg snapshot by ceremony + name.",
    )
    p_get.add_argument("tenant", help="Tenant id; assumed to be the DID by default.")
    p_get.add_argument("ceremony", help="Ceremony id segment in the inbox path.")
    p_get.add_argument("name", help="Snapshot file name (e.g. snap.tnpkg).")
    p_get.add_argument(
        "--did",
        default=None,
        help="Override the DID used for the inbox path (default: tenant).",
    )
    p_get.add_argument(
        "--out",
        default=None,
        help="Write bytes to this path instead of stdout.",
    )
    p_get.set_defaults(func=cmd_firehose_get)


# ---------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tn",
        description="TN protocol CLI — identity + ceremony + vault wallet.",
    )
    sub = p.add_subparsers(dest="verb", required=True)

    # --- tn init -------------------------------------------------
    p_init = sub.add_parser("init", help="Scaffold identity + ceremony.")
    p_init.add_argument(
        "project",
        help=(
            "Project name. The ceremony is created at ./.tn/<project>/. "
            "If a path is passed, only the basename is used."
        ),
    )
    # ``--version-name`` stamps a per-instance nickname inside the vault
    # project (e.g. 'laptop-dev', 'ci', 'prod'). Defaults to <project>.
    # The legacy --project-name flag was dropped (0.5.0a2): the positional
    # IS the project name; there is no separate vault-side label to
    # specify. Operators who want a different vault label later can
    # rename via a future `tn wallet relabel` verb.
    p_init.add_argument(
        "--version-name",
        default=None,
        help=(
            "Per-instance nickname inside the project (e.g. "
            "'laptop-dev', 'ci', 'prod'). Defaults to <project>."
        ),
    )
    # ``btn`` is the shipping default cipher; ``jwe`` is the pure-Python
    # alternative kept for environments that can't ship the Rust extension.
    # ``bgw`` was retired in Workstream G — removed from choices.
    p_init.add_argument("--cipher", default="btn", choices=["btn", "jwe"])
    p_init.add_argument("--words", type=int, default=12, choices=[12, 15, 18, 21, 24])
    p_init.add_argument(
        "--mnemonic-file", default=None, help="Read mnemonic from this file (non-interactive)."
    )
    p_init.add_argument(
        "--link",
        default=None,
        help=(
            "Vault URL to link this ceremony to. Defaults to identity.linked_vault, "
            "then $TN_VAULT_URL, then https://vault.tn-proto.org."
        ),
    )
    p_init.add_argument(
        "--no-link",
        action="store_true",
        help="Skip auto-link + initial backup. Produces an offline-only ceremony.",
    )
    p_init.add_argument(
        "--force", action="store_true", help="Overwrite existing project directory."
    )
    p_init.add_argument(
        "--skip-confirm", action="store_true", help="Do not pause for Enter after showing mnemonic."
    )
    p_init.add_argument(
        "--keep-mnemonic",
        action="store_true",
        help=(
            "Persist the recovery phrase into identity.json "
            "so `tn wallet export-mnemonic` can re-display it "
            "later. Trades some filesystem blast radius for "
            "recovery convenience."
        ),
    )
    p_init.set_defaults(func=cmd_init)

    # --- tn wallet ---------------------------------------------
    p_wallet = sub.add_parser("wallet", help="Wallet/vault operations.")
    wsub = p_wallet.add_subparsers(dest="wverb", required=True)

    p_status = wsub.add_parser("status")
    p_status.add_argument(
        "yaml", nargs="?", default=None, help="Optional ceremony yaml to describe."
    )
    p_status.set_defaults(func=cmd_wallet_status)

    # 0.4.2a9: wallet link / unlink / sync all default to the
    # discovered yaml the same way `tn read` and `tn status` do —
    # operator doesn't have to type the full path when one is in
    # scope. Pass an explicit yaml only when you want to override
    # discovery.
    p_link = wsub.add_parser("link")
    p_link.add_argument(
        "yaml", nargs="?", default=None,
        help="Optional ceremony yaml. Default: discover via the standard chain.",
    )
    p_link.add_argument("--vault", default=None)
    p_link.set_defaults(func=cmd_wallet_link)

    p_unlink = wsub.add_parser("unlink")
    p_unlink.add_argument(
        "yaml", nargs="?", default=None,
        help="Optional ceremony yaml. Default: discover via the standard chain.",
    )
    p_unlink.set_defaults(func=cmd_wallet_unlink)

    p_sync = wsub.add_parser("sync")
    p_sync.add_argument(
        "yaml", nargs="?", default=None,
        help="Optional ceremony yaml. Default: discover via the standard chain.",
    )
    p_sync.add_argument(
        "--drain-queue",
        action="store_true",
        help="Retry any pending autosync failures; clear queue on success.",
    )
    p_sync.add_argument(
        "--pull",
        action="store_true",
        help=(
            "Drain the vault's account inbox into the local inbox dir. "
            "Requires `tn account connect` to have bound this DID to "
            "an account. Does not auto-absorb: run `tn absorb <path>` "
            "on each staged file."
        ),
    )
    p_sync.set_defaults(func=cmd_wallet_sync)

    p_pull = wsub.add_parser("pull-prefs")
    p_pull.add_argument("--vault", default=None)
    p_pull.set_defaults(func=cmd_wallet_pull_prefs)

    p_restore = wsub.add_parser("restore")
    # Legacy mnemonic flow.
    p_restore.add_argument("--mnemonic", default=None, help="Recovery phrase as a quoted string.")
    p_restore.add_argument("--mnemonic-file", default=None)
    p_restore.add_argument("--vault", default=None, help="Vault URL to pull ceremonies from.")
    p_restore.add_argument(
        "--project-ids", default=None, help="Comma-separated list of project ids."
    )
    p_restore.add_argument("--all-projects", action="store_true")
    p_restore.add_argument(
        "out_dir",
        nargs="?",
        default=None,
        help=(
            "Output directory for the restored ceremony. Required for the "
            "new account-bound flow; optional for the legacy mnemonic flow."
        ),
    )
    # Backward compat: --out-dir was the previous spelling. Keep it as
    # an alias that overrides the positional.
    p_restore.add_argument("--out-dir", dest="out_dir_flag", default=None)
    p_restore.add_argument("--force", action="store_true")
    # Account-bound flow knobs (Session 10, plan
    # docs/superpowers/plans/2026-04-29-multi-device-restore.md).
    p_restore.add_argument(
        "--passphrase",
        action="store_true",
        help="Use passphrase fallback instead of opening a browser (D-22).",
    )
    p_restore.add_argument(
        "--port",
        type=int,
        default=None,
        help="Pin the loopback port (default: kernel-allocated).",
    )
    p_restore.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Loopback wait timeout in seconds (default: 300).",
    )
    p_restore.add_argument(
        "--credential-id",
        default=None,
        help="For --passphrase: which credential row's KDF to derive against.",
    )
    p_restore.add_argument(
        "--project-id",
        default=None,
        help="For --passphrase: project id to restore (skips interactive pick).",
    )
    p_restore.add_argument(
        "--jwt",
        default=None,
        help="For --passphrase: vault JWT (no browser handoff in this mode).",
    )
    p_restore.set_defaults(func=cmd_wallet_restore)

    p_export = wsub.add_parser("export-mnemonic")
    p_export.add_argument(
        "--yes", action="store_true", help="Confirm you want to display the phrase on screen."
    )
    p_export.set_defaults(func=cmd_wallet_export_mnemonic)

    # --- tn account -------------------------------------------------
    # Connect-code redemption: bind THIS device's DID to an existing
    # OAuth vault account so subsequent /account/* routes accept this
    # DID's challenge-issued JWT. The CLI counterpart to the dashboard's
    # "Connect a new app or device" action.
    p_account = sub.add_parser("account", help="Vault account binding operations.")
    asub = p_account.add_subparsers(dest="averb", required=True)

    p_connect = asub.add_parser(
        "connect",
        help="Redeem a tn_connect_<...> code to bind this device's DID to a vault account.",
    )
    p_connect.add_argument(
        "code",
        help="The single-use connect code copied from the vault dashboard.",
    )
    p_connect.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_connect.add_argument(
        "--vault", default=None,
        help="Vault URL. Default: identity.linked_vault, then $TN_VAULT_URL, then the hosted vault.",
    )
    p_connect.set_defaults(func=cmd_account_connect)

    # --- tn bundle [--yaml=...] <recipient_did> <out> -----------
    p_bundle = sub.add_parser(
        "bundle",
        help="Mint a kit_bundle .tnpkg for one recipient (FINDINGS #5 footgun-free).",
    )
    p_bundle.add_argument("recipient_identity", help="DID of the recipient receiving the kit.")
    p_bundle.add_argument("out", help="Destination .tnpkg path.")
    p_bundle.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via $TN_YAML / ./tn.yaml / ~/.tn/tn.yaml.",
    )
    p_bundle.add_argument(
        "--groups",
        default=None,
        help="Comma-separated group names. Default: every non-tn.agents group in the ceremony.",
    )
    p_bundle.add_argument(
        "--seal-for-recipient",
        action="store_true",
        default=False,
        help="Wrap the bundle body under a per-export key only the named "
             "recipient DID can unwrap. Lets a CDN or vault host the file "
             "without being able to read its contents.",
    )
    p_bundle.set_defaults(func=cmd_bundle)

    # --- tn add_recipient <group> <did-or-label> -------------
    # The friendlier alias the cash-_register assignment expected
    # (FINDINGS S6.4): yaml auto-discovered, output path defaults to
    # ./<label>.tnpkg, and a bare label gets a synthetic placeholder
    # DID for the attestation event.
    p_add = sub.add_parser(
        "add_recipient",
        help="One-shot mint+bundle: `tn add_recipient <group> <did-or-label>`.",
    )
    p_add.add_argument("group", help="Group name to mint a kit for (e.g. default).")
    p_add.add_argument(
        "recipient",
        help="Recipient DID, or a friendly label (auto-prefixed with did:key:zLabel-).",
    )
    p_add.add_argument(
        "--out", default=None,
        help="Output .tnpkg path. Default: ./<label>.tnpkg in the cwd.",
    )
    p_add.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via $TN_YAML / ./tn.yaml / ~/.tn/tn.yaml.",
    )
    p_add.add_argument(
        "--seal-for-recipient",
        action="store_true",
        default=False,
        help="Wrap the bundle body under a per-export key only the named "
             "recipient DID can unwrap. Lets a CDN or vault host the file "
             "without being able to read its contents.",
    )
    p_add.set_defaults(func=cmd_add_recipient)

    # --- tn absorb <package> -----------------------------------
    p_absorb = sub.add_parser(
        "absorb",
        help="Absorb a .tnpkg (kit bundle, enrolment, etc.) into the active ceremony.",
    )
    p_absorb.add_argument("package", help="Path to the .tnpkg to absorb.")
    p_absorb.add_argument(
        "--yaml", default=None,
        help="Path to the absorber's tn.yaml. Default: discover via the standard chain.",
    )
    p_absorb.add_argument(
        "--allow-self-absorb", action="store_true",
        help=(
            "Allow absorbing a .tnpkg this ceremony itself minted. The "
            "default is to refuse: self-absorb overwrites the publisher's "
            "own keystore with a reader-kit copy, which is almost never "
            "what you want outside test/recovery flows."
        ),
    )
    p_absorb.set_defaults(func=cmd_absorb)

    # --- tn rotate [<group>] [--groups a,b,c] [--out path] -----
    # The deploy-shaped verb: rotate one or more groups and emit
    # per-recipient kit_bundle .tnpkg artifacts so CI can upload them.
    # See cmd_rotate docstring for output shape and vault interaction.
    p_rotate = sub.add_parser(
        "rotate",
        help="Rotate group keys and emit per-recipient .tnpkg artifacts.",
    )
    p_rotate.add_argument(
        "group",
        nargs="?",
        default=None,
        help=(
            "Group to rotate. Omit (and skip --groups) to rotate every "
            "non-internal group in the ceremony — the default deploy shape."
        ),
    )
    p_rotate.add_argument(
        "--groups",
        default=None,
        help=(
            "Comma-separated subset of groups to rotate. Mutually "
            "exclusive with the positional <group>."
        ),
    )
    p_rotate.add_argument(
        "--out",
        default=None,
        help=(
            "Where to write the per-recipient .tnpkg artifacts. "
            "A directory (default: ./rotated_<UTC_TS>/) writes one .tnpkg "
            "per surviving recipient. A path ending in .tnpkg writes a "
            "single file (single-recipient rotations only)."
        ),
    )
    p_rotate.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_rotate.set_defaults(func=cmd_rotate)

    # --- tn read [<log>] ---------------------------------------
    p_read = sub.add_parser(
        "read",
        help="Print a log in flat, decrypted form (auto-routes cross-publisher).",
    )
    p_read.add_argument(
        "log",
        nargs="?",
        default=None,
        help="Optional log path (default: ceremony's main log). "
             "Cross-publisher logs are auto-routed via read_as_recipient (FINDINGS S6.2).",
    )
    p_read.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    # Read defaults to "everything on disk". A boolean-optional flag lets
    # callers narrow back to the current process run via `--no-all-runs`.
    p_read.add_argument(
        "--all-runs",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include entries from previous runs (default: True). "
             "Pass `--no-all-runs` to restrict to this process run.",
    )
    p_read.set_defaults(func=cmd_read)

    # --- tn show env ------------------------------------------------
    # Reflective inventory of every TN_* env var the install reads or
    # would meaningfully accept. ``tn show env`` mirrors the canonical
    # surface documented in ``docs/env-schema.md``. Three formats:
    #   human (default) — pretty table, secrets redacted
    #   env             — bash-style ``TN_FOO=value`` block, paste-able
    #   json            — programmatic / LLM consumption
    # --- tn streams --------------------------------------------
    # List ceremonies (streams) declared on disk under .tn/. Cheap
    # introspection for operators auditing what got registered as
    # code ran. Matches the multi-ceremony directory contract in
    # docs/directory-layout.md.
    p_streams = sub.add_parser(
        "streams",
        help="List ceremonies/streams under .tn/ for the project.",
    )
    p_streams.add_argument(
        "--project-dir",
        default=None,
        help="Project root containing .tn/. Default: current directory.",
    )
    p_streams.add_argument(
        "--format",
        default="human",
        choices=["human", "json"],
        help="Output format. ``human`` is a table; ``json`` is a list "
             "of {name, profile, yaml_path} objects.",
    )
    p_streams.set_defaults(func=cmd_streams)

    # --- tn validate -------------------------------------------
    # Static check of the project's .tn/ tree: profile names valid,
    # yamls parseable, identity declared at default. Read-only;
    # exits non-zero on failure. Suitable as a pre-commit / CI step.
    p_validate = sub.add_parser(
        "validate",
        help="Validate the project's .tn/ configuration tree.",
    )
    p_validate.add_argument(
        "--project-dir",
        default=None,
        help="Project root containing .tn/. Default: current directory.",
    )
    p_validate.set_defaults(func=cmd_validate)

    p_show = sub.add_parser("show", help="Reflective inspection commands.")
    # DX review #21: ``required=False`` so ``tn show`` with no subverb
    # dispatches to a useful default (env) rather than spitting an
    # argparse usage error.
    show_sub = p_show.add_subparsers(dest="show_verb", required=False)
    p_show.set_defaults(func=cmd_show, format="human")
    p_show_env = show_sub.add_parser(
        "env",
        help="Print the canonical TN_* env-var surface (human / env / json).",
    )
    p_show_env.add_argument(
        "--format",
        default="human",
        choices=["human", "env", "json"],
        help="human (default) for the pretty table; env for a paste-able "
             "TN_FOO=value block (secrets present); json for programmatic use.",
    )
    p_show_env.set_defaults(func=cmd_show_env)

    # DX review #22: profile-catalog reflection.
    p_show_profiles = show_sub.add_parser(
        "profiles",
        help="Print the profile catalog (transaction / audit / secure_log / telemetry / stdout) with their encrypts/signs/chains/flush/sink matrices and intended-use blurbs.",
    )
    p_show_profiles.add_argument(
        "--format",
        default="human",
        choices=["human", "json"],
        help="human (default) for the pretty table + descriptions; json for programmatic use.",
    )
    p_show_profiles.set_defaults(func=cmd_show_profiles)

    # --- tn firehose (gated) -----------------------------------
    # Surface only when TN_FIREHOSE_ENABLED=1 at parser-construction
    # time. Same shape as the vault server's TN_DEV_AUTH_BYPASS gate:
    # absence at import/build time means the verb does not appear in
    # ``tn --help`` and dispatch raises the usual unknown-verb error.
    if _firehose_enabled():
        _register_firehose_subcommands(sub)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
