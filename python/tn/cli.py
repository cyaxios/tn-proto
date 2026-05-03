"""TN command-line interface.

Two top-level verbs:

    tn init <project>        One-time scaffold of identity + ceremony.
                             Generates a BIP-39 mnemonic (shown ONCE to
                             the user — TTY-only), writes identity.json
                             to $XDG_DATA_HOME/tn/, and creates
                             <project>/tn.yaml + <project>/keys/.

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
Installed console script (future): `tn [verb] ...`
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Any, NoReturn

from . import admin as _admin
from . import wallet as _wallet
from . import wallet_restore as _wallet_restore
from . import wallet_restore_loopback as _wallet_restore_loopback
from . import wallet_restore_passphrase as _wallet_restore_passphrase
from .identity import Identity, IdentityError, _default_identity_path
from .vault_client import VaultClient, resolve_vault_url

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

    # Refuse to print mnemonic in non-TTY contexts — defense against
    # leaking the recovery phrase into logs, CI pipelines, build artifacts.
    if not _is_tty() and args.mnemonic_file is None:
        _die(
            "tn init requires an interactive terminal. "
            "For non-interactive provisioning, pass --mnemonic-file <path> "
            "with a pre-generated mnemonic.",
            code=2,
        )

    project_dir = Path(args.project).resolve()
    if project_dir.exists() and any(project_dir.iterdir()):
        if not args.force:
            _die(
                f"project directory {project_dir} already exists and is non-empty. "
                f"Use --force to overwrite or pick a different path.",
                code=2,
            )
    project_dir.mkdir(parents=True, exist_ok=True)

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

    # -- Create ceremony -------------------------------------------
    from . import current_config, flush_and_close
    from . import init as tn_init

    yaml_path = project_dir / "tn.yaml"
    # Don't pass log_path: let create_fresh + the generated yaml drive
    # the path so the per-yaml-stem namespace (FINDINGS #2) is honored.
    # Hardcoding `.tn/logs/...` here would override the yaml and create
    # a layout collision when a second ceremony is added to the same dir.

    if yaml_path.exists() and not args.force:
        _die(
            f"{yaml_path} already exists. Use --force to overwrite.",
            code=2,
        )

    tn_init(
        yaml_path,
        cipher=args.cipher,
        identity=identity,
    )
    cfg = current_config()
    print(f"[tn init] Ceremony {cfg.ceremony_id} created at {yaml_path}")
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

        client = None
        try:
            from .handlers.vault_push import init_upload, _default_client_factory
            client = _default_client_factory(vault_url, identity)
            # Re-open cfg so init_upload reads the just-written ceremony.
            tn_init(yaml_path, cipher=args.cipher, identity=identity)
            cfg = current_config()
            result = init_upload(cfg, client, vault_base=vault_url)
            print()
            print(f"[tn init] Backed up to {vault_url}")
            print(f"[tn init]   vault_id:   {result['vault_id']}")
            print(f"[tn init]   expires:    {result['expires_at']}")
            if result.get("reused"):
                print(f"[tn init]   (reusing live pending-claim within TTL)")
            print()
            print("[tn init] CLAIM URL — open this in your browser to attach the project to your account:")
            print(f"  {result['claim_url']}")
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

    yaml_path = Path(args.yaml).resolve()
    tn_init(yaml_path, identity=identity)
    cfg = current_config()

    client = VaultClient.for_identity(identity, vault_url)
    try:
        _wallet.link_ceremony(cfg, client, project_name=cfg.ceremony_id)
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

    yaml_path = Path(args.yaml).resolve()
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

    yaml_path = Path(args.yaml).resolve()
    tn_init(yaml_path, identity=identity)
    cfg = current_config()

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

    # New-flow dispatch. The presence of an out_dir + absence of a
    # mnemonic are the cue. Passphrase fallback (--passphrase) is also
    # the new flow with a different secret-derivation path.
    using_new_flow = (
        args.mnemonic is None
        and args.mnemonic_file is None
        and (args.out_dir is not None or getattr(args, "passphrase", False))
    )
    if using_new_flow:
        return _cmd_wallet_restore_account_bound(args)

    if args.mnemonic is None and args.mnemonic_file is None:
        if not _is_tty():
            _die(
                "--mnemonic or --mnemonic-file required in non-TTY contexts "
                "(or pass an output directory to use the new account-bound flow)",
                code=2,
            )
        mnemonic = getpass.getpass("Enter your 12/24-word recovery phrase: ").strip()
    elif args.mnemonic_file is not None:
        mnemonic = Path(args.mnemonic_file).read_text(encoding="utf-8").strip()
    else:
        mnemonic = args.mnemonic.strip()

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

    vault_url = args.vault
    if vault_url is None:
        print("No --vault passed; restoring identity only (no ceremonies).")
        identity.ensure_written(identity_path)
        print(f"Identity restored to {identity_path}")
        print(f"  DID: {identity.did}")
        return 0

    identity.linked_vault = vault_url
    identity.ensure_written(identity_path)
    print(f"Identity restored to {identity_path}")
    print(f"  DID: {identity.did}")
    print(f"  vault: {vault_url}")

    client = VaultClient.for_identity(identity, vault_url)
    try:
        projects = client.list_projects()
        if not projects:
            print("No linked ceremonies on the vault. Restore complete.")
            return 0

        print(f"Found {len(projects)} linked ceremonies:")
        for i, p in enumerate(projects):
            pid = p.get("id") or p.get("_id")
            name = p.get("name", "(unnamed)")
            print(f"  [{i}] {pid}  name={name}")

        if args.project_ids:
            selected_ids = set(args.project_ids.split(","))
        elif args.all_projects or not _is_tty():
            selected_ids = {p.get("id") or p.get("_id") for p in projects}
        else:
            picks = input("Enter comma-separated indexes to restore (or 'all'): ").strip()
            if picks.lower() == "all":
                selected_ids = {p.get("id") or p.get("_id") for p in projects}
            else:
                idx = [int(x) for x in picks.split(",") if x.strip()]
                selected_ids = {(projects[i].get("id") or projects[i].get("_id")) for i in idx}

        base_restore_dir = Path(args.out_dir or "./restored").resolve()
        base_restore_dir.mkdir(parents=True, exist_ok=True)

        for p in projects:
            pid = p.get("id") or p.get("_id")
            if pid is None or pid not in selected_ids:
                continue
            name = p.get("name") or pid
            target = base_restore_dir / str(name)
            print(f"Restoring {pid} -> {target}")
            result = _wallet.restore_ceremony(client, str(pid), target_dir=target)
            print(f"  pulled {len(result.files_restored)} files: {result.files_restored}")
            if result.errors:
                print(f"  WARN {len(result.errors)} errors: {result.errors}")
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
        out = bundle_for_recipient(args.recipient_did, args.out, groups=groups)
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

    out_path = Path(args.out).resolve() if args.out else Path.cwd() / f"{out_default_stem}.tnpkg"

    tn_init(yaml_path)
    try:
        groups = [args.group]
        out = bundle_for_recipient(recipient_did, out_path, groups=groups)
        print(f"[tn add_recipient] wrote {out}")
        print(f"[tn add_recipient]   group:     {args.group}")
        print(f"[tn add_recipient]   recipient: {recipient_did}")
    finally:
        flush_and_close()
    return 0


def cmd_absorb(args: argparse.Namespace) -> int:
    from . import flush_and_close
    from . import init as tn_init
    from .pkg import absorb

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    package = Path(args.package).resolve()
    if not package.exists():
        _die(f"package not found: {package}")

    tn_init(yaml_path)
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


def cmd_read(args: argparse.Namespace) -> int:
    from . import flush_and_close
    from . import init as tn_init
    from . import read as tn_read

    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn_init(yaml_path)
    try:
        log_path = Path(args.log).resolve() if args.log else None
        kwargs: dict[str, Any] = {"all_runs": args.all_runs}
        for entry in tn_read(log_path, **kwargs):
            ts = entry.get("timestamp", "?")
            level = entry.get("level", "")
            et = entry.get("event_type", "?")
            # Inline a few important non-envelope fields so the operator can
            # eyeball the log without piping to jq for every command.
            extras = {
                k: v
                for k, v in entry.items()
                if k not in {"timestamp", "level", "event_type", "did", "sequence",
                              "event_id", "row_hash", "prev_hash", "signature",
                              "_hidden_groups", "_decrypt_errors", "run_id"}
            }
            extra_str = " ".join(f"{k}={v!r}" for k, v in extras.items())
            print(f"{ts}  {level:<7} {et}  {extra_str}".rstrip())
    finally:
        flush_and_close()
    return 0


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
    p_init.add_argument("project", help="Path to the new project directory.")
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

    p_link = wsub.add_parser("link")
    p_link.add_argument("yaml")
    p_link.add_argument("--vault", default=None)
    p_link.set_defaults(func=cmd_wallet_link)

    p_unlink = wsub.add_parser("unlink")
    p_unlink.add_argument("yaml")
    p_unlink.set_defaults(func=cmd_wallet_unlink)

    p_sync = wsub.add_parser("sync")
    p_sync.add_argument("yaml")
    p_sync.add_argument(
        "--drain-queue",
        action="store_true",
        help="Retry any pending autosync failures; clear queue on success.",
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

    # --- tn bundle [--yaml=...] <recipient_did> <out> -----------
    p_bundle = sub.add_parser(
        "bundle",
        help="Mint a kit_bundle .tnpkg for one recipient (FINDINGS #5 footgun-free).",
    )
    p_bundle.add_argument("recipient_did", help="DID of the recipient receiving the kit.")
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
    p_absorb.set_defaults(func=cmd_absorb)

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
    p_read.add_argument(
        "--all-runs",
        action="store_true",
        help="Include entries from previous runs (default: this run only).",
    )
    p_read.set_defaults(func=cmd_read)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
