"""``tn init <project>`` — one-time identity + ceremony scaffold.

Mints (or reuses) the machine identity, scaffolds <cwd>/.tn/<project>/, and —
unless --no-link — backs the project up to the vault: the warm path
(_try_warm_attach) attaches to an existing account over the device DID JWT,
otherwise a pending-claim URL is minted for browser claim. Thin over the SDK
init/attach engines; _pull_absorb_step is shared with cli_wallet.
"""

from __future__ import annotations

import argparse
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import yaml

import tn

from ._init_attach import AttachMode, _warm_attach_signal, attach_or_sync
from ._layout import is_valid_ceremony_name as _is_valid_ceremony_name
from ._layout import tn_root as _tn_root
from ._multi import _ensure_ceremony_on_disk
from .cli_common import _die, _is_tty, _print_mnemonic_banner
from .cli_wallet import _pull_absorb_step
from .handlers.vault_push import _default_client_factory, init_upload
from .identity import Identity, _default_identity_path
from .vault_client import resolve_vault_url

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
    with yaml_path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    ceremony = doc.setdefault("ceremony", {})
    if project_name is not None:
        ceremony["project_name"] = project_name
    if version_name is not None:
        ceremony["version_name"] = version_name
    with yaml_path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)


def _format_expires_local(expires_iso: str) -> str:
    """Render the vault's ISO-8601 UTC `expires_at` as local-time + UTC offset.

    Falls back to the raw ISO string on any parse failure so the operator
    is never deprived of the value just because the local-tz lookup hiccupped.
    """
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
    try:
        tn.init(yaml_path, cipher=cipher or "btn", identity=identity, link=False)
        cfg = tn.current_config()
    except Exception as e:  # noqa: BLE001 — load failure -> cold fallback
        print(f"[tn init] WARN ceremony load failed ({e}); using claim URL instead")
        return False

    # The shared engine: WARM_CREATE (new project → link + push) or WARM_SYNC
    # (existing project → pull/merge + push), using the cached AWK for the
    # body backup. Never raises; contained failures come back as warnings.
    out = attach_or_sync(
        cfg, identity, vault_url, pull_absorb=_pull_absorb_step
    )
    tn.flush_and_close()

    if out.mode is AttachMode.CLAIM_URL:
        # No logged-in account after all — fall back to the claim-URL flow.
        return False

    verb = "Created" if out.mode is AttachMode.WARM_CREATE else "Synced"
    print()
    if out.attached:
        print("[tn init] Attached to your vault account (no browser needed).")
        if out.project_id:
            print(f"[tn init]   {verb.lower()}:  {vault_url}/projects/{out.project_id}")
        print(f"[tn init]   uploaded: {len(out.uploaded)} file(s)")
        if not out.uploaded:
            # Linked is NOT the same as backed up: the vault is zero-knowledge,
            # so it can't store your keystore without your passphrase-derived key.
            print("[tn init]   NOTE: your project is linked, but your keystore is NOT backed up yet.")
            print("[tn init]   The vault cannot store it without your account passphrase. Back it up with:")
            print("[tn init]     tn auth login --account-passphrase     # caches the key; future syncs are automatic")
    else:
        # Warm attach didn't complete (e.g. vault unreachable). Don't claim
        # success — the ceremony is still valid locally; surface the reason.
        print(f"[tn init] Could not reach your vault account at {vault_url}.")
        print("[tn init]   Your project is saved locally; vault sync was skipped.")
    for w in out.warnings:
        # The body-backup-skipped note carries the internal "<passphrase>:" /
        # "<auth>:" error tag; the plain-language NOTE above already says it, so
        # don't also dump the raw internal warning on the no-credential path.
        if w.startswith("<passphrase>:") and out.attached and not out.uploaded:
            continue
        print(f"[tn init]   WARN {w}")
    print()
    return True


def cmd_init(args: argparse.Namespace) -> int:
    """Scaffold identity (if absent) + ceremony at <project>/tn.yaml."""
    # Quiet the stdout handler by default: it echoes every log envelope
    # as JSON, which is useful for debugging but ruinous for the
    # human-facing CLI output (the user just wants the claim URL). Use
    # ``setdefault`` so an explicit ``TN_NO_STDOUT=0`` from the caller
    # still wins — same convention ``python -m tn`` uses (see
    # ``tn/__main__.py``).
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
        # The mnemonic banner is suppressed in this mode (it would land in CI
        # logs); the call below is guarded on `non_tty_provision`.
        print(
            "[tn init] non-interactive mode: mnemonic will be persisted "
            "into identity.json (treat that file as a secret).",
        )

    # 0.5.0a2 layout: the ceremony lives at <cwd>/.tn/<project>/ — the
    # project name IS the ceremony name, all of it nested under a single
    # .tn/ at the cwd. (Prior layout put .tn under a per-project dir:
    # <cwd>/<project>/.tn/default/.) `project` may be passed as a bare
    # name or a path; only the basename is used as the ceremony name.
    if args.project is None:
        # No name given: use the current folder's name (matches the library
        # auto-init layout ./.tn/<cwd-name>/). Fail with a friendly hint if
        # the folder name isn't a valid ceremony name.
        project_dir = Path.cwd().resolve()
        ceremony_name = project_dir.name
        if not _is_valid_ceremony_name(ceremony_name):
            _die(
                f"can't use the current folder name {ceremony_name!r} as a "
                f"project name (use letters, digits, underscore, or dash; not "
                f"starting with a dash). Pass an explicit name: tn init <name>."
            )
        print(f"[tn init] no name given; using current folder: {ceremony_name}")
    else:
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
        project_dir = (
            _project_arg.parent if str(_project_arg.parent) != "." else Path.cwd()
        ).resolve()
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
            if not non_tty_provision:
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
    ceremony_d = _tn_root(project_dir) / ceremony_name
    yaml_path = ceremony_d / "tn.yaml"

    if yaml_path.exists() and args.force:
        # Move the existing ceremony aside so --force never deletes data
        # silently. The operator can recover by hand from the backup dir.
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = _tn_root(project_dir) / f"_overwritten_{ceremony_name}_{stamp}"
        shutil.move(str(ceremony_d), str(backup))
        print(f"[tn init] --force: prior ceremony moved to {backup}")

    if yaml_path.exists():
        # Idempotent re-attach. Matches Python `tn.init()`'s behaviour:
        # if the ceremony is already there, attach to it; don't mint a
        # second one and don't error.
        tn.init(yaml_path, identity=identity, link=False)
        cfg = tn.current_config()
        print(f"[tn init] Reusing ceremony {cfg.ceremony_id} at {yaml_path}")
        print(f"[tn init]   cipher: {cfg.cipher_name}")
        print(f"[tn init]   keystore: {cfg.keystore}")
        tn.flush_and_close()
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
    tn.init(yaml_path, identity=identity, link=False)
    cfg = tn.current_config()
    print(f"[tn init] Ceremony {cfg.ceremony_id} created at {yaml_path}")
    if cfg.project_name:
        print(f"[tn init]   project: {cfg.project_name}"
              + (f" (version: {cfg.version_name})" if cfg.version_name else ""))
    print(f"[tn init]   cipher: {cfg.cipher_name}")
    print(f"[tn init]   keystore: {cfg.keystore}")
    tn.flush_and_close()

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
    # unauthenticated by design (the claimer has no account yet); the
    # BEK travels in the URL fragment so the vault never sees it (the
    # fragment is never sent to the server). The browser claim page
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
        # `tn account connect` — the latter only when the target vault is
        # that account's vault (see _warm_attach_signal). Falls through to
        # the claim-URL flow if the authenticated attach can't be completed.
        warm_signal = _warm_attach_signal(identity, vault_url)
        if warm_signal and _try_warm_attach(yaml_path, identity, vault_url, args.cipher):
            return 0

        client = None
        try:
            client = _default_client_factory(vault_url, identity)
            # Re-open cfg so init_upload reads the just-written ceremony.
            tn.init(yaml_path, cipher=args.cipher, identity=identity, link=False)
            cfg = tn.current_config()
            result = init_upload(cfg, client, vault_base=vault_url)
            print()
            print(f"[tn init] Backed up to {vault_url}")
            print(f"[tn init]   vault_id:   {result['vault_id']}")
            print(f"[tn init]   expires:    {_format_expires_local(result['expires_at'])}")
            if result.get("reused"):
                print("[tn init]   (reusing live pending-claim within TTL)")
            print()
            print("[tn init] CLAIM URL - open this in your browser to attach the project to your account:")
            print(f"  {result['claim_url']}")
            print()
            print("[tn init] Already have an account, or attaching this project later?")
            print("[tn init]   tn auth login              # sign in (browser) + back up")
            print("[tn init]   tn auth connect <code>     # headless: redeem a connect code")
            print()
        except Exception as e:  # noqa: BLE001 — vault backup is best-effort; ceremony stays valid
            print(f"[tn init] WARN backup to vault failed: {e}")
            print(f"[tn init]   The ceremony at {yaml_path} is still valid; retry with")
            print(f"[tn init]   ``tn wallet link {yaml_path} --vault {vault_url}``.")
        finally:
            if client is not None:
                # _SnapshotPostingClient wraps a VaultClient; reach through.
                try:
                    client._vc.close()
                except Exception:  # noqa: BLE001 — best-effort client close
                    pass
            tn.flush_and_close()

    return 0
