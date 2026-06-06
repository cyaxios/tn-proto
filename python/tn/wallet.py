"""Wallet operations: sync ceremonies to and from the vault.

High-level verbs that operate on a LoadedConfig + VaultClient pair:

    wallet.sync_ceremony(cfg, client)
    wallet.restore_ceremony(client, project_id, target_dir)
    wallet.link_ceremony(cfg, client, project_name=...)

These wrap the sealing + upload + manifest dance so the CLI and
scenario code don't each re-invent it.

Not wired into admin verbs (rotate, ensure_group, etc.) in V1 —
callers must invoke sync explicitly after a state change. That keeps
network I/O explicit and testable. A future pass may add an opt-in
autosync flag inside admin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import admin as _admin
from .config import LoadedConfig
from .identity import Identity
from .sealing import SealedBlob, _unseal
from .vault_client import VaultClient, VaultError

# ---------------------------------------------------------------------
# Which files get synced
# ---------------------------------------------------------------------


def _collect_body_members(cfg: LoadedConfig) -> dict[str, bytes]:
    """Collect the ceremony body keyed ``body/<name>`` for the AWK/BEK push.

    Every regular keystore file (minus transient ``*.lock`` mutexes) lands
    at ``body/keys/<name>`` and the yaml at ``body/tn.yaml`` — the layout
    the browser minter (project_minter.js) packs and the restore side
    (``wallet_restore._write_restored_bytes``) unpacks. Mirrors the TS
    ``collectBodyMembers`` (sans the opt-in log files).

    Log files are included under ``body/logs/<name>`` IFF the ceremony
    yaml sets ``ceremony.sync_logs: true`` (spec §9.4 option B); default
    stays option A — logs local-only.
    """
    body: dict[str, bytes] = {}
    for p in sorted(cfg.keystore.iterdir()):
        if p.is_file() and p.suffix != ".lock":
            body[f"body/keys/{p.name}"] = p.read_bytes()
    body["body/tn.yaml"] = cfg.yaml_path.read_bytes()
    if getattr(cfg, "sync_logs", False):
        logs_dir = cfg.resolve_log_path().parent
        if logs_dir.is_dir():
            for p in sorted(logs_dir.iterdir()):
                # Skip transient emit-lock mutexes (same rationale as the
                # keystore *.lock skip): a held lock is local btn state, not
                # worth backing up and harmful to restore.
                if p.is_file() and p.suffix != ".lock":
                    body[f"body/logs/{p.name}"] = p.read_bytes()
    return body


def _ceremony_files(cfg: LoadedConfig) -> list[tuple[str, Path]]:
    """Return [(file_name_on_vault, local_path), ...] for sync.

    Includes every regular file in the keystore + tn.yaml. Log files
    (logs/tn.ndjson + rotated backups) are included IFF the ceremony
    yaml sets `ceremony.sync_logs: true` (spec §9.4 option B).
    Default stays option A — logs local-only.
    """
    out: list[tuple[str, Path]] = []
    # Keystore files — any regular file directly under keys/, EXCEPT
    # transient concurrency locks. A ``*.lock`` is a local btn-state mutex;
    # backing it up is pointless and restoring one can wedge the restored
    # ceremony. (Also avoids a vault 500 on re-PUT of a held lock file.)
    for p in sorted(cfg.keystore.iterdir()):
        if p.is_file() and p.suffix != ".lock":
            out.append((p.name, p))
    # The yaml itself (stored at vault path "tn.yaml")
    out.append(("tn.yaml", cfg.yaml_path))
    # Log files, only if opted in via ceremony.sync_logs
    if getattr(cfg, "sync_logs", False):
        logs_dir = cfg.resolve_log_path().parent
        if logs_dir.is_dir():
            for p in sorted(logs_dir.iterdir()):
                if p.is_file():
                    # Prefix with "logs/" so the vault file_name is unique
                    # vs keystore entries.
                    out.append((f"logs__{p.name}", p))
    return out


# ---------------------------------------------------------------------
# Sync results
# ---------------------------------------------------------------------


@dataclass
class SyncResult:
    uploaded: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    project_id: str | None = None
    # Two-device group sync: group names whose KEY material was published to
    # the OWN account inbox (append-only merge path) alongside the body push.
    # Empty when the ceremony has no btn groups or publish was skipped.
    published_groups: list[str] = field(default_factory=list)
    # Soft warning if the (best-effort) group-keys publish failed. The body
    # push already succeeded; a publish failure is non-fatal and is NOT added
    # to ``errors`` (mirrors the TS reference's stderr WARN). None on success.
    publish_warning: str | None = None


# ---------------------------------------------------------------------
# link_ceremony: bind a local ceremony to a vault project
# ---------------------------------------------------------------------


def link_ceremony(
    cfg: LoadedConfig,
    client: VaultClient,
    *,
    project_name: str | None = None,
) -> LoadedConfig:
    """Create a vault project for this ceremony and flip mode=linked.

    Idempotent: if the ceremony is already linked to the same vault,
    returns cfg unchanged. If linked to a different vault, raises.
    """
    if cfg.is_linked() and cfg.linked_vault == client.base_url:
        return cfg
    if cfg.mode == "linked" and cfg.linked_vault and cfg.linked_vault != client.base_url:
        raise RuntimeError(
            f"ceremony {cfg.ceremony_id} is already linked to "
            f"{cfg.linked_vault}; unlink first before re-linking",
        )

    # 0.4.2a9: prefer the operator-chosen project_name stamped into
    # the yaml (`ceremony.project_name`). Fall back to ceremony_id
    # for legacy ceremonies that don't carry the field. Explicit
    # `project_name=` kwarg still wins (caller knows best).
    name = project_name or cfg.project_name or cfg.ceremony_id
    project: dict[Any, Any] | None
    try:
        project = client.create_project(name=name, ceremony_id=cfg.ceremony_id)
    except VaultError as exc:
        # 409 means a project with this name already exists under this DID.
        # Find it and reuse its ID (idempotent re-link after unlink).
        if exc.status == 409:
            projects = client.list_projects()
            project = next(
                (p for p in projects if p.get("name") == name),
                None,
            )
            if project is None:
                raise VaultError(
                    f"vault returned 409 for project {name!r} but list "
                    f"returned no match — cannot re-link",
                ) from exc
        else:
            raise
    if project is None:
        # Defensive: either create succeeded or the 409-branch raised.
        raise RuntimeError("project remained None after create/list resolution")
    project_id = project.get("id") or project.get("_id")
    if not project_id:
        raise VaultError(f"create_project response missing id: {project}")

    _admin.set_link_state(
        cfg,
        mode="linked",
        linked_vault=client.base_url,
        linked_project_id=project_id,
    )
    return cfg


# ---------------------------------------------------------------------
# publish_group_keys: append-only group-key snapshot to OWN account inbox
# ---------------------------------------------------------------------


def publish_group_keys(
    cfg: LoadedConfig,
    client: VaultClient,
    *,
    sign_with: Any | None = None,
    author_did: str | None = None,
    groups: list[str] | None = None,
) -> list[str]:
    """Publish the ceremony's group KEY material to the OWN account inbox so
    a SECOND device on the same account ends up with the groups INSTALLED +
    ROUTABLE after its next ``pull -> absorb``.

    1:1 with the TS reference ``wallet_sync.publishGroupKeys``. This is the
    merge-path companion to the last-write-wins body push: the body blob is
    content (lost on overwrite), the group keys ride the append-only inbox
    (union-merged).

    Exports a ``group_keys`` ``.tnpkg`` (group ``.btn.state`` / ``.btn.mykit``
    + the yaml ``groups.<name>`` blocks — NO device secret) and POSTs it to
    this device's OWN inbox at
    ``/api/v1/inbox/{did}/snapshots/{ceremony}/{ts}.tnpkg``.

    The snapshot is authored AS the account-bound identity DID — the vault's
    inbox POST requires ``manifest.publisher_identity == auth_did``. By
    default this is ``cfg.device`` (the ceremony device key, which the CLI
    authenticates the ``client`` as via DID challenge); pass ``sign_with`` /
    ``author_did`` to author as a distinct identity device key.

    Best-effort: a ceremony with no btn groups (only ``tn.agents``)
    publishes nothing. Returns the published group names (empty when
    nothing was sent). Raises on a genuine POST failure so the caller can
    decide whether to swallow it (``sync_ceremony`` does, per the TS).
    """
    import tempfile
    from datetime import datetime, timezone

    from .export import export_group_keys
    from .handlers.vault_push import _SnapshotPostingClient

    # The DID the snapshot is authored as. Mirrors TS `authorKey.did`.
    own_did = author_did or (
        sign_with.did if sign_with is not None else cfg.device.device_identity
    )

    td = Path(tempfile.mkdtemp(prefix="tn-groupkeys-"))
    pkg_path = td / "group_keys.tnpkg"
    try:
        try:
            export_group_keys(
                pkg_path,
                cfg=cfg,
                groups=groups,
                sign_with=sign_with,
                author_did=author_did,
            )
        except (RuntimeError, FileNotFoundError):
            # No btn groups with key material — nothing to publish.
            return []

        names = sorted(g for g in cfg.groups if g != "tn.agents")
        body = pkg_path.read_bytes()

        # Inbox snapshot timestamp YYYYMMDDTHHMMSS<micros>Z — the shape the
        # vault's _TS_RE accepts. Matches push_snapshot / TS inboxSnapshotTs.
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        url_path = (
            f"/api/v1/inbox/{own_did}/snapshots/{cfg.ceremony_id}/{ts}.tnpkg"
        )
        # Reuse the existing adapter (lazy DID-challenge auth + 401 retry).
        poster = _SnapshotPostingClient(client)
        poster.post_inbox_snapshot(url_path, body)
    finally:
        import shutil

        try:
            shutil.rmtree(td, ignore_errors=True)
        except OSError:
            pass
    return names


# ---------------------------------------------------------------------
# sync_ceremony: push current state up
# ---------------------------------------------------------------------


def read_sync_queue(ceremony_id: str) -> list[dict]:
    """Read pending autosync failures for a ceremony (if any).

    Returns a list of {ceremony_id, ts, error} entries. Empty list if
    the queue file doesn't exist.
    """
    import json as _json

    from . import admin as _admin

    path = _admin._sync_queue_path(ceremony_id)
    if not path.is_file():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue
    return out


def drain_sync_queue(
    cfg: LoadedConfig,
    client: VaultClient,
    *,
    passphrase: str | None = None,
) -> SyncResult:
    """Retry a pending autosync failure by running a fresh sync_ceremony.

    If the sync succeeds, the queue file is truncated (removed). If it
    fails again, the existing queue entries remain and a new one is
    appended via the autosync hook... no wait, drain is explicit so
    errors bubble up to the caller.
    """
    from . import admin as _admin

    result = sync_ceremony(cfg, client, passphrase=passphrase, publish_groups=False)
    if not result.errors:
        path = _admin._sync_queue_path(cfg.ceremony_id)
        if path.is_file():
            try:
                path.unlink()
            except OSError:
                pass
    return result


def sync_ceremony(
    cfg: LoadedConfig,
    client: VaultClient,
    *,
    passphrase: str | None = None,
    if_match: str | None = None,
    publish_groups: bool = True,
    sign_with: Any | None = None,
    author_did: str | None = None,
) -> SyncResult:
    """Push the current keystore + tn.yaml to this ceremony's linked project.

    Uses the SUPPORTED AWK/BEK whole-body model (D-20 / D-22), NOT the
    deprecated per-file ``client.upload_file`` sealing: the ceremony body
    (keystore files + ``tn.yaml``) is packed into a STORED zip, AES-256-GCM
    encrypted as a no-AAD ``nonce||ct`` frame under the project BEK (minted
    + wrapped under the account AWK on first push, else derived), and PUT
    to ``encrypted-blob-account`` with ``If-Match``. This is the exact
    inverse of ``tn wallet restore --passphrase`` — a body pushed here
    round-trips through that verb. See :mod:`tn.wallet_push`.

    The push needs the account ``passphrase`` (to derive the AWK that
    wraps the project BEK) and a bearer JWT (taken from the authed
    ``client.token``). When either is missing the failure is recorded in
    ``SyncResult.errors`` rather than raised, preserving the
    "errors don't abort" contract callers (autosync queue, warm-attach)
    rely on.

    ``if_match`` overrides the auto-resolved blob generation (tests).
    """
    if not cfg.is_linked():
        raise RuntimeError(
            f"ceremony {cfg.ceremony_id} is not linked; call link_ceremony() first",
        )
    if cfg.linked_project_id is None:
        raise RuntimeError(
            f"ceremony {cfg.ceremony_id} claims linked mode but has no "
            f"linked_project_id; relink to repair",
        )

    from . import wallet_push as _wallet_push

    result = SyncResult(project_id=cfg.linked_project_id)

    bearer = client.token
    if not bearer:
        # Authenticate so the account routes resolve the bound account.
        try:
            bearer = client.authenticate()
        except Exception as e:  # noqa: BLE001 — record, don't abort
            result.errors.append(("<auth>", f"{type(e).__name__}: {e}"))
            return result

    if not passphrase:
        result.errors.append(
            (
                "<passphrase>",
                "account passphrase required to push the body backup "
                "(derives the AWK that wraps the project BEK); pass "
                "--passphrase",
            ),
        )
        return result

    body = _collect_body_members(cfg)
    vault_url = cfg.linked_vault or client.base_url
    try:
        _wallet_push.push_ceremony_body(
            vault_url=vault_url,
            bearer=bearer,
            project_id=cfg.linked_project_id,
            passphrase=passphrase,
            body=body,
            if_match=if_match,
        )
    except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
        result.errors.append((cfg.ceremony_id, f"{type(e).__name__}: {e}"))
        return result

    # Mirror the prior per-file `uploaded` list: one entry per body member,
    # with the `body/` prefix stripped so the names read like file paths.
    result.uploaded = sorted(k[len("body/"):] for k in body)

    # Two-device group sync: in ADDITION to the last-write-wins body blob,
    # publish the ceremony's group KEY material to the OWN account inbox.
    # The other device's pull -> absorb then INSTALLS + REGISTERS the groups
    # (union-merged, idempotent) — so a group added becomes USABLE on the
    # other device without depending on the body blob (overwritten on its
    # next push). Best-effort: a publish failure must not fail the body sync
    # (mirrors the TS reference). Skipped for the drain-queue retry.
    if publish_groups:
        try:
            result.published_groups = publish_group_keys(
                cfg,
                client,
                sign_with=sign_with,
                author_did=author_did,
            )
        except Exception as e:  # noqa: BLE001 — publish must not fail body sync
            # Soft warning only — the body push already succeeded. Mirrors the
            # TS reference, which writes a stderr WARN and does NOT fail sync.
            result.publish_warning = f"{type(e).__name__}: {e}"
    return result


# ---------------------------------------------------------------------
# restore_ceremony: pull a project's files into a workspace
# ---------------------------------------------------------------------


@dataclass
class RestoreResult:
    yaml_path: Path
    keystore: Path
    files_restored: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)


def restore_ceremony(
    client: VaultClient,
    project_id: str,
    *,
    target_dir: Path,
    ceremony_id: str | None = None,
) -> RestoreResult:
    """Pull a project's files from the vault into `target_dir`.

    Writes:
      target_dir/tn.yaml
      target_dir/keys/<group>.jwe.sender
      target_dir/keys/<group>.jwe.recipients
      ...

    Returns paths to the restored yaml and keystore. Caller is
    responsible for calling tn.init(yaml_path, ...) after this.

    `ceremony_id` is required to verify AAD; if not passed, it is
    read from the restored tn.yaml.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    keystore = target_dir / ".tn" / "keys"
    keystore.mkdir(exist_ok=True)

    result = RestoreResult(yaml_path=target_dir / "tn.yaml", keystore=keystore)

    # Fetch manifest first so we know what files to expect.
    manifest = client.restore_manifest(project_id)
    files = manifest.get("files", [])

    # If ceremony_id wasn't provided, download tn.yaml FIRST without AAD
    # verification so we can read the ceremony id out of it.
    pending = list(files)
    if ceremony_id is None:
        yaml_entry = next(
            (f for f in pending if f.get("name") == "tn.yaml"),
            None,
        )
        if yaml_entry is None:
            raise VaultError(
                f"project {project_id} restore manifest has no tn.yaml",
            )
        blob = client.download_sealed(project_id, "tn.yaml")
        # We don't know the expected ceremony_id yet, so we trust the AAD
        # embedded in the blob. The remaining files we'll verify with the
        # extracted ceremony_id.
        yaml_bytes = (
            _unseal(
                blob,
                wrap_key=client.identity.vault_wrap_key(),
                expected_did=client.identity.did,
                expected_ceremony_id=None,
                expected_file_name=None,
            )
            if False
            else _unseal_trust_aad(blob, client.identity)
        )
        (target_dir / "tn.yaml").write_bytes(yaml_bytes)
        result.files_restored.append("tn.yaml")
        # parse tn.yaml to read ceremony id
        doc = yaml.safe_load(yaml_bytes) or {}
        ceremony_id = str((doc.get("ceremony") or {}).get("id") or "")
        if not ceremony_id:
            raise VaultError("restored tn.yaml has no ceremony.id")
        pending = [f for f in pending if f.get("name") != "tn.yaml"]

    # Download remaining files with strict AAD check.
    for f in pending:
        name = f.get("name")
        if not name:
            continue
        try:
            data = client.download_file(
                project_id,
                name,
                ceremony_id=ceremony_id,
            )
            dst = (target_dir / "tn.yaml") if name == "tn.yaml" else (keystore / name)
            dst.write_bytes(data)
            result.files_restored.append(name)
        except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
            result.errors.append((name, f"{type(e).__name__}: {e}"))

    return result


def _unseal_trust_aad(blob: SealedBlob, identity: Identity) -> bytes:
    """Unseal a blob while trusting its embedded AAD.

    Used only by restore when we don't yet know the expected
    ceremony_id (first-time pull of tn.yaml). AES-GCM still
    authenticates the ciphertext against the AAD the blob carries;
    the DID check is enforced by parsing the AAD after _unseal.
    """
    # AES-GCM authenticates against whatever AAD is embedded; a wrong
    # wrap key still fails _unseal, so the worst case here is the blob
    # decrypting to bytes we then parse as yaml.
    return _unseal(blob, wrap_key=identity.vault_wrap_key())
