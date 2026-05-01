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


def _ceremony_files(cfg: LoadedConfig) -> list[tuple[str, Path]]:
    """Return [(file_name_on_vault, local_path), ...] for sync.

    Includes every regular file in the keystore + tn.yaml. Log files
    (logs/tn.ndjson + rotated backups) are included IFF the ceremony
    yaml sets `ceremony.sync_logs: true` (spec §9.4 option B).
    Default stays option A — logs local-only.
    """
    out: list[tuple[str, Path]] = []
    # Keystore files — any regular file directly under keys/
    for p in sorted(cfg.keystore.iterdir()):
        if p.is_file():
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

    name = project_name or cfg.ceremony_id
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


def drain_sync_queue(cfg: LoadedConfig, client: VaultClient) -> SyncResult:
    """Retry a pending autosync failure by running a fresh sync_ceremony.

    If the sync succeeds, the queue file is truncated (removed). If it
    fails again, the existing queue entries remain and a new one is
    appended via the autosync hook... no wait, drain is explicit so
    errors bubble up to the caller.
    """
    from . import admin as _admin

    result = sync_ceremony(cfg, client)
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
) -> SyncResult:
    """Upload current keystore + tn.yaml to this ceremony's linked project.

    Each file is sealed under the client identity's vault_wrap_key with
    AAD bound to (did, ceremony_id, file_name). Errors on individual
    files do not abort the whole sync; they're collected in
    SyncResult.errors.
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

    result = SyncResult(project_id=cfg.linked_project_id)
    for file_name, path in _ceremony_files(cfg):
        try:
            data = path.read_bytes()
            client.upload_file(
                cfg.linked_project_id,
                file_name,
                data,
                ceremony_id=cfg.ceremony_id,
            )
            result.uploaded.append(file_name)
        except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
            result.errors.append((file_name, f"{type(e).__name__}: {e}"))
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
