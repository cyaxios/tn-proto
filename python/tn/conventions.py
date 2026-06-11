"""Conventional filesystem layout under a single ``.tn/`` root.

Every TN-managed directory lives under
``<yaml_dir>/.tn/<yaml-stem>/`` so two yamls in one project don't
collide on the same paths (FINDINGS #2). For a yaml at
``./_register.yaml`` the layout is::

    <yaml_dir>/_register.yaml                    ceremony config
    <yaml_dir>/.tn/_register/keys/               keystore (BTN state, X25519 keys)
    <yaml_dir>/.tn/_register/logs/               main log files (tn.ndjson)
    <yaml_dir>/.tn/_register/admin/              admin event log + cache
    <yaml_dir>/.tn/_register/inbox/              .tnpkg packages awaiting absorb
    <yaml_dir>/.tn/_register/outbox/             .tnpkg packages produced by compile/export
    <yaml_dir>/.tn/_register/config/             agents.md policy, etc.
    <yaml_dir>/.tn/_register/pending_offers/     offers absorbed but not promoted

These helpers accept the yaml *path* (not the parent directory) so the
stem can be extracted; an older ``yaml_dir``-typed caller can pass
``yaml_path.parent / yaml_path.name`` or migrate to passing the path.
"""

from __future__ import annotations

import re
from pathlib import Path

# Single visible root directory for every TN-managed file under a project.
TN_DIR_NAME = ".tn"


def _stem_dir(yaml_path: Path) -> Path:
    """Return the per-yaml-stem subdir under ``.tn/``. Accepts either a
    yaml file path (``./_register.yaml``) or a yaml directory in which
    case stem defaults to ``"tn"`` for back-compat with callers that
    pre-date the stem migration."""
    if yaml_path.suffix in (".yaml", ".yml"):
        return yaml_path.parent / TN_DIR_NAME / yaml_path.stem
    # Caller passed a directory (legacy). Fall back to the canonical
    # default-stem layout.
    return yaml_path / TN_DIR_NAME / "tn"


def tn_dir(yaml_path: Path) -> Path:
    """The per-ceremony ``.tn/<stem>/`` directory."""
    return _stem_dir(yaml_path)


def keys_dir(yaml_path: Path) -> Path:
    return _stem_dir(yaml_path) / "keys"


def logs_dir(yaml_path: Path) -> Path:
    return _stem_dir(yaml_path) / "logs"


def admin_dir(yaml_path: Path) -> Path:
    return _stem_dir(yaml_path) / "admin"


def config_dir(yaml_path: Path) -> Path:
    return _stem_dir(yaml_path) / "config"


def inbox_dir(yaml_path: Path) -> Path:
    return _stem_dir(yaml_path) / "inbox"


def outbox_dir(yaml_path: Path) -> Path:
    return _stem_dir(yaml_path) / "outbox"


def pending_offers_dir(yaml_path: Path) -> Path:
    return _stem_dir(yaml_path) / "pending_offers"


# ---------------------------------------------------------------------------
# Outbox layout — per session-11 plan (2026-04-29-outbox-layout-migration.md).
#
# Three roots used to overlap (.tn/outbox, .tn/outbox/durable/<name>,
# .tn/admin/outbox). All three now live under the per-stem subtree and the
# `durable/` infix is gone. See D-19 (handler-driven sync) and §4 of
# 2026-04-27-vault-passive-backup-and-sync-design.md.
# ---------------------------------------------------------------------------


def admin_outbox_dir(yaml_path: Path) -> Path:
    """Where ``vault.push`` stages admin-log snapshots before POST."""
    return _stem_dir(yaml_path) / "admin" / "outbox"


def admin_inbox_dir(yaml_path: Path) -> Path:
    """Reserved companion to :func:`admin_outbox_dir` — inbound admin
    snapshots (vault → SDK) land here once that flow is implemented.
    Created by :func:`admin_outbox_dir`-aware code paths only on demand."""
    return _stem_dir(yaml_path) / "admin" / "inbox"


def handler_outbox_dir(yaml_path: Path, handler_name: str) -> Path:
    """Per-network-handler durable retry queue path.

    Replaces the legacy ``.tn/outbox/durable/<handler_name>/`` location.
    The new path is ``.tn/<stem>/handlers/<handler_name>/outbox/``.
    """
    return _stem_dir(yaml_path) / "handlers" / handler_name / "outbox"


def legacy_handler_outbox_dir(yaml_dir_or_path: Path, handler_name: str) -> Path:
    """The pre-migration handler outbox path. Used only by read-side
    backward-compat fallbacks; new writes always use
    :func:`handler_outbox_dir`."""
    base = (
        yaml_dir_or_path.parent
        if yaml_dir_or_path.suffix in (".yaml", ".yml")
        else yaml_dir_or_path
    )
    return base / TN_DIR_NAME / "outbox" / "durable" / handler_name


def legacy_admin_outbox_dir(yaml_dir_or_path: Path) -> Path:
    """The pre-migration admin outbox path. Read-side fallback only."""
    base = (
        yaml_dir_or_path.parent
        if yaml_dir_or_path.suffix in (".yaml", ".yml")
        else yaml_dir_or_path
    )
    return base / TN_DIR_NAME / "admin" / "outbox"


_DID_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def tnpkg_filename(peer_did: str | None, kind: str, version: int) -> str:
    # None / empty peer_did is the broadcast-package case; keep the substitution
    # here so callers can pass the dataclass field directly.
    safe = _DID_SAFE.sub("_", peer_did or "broadcast")
    return f"{safe}__{kind}__v{version}.tnpkg"


def ensure_dirs(_yaml_path: Path) -> None:
    """Deprecated. The eager-create-everything pattern produced ghost
    directories visible to operators (FINDINGS S0.2). Each write site
    now creates only the directories it actually uses, on demand. This
    function is intentionally a no-op so legacy callers remain
    source-compatible while the cleanup migrates."""
    return
