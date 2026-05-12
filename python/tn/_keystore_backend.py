"""Keystore persistence backend.

Owns the atomic-write primitive plus the CAS protocol for multi-writer
safety. The cipher layer used to do ``path.write_bytes(...)`` directly;
that pattern has no tear-resistance and no concurrency story. This
module is the single place that writes durable keystore files.

See ``docs/superpowers/specs/2026-05-12-runtime-correctness-design.md``.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol


class KeystoreConflictError(Exception):
    """Raised when a CAS write detects the on-disk state has diverged
    from what the caller passed as ``prior``. Caller should re-read,
    re-mutate, and retry.
    """


class KeystoreBackend(Protocol):
    """Pluggable persistence for cipher state.

    Today: one Local backend (filesystem). Future: remote backends
    (database, vault, KV with conditional writes) plug in without
    touching cipher callers.
    """

    def read_state(self, group_name: str) -> bytes | None:
        """Return the raw state bytes for ``group_name``, or None if absent."""
        ...

    def write_state(
        self, group_name: str, prior: bytes | None, new: bytes
    ) -> None:
        """Compare-and-swap write. Succeeds iff the on-disk content
        equals ``prior`` (None meaning "must not exist yet"). On
        divergence, raises :class:`KeystoreConflictError`.
        """
        ...


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically: tmp file + fsync + replace.

    Guarantees:
      * On success, ``path`` contains exactly ``data``.
      * On failure mid-write (including OSError from fsync/replace),
        the *existing* contents of ``path`` (if any) are untouched.
      * No ``.<name>.tmp.<pid>`` siblings remain after either outcome.

    Uses ``os.replace``, which is atomic on POSIX and Windows when the
    source and destination share a filesystem (the keystore tmp file is
    always created in the same dir as its target, so this holds).
    """
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp = parent / f".{path.name}.tmp.{os.getpid()}"
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise


class LocalFileKeystoreBackend:
    """Filesystem-backed :class:`KeystoreBackend`.

    State for each ``group_name`` lives at
    ``<keystore_dir>/<group_name>.btn.state``. Writes use
    :func:`atomic_write_bytes` so a torn write never leaves a partial
    file on disk. CAS is enforced by reading the current file and
    comparing to ``prior`` before the write.

    The CAS window today is "best-effort under cooperating writers in
    one process or across processes that aren't actively contending."
    If real multi-writer contention shows up, add an OS-level lock
    (``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows) inside
    :meth:`write_state` without changing the protocol shape.
    """

    def __init__(self, keystore_dir: Path) -> None:
        self._dir = Path(keystore_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, group_name: str) -> Path:
        return self._dir / f"{group_name}.btn.state"

    def read_state(self, group_name: str) -> bytes | None:
        p = self._path(group_name)
        if not p.exists():
            return None
        return p.read_bytes()

    def write_state(
        self, group_name: str, prior: bytes | None, new: bytes
    ) -> None:
        p = self._path(group_name)
        current = self.read_state(group_name)
        if current != prior:
            raise KeystoreConflictError(
                f"state for {group_name!r} has diverged on disk; "
                f"re-read and retry"
            )
        atomic_write_bytes(p, new)
