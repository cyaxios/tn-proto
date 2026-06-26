"""Keystore persistence backend.

Owns the atomic-write primitive plus the CAS protocol for multi-writer
safety. The cipher layer used to do ``path.write_bytes(...)`` directly;
that pattern has no tear-resistance and no concurrency story. This
module is the single place that writes durable keystore files.
"""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Protocol

_log = logging.getLogger("tn.keystore")


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
    """Write ``data`` to ``path`` atomically and owner-only: tmp file
    (created ``0600``) + fsync + replace.

    Guarantees:
      * On success, ``path`` contains exactly ``data``.
      * On failure mid-write (including OSError from fsync/replace),
        the *existing* contents of ``path`` (if any) are untouched.
      * No ``.<name>.tmp.<pid>`` siblings remain after either outcome.
      * POSIX permissions are ``0600`` (owner read/write only) from
        creation, not after a chmod race: the tmp file is opened with
        ``os.open(..., O_CREAT | O_WRONLY | O_TRUNC, 0o600)`` and the
        atomic ``os.replace`` carries those bits onto ``path``. This
        matters because every caller writes secret key material (Ed25519
        seeds, index master keys, btn state/kits). On Windows the mode
        argument is a no-op (POSIX bits don't apply); the protection
        there is the user-profile ACL, the same posture the credential
        store already takes.

    Uses ``os.replace``, which is atomic on POSIX and Windows when the
    source and destination share a filesystem (the keystore tmp file is
    always created in the same dir as its target, so this holds).
    """
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp = parent / f".{path.name}.tmp.{os.getpid()}"
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with open(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        # The keystore holds secret key material. A failed durable write
        # must surface, never be hidden: log which path/op failed, run a
        # best-effort temp cleanup, then re-raise the original failure.
        _log.error(
            "keystore atomic write failed for %s (tmp=%s); secret state was "
            "NOT persisted",
            path,
            tmp,
        )
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            _log.warning(
                "keystore temp cleanup failed for %s; a stale temp file may "
                "remain (does not affect the existing keystore contents)",
                tmp,
            )
        raise


def secure_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Owner-only atomic text write — the str twin of :func:`atomic_write_bytes`.

    Encodes ``text`` and hands off to :func:`atomic_write_bytes`, so it
    inherits the same guarantees: same-dir tmp file created ``0600``,
    fsync, atomic ``os.replace``, tmp cleanup on failure, and log+reraise
    on a torn write. Use this for secret-bearing text files (sync state
    JSON carrying the BEK, the claim-URL file whose fragment is the BEK)
    that previously went through ``Path.write_text`` with the default
    umask. On Windows the POSIX mode is a no-op; the user-profile ACL is
    the protection, same as the keystore/credential-store posture.
    """
    atomic_write_bytes(Path(path), text.encode(encoding))


# Per-path in-process locks. Stops two threads in THIS process from
# both passing the OS-level acquire and racing through the CAS body
# — which can happen on platforms where the OS file lock is
# per-file-handle (e.g. Windows' msvcrt.locking) rather than
# per-file. On POSIX flock is already file-level so this lock is
# strictly defensive there.
_PROCESS_LOCKS: dict[str, threading.Lock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _process_lock_for(path: Path) -> threading.Lock:
    """Return the singleton process-level lock for ``path``.

    Keyed on the resolved path string so two LocalFileKeystoreBackend
    instances pointing at the same lock file share one Lock.
    """
    key = str(Path(path).resolve())
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PROCESS_LOCKS[key] = lock
        return lock


class _AdvisoryFileLock:
    """Cross-platform exclusive advisory file lock.

    Two-tier:

    * In-process: a ``threading.Lock`` keyed on the lock-file path
      serialises threads in the same interpreter. Necessary because
      ``msvcrt.locking`` on Windows operates on the *file handle*,
      not the *file*, so two threads in the same process each
      acquire their own handle and can both pass the OS-level lock
      simultaneously.
    * Cross-process: ``fcntl.flock`` on POSIX (whole-file BSD-style),
      ``msvcrt.locking`` on Windows (over the first byte). Blocks
      writers in *other* processes from entering the CAS body.

    Together: writers serialise correctly within the process AND
    across processes. Mirrors the Rust ``LocalKeystore``'s use of the
    ``fs4`` crate (whose ``LockFileEx`` on Windows is genuinely
    file-level — Python has no stdlib equivalent without ``ctypes``).
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._fd: int | None = None
        self._proc_lock = _process_lock_for(self._path)
        self._proc_lock_held = False

    def __enter__(self) -> _AdvisoryFileLock:
        import os as _os

        # In-process serialisation first. Released last on exit.
        self._proc_lock.acquire()
        self._proc_lock_held = True

        flags = _os.O_CREAT | _os.O_RDWR
        if hasattr(_os, "O_CLOEXEC"):
            flags |= _os.O_CLOEXEC  # type: ignore[attr-defined]
        self._fd = _os.open(self._path, flags, 0o600)
        # Windows byte-range lock needs at least one byte to lock.
        # POSIX flock is whole-file and doesn't care; the write is
        # harmless either way.
        try:
            _os.write(self._fd, b"\0")
            _os.lseek(self._fd, 0, 0)
        except OSError:
            pass

        try:
            import fcntl as _fcntl

            _fcntl.flock(self._fd, _fcntl.LOCK_EX)  # type: ignore[attr-defined]
        except ImportError:
            # Windows: msvcrt.locking with LK_LOCK retries ~10 times
            # at ~1s intervals before raising. Combined with the
            # in-process threading.Lock above, contention is bounded
            # by inter-process traffic only (microsecond-scale per
            # writer) so the retry budget is plenty.
            import msvcrt as _msvcrt

            _msvcrt.locking(self._fd, _msvcrt.LK_LOCK, 1)
        return self

    def __exit__(self, *exc: object) -> None:
        import os as _os

        try:
            if self._fd is not None:
                try:
                    try:
                        import fcntl as _fcntl

                        _fcntl.flock(self._fd, _fcntl.LOCK_UN)  # type: ignore[attr-defined]
                    except ImportError:
                        import msvcrt as _msvcrt

                        try:
                            _os.lseek(self._fd, 0, 0)
                            _msvcrt.locking(self._fd, _msvcrt.LK_UNLCK, 1)
                        except OSError:
                            pass
                finally:
                    try:
                        _os.close(self._fd)
                    finally:
                        self._fd = None
        finally:
            if self._proc_lock_held:
                self._proc_lock.release()
                self._proc_lock_held = False


class LocalFileKeystoreBackend:
    """Filesystem-backed :class:`KeystoreBackend`.

    State for each ``group_name`` lives at
    ``<keystore_dir>/<group_name>.btn.state``. Writes use:

    1. :func:`atomic_write_bytes` so a torn write never leaves a
       partial file on disk.
    2. An OS-level advisory lock on a sibling
       ``<group>.btn.state.lock`` file (``fcntl.flock`` on POSIX,
       ``msvcrt.locking`` on Windows). Serialises concurrent writers
       across both threads and processes — last writer no longer
       silently wins.
    3. Compare-and-swap re-read under the lock: ``prior`` is compared
       byte-for-byte against the current on-disk state. Mismatch
       raises :class:`KeystoreConflictError` so the caller re-reads,
       re-applies their mutation, and retries.

    Matches the Rust ``keystore_backend::LocalKeystore`` semantics so
    Python and Rust writers contending on the same keystore directory
    are mutually safe.
    """

    def __init__(self, keystore_dir: Path) -> None:
        self._dir = Path(keystore_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, group_name: str) -> Path:
        return self._dir / f"{group_name}.btn.state"

    def _lock_path(self, group_name: str) -> Path:
        return self._dir / f"{group_name}.btn.state.lock"

    def read_state(self, group_name: str) -> bytes | None:
        p = self._path(group_name)
        if not p.exists():
            return None
        return p.read_bytes()

    def write_state(
        self, group_name: str, prior: bytes | None, new: bytes
    ) -> None:
        with _AdvisoryFileLock(self._lock_path(group_name)):
            # Under the lock: re-read on-disk state and CAS against
            # the caller's prior snapshot. Without the lock this read
            # would be a TOCTOU race vs. another process about to
            # commit a write.
            current = self.read_state(group_name)
            if current != prior:
                raise KeystoreConflictError(
                    f"state for {group_name!r} has diverged on disk; "
                    f"re-read and retry"
                )
            atomic_write_bytes(self._path(group_name), new)
