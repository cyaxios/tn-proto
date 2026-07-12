"""Keystore persistence backend.

Owns the atomic-write primitive plus the CAS protocol for multi-writer
safety. The cipher layer used to do ``path.write_bytes(...)`` directly;
that pattern has no tear-resistance and no concurrency story. Enrollment
state also reuses this primitive for its durable local records.
"""
from __future__ import annotations

import errno
import logging
import os
import secrets
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


def durable_mkdir(path: Path) -> None:
    """Create missing directories top-down, durably linking every new name."""
    path = Path(path)
    if path.exists():
        if not path.is_dir():
            raise NotADirectoryError(f"directory path is not a directory: {path}")
        _fsync_directory(path.parent)
        return

    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    if cursor.exists() and not cursor.is_dir():
        raise NotADirectoryError(f"directory ancestor is not a directory: {cursor}")
    if cursor.exists():
        # Confirm the deepest existing frontier before linking children below
        # it. This also closes the retry case where an earlier mkdir succeeded
        # but synchronizing its containing directory failed.
        _fsync_directory(cursor.parent)

    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            # Another creator may win between discovery and mkdir. Observe a
            # real directory, then synchronize the containing name exactly as
            # for our own creation; any non-directory collision still fails.
            if not directory.is_dir():
                raise
        _fsync_directory(directory.parent)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically and owner-only: tmp file
    (created ``0600``) + fsync + replace.

    Guarantees:
      * On success, ``path`` contains exactly ``data``.
      * On failure before ``os.replace``, the *existing* contents of ``path``
        (if any) are untouched. A directory-fsync failure occurs after replace:
        it is reported, but ``path`` may already contain ``data`` and its crash
        durability is unconfirmed.
      * Temporary siblings use unique, exclusive names and are removed after
        success. Failure cleanup is best-effort, so a cleanup error can leave
        an inert stale temporary file without changing the target.
      * Missing parent directories are created top-down; each new directory
        name is synchronized through its containing parent before descending.
        The deepest preexisting directory link is also synchronized so a retry
        after an earlier mkdir/fsync failure cannot silently skip durability.
      * POSIX permissions are ``0600`` (owner read/write only) from
        creation, not after a chmod race: the tmp file is opened with
        ``os.open(..., O_CREAT | O_EXCL | O_WRONLY, 0o600)`` and the
        atomic ``os.replace`` carries those bits onto ``path``. This
        matters because some callers write secret key material (Ed25519
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
    durable_mkdir(parent)
    tmp = parent / (
        f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}."
        f"{secrets.token_hex(8)}"
    )
    replaced = False
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with open(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        replaced = True
        _fsync_directory(parent)
    except BaseException:
        # Some targets hold secret key material. A failed durable write must
        # surface, never be hidden: report whether replace already completed,
        # run best-effort temp cleanup, then re-raise the original failure.
        if replaced:
            _log.error(
                "keystore directory sync failed for %s after replace; target "
                "may contain new state but crash durability is unconfirmed",
                path,
            )
        else:
            _log.error(
                "keystore atomic write failed for %s (tmp=%s); target was not replaced",
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


def _directory_sync_unsupported(exc: OSError, *, opening: bool) -> bool:
    unsupported = {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    if exc.errno in unsupported:
        return True
    # CPython on Windows cannot open a directory with os.open for fsync.
    return bool(
        opening and os.name == "nt" and exc.errno in {errno.EACCES, errno.EPERM}
    )


def _fsync_directory(path: Path) -> None:
    """Synchronize a directory entry, ignoring only unsupported operations."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY  # type: ignore[attr-defined]
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if _directory_sync_unsupported(exc, opening=True):
            return
        raise
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if not _directory_sync_unsupported(exc, opening=False):
                raise
    finally:
        os.close(fd)


def secure_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Owner-only atomic text write — the str twin of :func:`atomic_write_bytes`.

    Encodes ``text`` and hands off to :func:`atomic_write_bytes`, so it
    inherits the same guarantees: durable parent creation, same-dir tmp file
    created ``0600``, fsync, atomic ``os.replace``, tmp cleanup on failure,
    and log+reraise on a durability error. Use this for secret-bearing text
    files (sync state JSON carrying the BEK, the claim-URL file whose fragment
    is the BEK)
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


class AdvisoryFileLock:
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
        self._os_lock_held = False
        self._proc_lock = _process_lock_for(self._path)
        self._proc_lock_held = False

    def __enter__(self) -> AdvisoryFileLock:
        import os as _os

        try:
            durable_mkdir(self._path.parent)
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
            self._os_lock_held = True
            return self
        except BaseException:
            # Context-manager __exit__ is never called when __enter__ fails.
            # Roll back every successfully acquired layer here so this path
            # cannot permanently poison the per-path process lock.
            try:
                self._release()
            except Exception:  # noqa: BLE001 — preserve acquisition failure
                # Cleanup failure must not replace the acquisition error.
                pass
            raise

    def __exit__(self, *exc: object) -> None:
        self._release()

    def _release(self) -> None:
        import os as _os

        try:
            if self._fd is not None:
                try:
                    if self._os_lock_held:
                        try:
                            import fcntl as _fcntl

                            _fcntl.flock(self._fd, _fcntl.LOCK_UN)  # type: ignore[attr-defined]
                        except ImportError:
                            import msvcrt as _msvcrt

                            _os.lseek(self._fd, 0, 0)
                            _msvcrt.locking(self._fd, _msvcrt.LK_UNLCK, 1)
                        except OSError:
                            pass
                finally:
                    try:
                        _os.close(self._fd)
                    finally:
                        self._fd = None
                        self._os_lock_held = False
            else:
                self._os_lock_held = False
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
        durable_mkdir(self._dir)

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
        with AdvisoryFileLock(self._lock_path(group_name)):
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
