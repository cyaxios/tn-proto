"""KeystoreBackend Protocol + LocalFileKeystoreBackend invariants."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import tn._keystore_backend as backend_module
from tn._keystore_backend import (
    AdvisoryFileLock,
    KeystoreConflictError,
    LocalFileKeystoreBackend,
)


def test_local_backend_round_trip(tmp_path: Path) -> None:
    b = LocalFileKeystoreBackend(tmp_path)
    assert b.read_state("payments") is None
    b.write_state("payments", prior=None, new=b"v1")
    assert b.read_state("payments") == b"v1"


def test_local_backend_cas_detects_conflict(tmp_path: Path) -> None:
    """Two writers reading the same prior — exactly one write wins."""
    b = LocalFileKeystoreBackend(tmp_path)
    b.write_state("payments", prior=None, new=b"v1")

    seen_a = b.read_state("payments")
    seen_b = b.read_state("payments")
    assert seen_a == seen_b == b"v1"

    b.write_state("payments", prior=seen_a, new=b"v2-A")
    with pytest.raises(KeystoreConflictError):
        b.write_state("payments", prior=seen_b, new=b"v2-B")
    assert b.read_state("payments") == b"v2-A"


def test_local_backend_cas_prior_none_requires_no_file(tmp_path: Path) -> None:
    """write_state(prior=None) requires the file not to exist yet."""
    b = LocalFileKeystoreBackend(tmp_path)
    b.write_state("payments", prior=None, new=b"v1")
    with pytest.raises(KeystoreConflictError):
        b.write_state("payments", prior=None, new=b"v2")


def test_local_backend_tear_resistant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed write leaves the prior value intact (atomic_write_bytes underneath)."""
    b = LocalFileKeystoreBackend(tmp_path)
    b.write_state("payments", prior=None, new=b"v1")

    def boom(fd: int) -> None:
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(backend_module, "_fsync_directory", lambda _path: None)
    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError, match="simulated fsync failure"):
        b.write_state("payments", prior=b"v1", new=b"v2")
    monkeypatch.undo()
    assert b.read_state("payments") == b"v1"


def test_local_backend_independent_keys(tmp_path: Path) -> None:
    """Different group names live in different files; no cross-talk."""
    b = LocalFileKeystoreBackend(tmp_path)
    b.write_state("payments", prior=None, new=b"pv1")
    b.write_state("audits", prior=None, new=b"av1")
    assert b.read_state("payments") == b"pv1"
    assert b.read_state("audits") == b"av1"


def test_concurrent_writers_serialise_via_lock(tmp_path: Path) -> None:
    """N threads racing read+CAS-write+retry on the same group all
    land their mutation.

    Mirrors the Rust ``concurrent_writers_serialise_via_lock`` test —
    proves the OS-level lock + CAS combo prevents lost updates.
    Without the lock, the read-then-write window would be a TOCTOU
    race and the final state length would be < expected.
    """
    import threading

    b = LocalFileKeystoreBackend(tmp_path)
    b.write_state("payments", prior=None, new=b"v0")

    n = 20

    def worker(i: int) -> None:
        while True:
            current = b.read_state("payments")
            new = (current or b"") + bytes([ord("a") + (i % 26)])
            try:
                b.write_state("payments", prior=current, new=new)
                return
            except KeystoreConflictError:
                continue

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = b.read_state("payments")
    assert final is not None
    # Initial "v0" (2 bytes) + n single-byte appends. Every mutation
    # must have landed; the CAS+lock combo serialised them.
    assert len(final) == 2 + n, (
        f"expected every concurrent write to land; got len={len(final)}"
    )


def test_advisory_lock_releases_process_lock_when_open_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = tmp_path / "open-failure.lock"
    failed_lock = AdvisoryFileLock(lock_path)
    real_open = os.open

    def fail_lock_file_open(path: os.PathLike[str] | str, *args: object, **kwargs: object) -> int:
        if Path(path) == lock_path:
            raise OSError("simulated lock open failure")
        return real_open(path, *args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(os, "open", fail_lock_file_open)
        with pytest.raises(OSError, match="simulated lock open failure"):
            failed_lock.__enter__()

    assert failed_lock._fd is None
    assert failed_lock._os_lock_held is False
    assert failed_lock._proc_lock_held is False
    assert failed_lock._proc_lock.acquire(blocking=False)
    failed_lock._proc_lock.release()
    with AdvisoryFileLock(lock_path):
        pass


def test_advisory_lock_releases_fd_and_process_lock_when_os_lock_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = tmp_path / "os-lock-failure.lock"
    failed_lock = AdvisoryFileLock(lock_path)

    with monkeypatch.context() as patcher:
        if os.name == "nt":
            import msvcrt

            patcher.setattr(
                msvcrt,
                "locking",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    OSError("simulated OS lock failure")
                ),
            )
        else:
            import fcntl

            patcher.setattr(
                fcntl,
                "flock",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    OSError("simulated OS lock failure")
                ),
            )
        with pytest.raises(OSError, match="simulated OS lock failure"):
            failed_lock.__enter__()

    assert failed_lock._fd is None
    assert failed_lock._os_lock_held is False
    assert failed_lock._proc_lock_held is False
    assert failed_lock._proc_lock.acquire(blocking=False)
    failed_lock._proc_lock.release()
    with AdvisoryFileLock(lock_path):
        pass
