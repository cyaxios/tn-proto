"""KeystoreBackend Protocol + LocalFileKeystoreBackend invariants."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tn._keystore_backend import (
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
