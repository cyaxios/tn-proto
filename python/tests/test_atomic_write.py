"""Atomic write invariants — tear-resistance for keystore state files."""
from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

import tn._keystore_backend as backend_module
from tn._keystore_backend import atomic_write_bytes
from tn.cipher import _atomic_write_text


def test_atomic_write_creates_file(tmp_path: Path) -> None:
    p = tmp_path / "state.bin"
    atomic_write_bytes(p, b"hello")
    assert p.read_bytes() == b"hello"


def test_atomic_write_overwrites_existing(tmp_path: Path) -> None:
    p = tmp_path / "state.bin"
    p.write_bytes(b"old")
    atomic_write_bytes(p, b"new")
    assert p.read_bytes() == b"new"


def test_atomic_write_no_tmp_leak_on_success(tmp_path: Path) -> None:
    p = tmp_path / "state.bin"
    atomic_write_bytes(p, b"hello")
    leftovers = [x for x in tmp_path.iterdir() if x.name != "state.bin"]
    assert leftovers == [], f"tmp files leaked: {leftovers}"


def test_atomic_write_preserves_original_on_simulated_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If fsync raises (simulating mid-write crash), original file is intact."""
    p = tmp_path / "state.bin"
    p.write_bytes(b"original")

    def boom(fd: int) -> None:
        raise OSError("simulated crash")

    monkeypatch.setattr(backend_module, "_fsync_directory", lambda _path: None)
    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError, match="simulated crash"):
        atomic_write_bytes(p, b"replacement")
    assert p.read_bytes() == b"original"
    leftovers = [x for x in tmp_path.iterdir() if x.name != "state.bin"]
    assert leftovers == [], f"tmp files leaked: {leftovers}"


def test_directory_fsync_propagates_real_io_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []

    monkeypatch.setattr(backend_module.os, "open", lambda *_args, **_kwargs: 123)
    monkeypatch.setattr(
        backend_module.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError(errno.EIO, "directory I/O error")),
    )
    monkeypatch.setattr(backend_module.os, "close", closed.append)

    with pytest.raises(OSError, match="directory I/O error") as raised:
        backend_module._fsync_directory(tmp_path)

    assert raised.value.errno == errno.EIO
    assert closed == [123]


def test_atomic_write_reports_post_replace_directory_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.bin"
    path.write_bytes(b"old")

    sync_calls = 0

    def fail_directory_fsync(_path: Path) -> None:
        nonlocal sync_calls
        sync_calls += 1
        if sync_calls == 2:
            raise OSError(errno.EIO, "directory I/O error")

    monkeypatch.setattr(backend_module, "_fsync_directory", fail_directory_fsync)

    with pytest.raises(OSError, match="directory I/O error"):
        atomic_write_bytes(path, b"new")

    # Directory synchronization runs after replace: failure means durability
    # is unconfirmed, not that the prior target is necessarily still present.
    assert sync_calls == 2
    assert path.read_bytes() == b"new"


def test_atomic_write_durably_creates_parent_hierarchy_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "one" / "two" / "three" / "state.bin"
    events: list[tuple[str, Path]] = []
    original_mkdir = Path.mkdir

    def tracked_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        events.append(("mkdir", path))
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", tracked_mkdir)
    monkeypatch.setattr(
        backend_module,
        "_fsync_directory",
        lambda path: events.append(("fsync", Path(path))),
    )

    atomic_write_bytes(target, b"durable")

    assert events == [
        ("fsync", tmp_path.parent),
        ("mkdir", tmp_path / "one"),
        ("fsync", tmp_path),
        ("mkdir", tmp_path / "one" / "two"),
        ("fsync", tmp_path / "one"),
        ("mkdir", tmp_path / "one" / "two" / "three"),
        ("fsync", tmp_path / "one" / "two"),
        ("fsync", tmp_path / "one" / "two" / "three"),
    ]
    assert target.read_bytes() == b"durable"


def test_durable_mkdir_syncs_containing_parent_for_preexisting_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    synced: list[Path] = []
    monkeypatch.setattr(
        backend_module,
        "_fsync_directory",
        lambda path: synced.append(Path(path)),
    )

    backend_module.durable_mkdir(existing)

    assert synced == [tmp_path]


def test_durable_mkdir_retry_resyncs_directory_left_by_failed_parent_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "retry-parent"
    synced: list[Path] = []

    def fail_once(path: Path) -> None:
        synced.append(Path(path))
        if len(synced) == 2:
            raise OSError(errno.EIO, "one-shot parent sync failure")

    monkeypatch.setattr(backend_module, "_fsync_directory", fail_once)

    with pytest.raises(OSError, match="one-shot parent sync failure"):
        backend_module.durable_mkdir(target)
    assert target.is_dir()

    backend_module.durable_mkdir(target)

    assert synced == [tmp_path.parent, tmp_path, tmp_path]


def test_durable_mkdir_propagates_parent_sync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "new-parent"
    monkeypatch.setattr(
        backend_module,
        "_fsync_directory",
        lambda _path: (_ for _ in ()).throw(OSError(errno.EIO, "parent sync failed")),
    )

    with pytest.raises(OSError, match="parent sync failed") as raised:
        backend_module.durable_mkdir(target)

    assert raised.value.errno == errno.EIO


def test_atomic_write_creates_parent_dir(tmp_path: Path) -> None:
    p = tmp_path / "nested" / "dir" / "state.bin"
    atomic_write_bytes(p, b"deep")
    assert p.read_bytes() == b"deep"


def test_atomic_write_text_is_byte_identical_across_platforms(tmp_path: Path) -> None:
    """Text keystore files must land as the exact UTF-8 bytes of the content.

    The Rust runtime parses some of these files (e.g. the hibe idpath
    history) and rejects CR, so Windows newline translation of "\\n" into
    "\\r\\n" breaks re-init after a hibe rotation.
    """
    p = tmp_path / "state.txt"
    _atomic_write_text(p, "self\npolicy-b\n")
    assert p.read_bytes() == b"self\npolicy-b\n"
