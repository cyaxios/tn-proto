"""Atomic write invariants — tear-resistance for keystore state files."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

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

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError, match="simulated crash"):
        atomic_write_bytes(p, b"replacement")
    assert p.read_bytes() == b"original"
    leftovers = [x for x in tmp_path.iterdir() if x.name != "state.bin"]
    assert leftovers == [], f"tmp files leaked: {leftovers}"


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
