"""Atomic write invariants — tear-resistance for keystore state files.

See docs/superpowers/specs/2026-05-12-runtime-correctness-design.md
(Cluster A1) for design rationale.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tn._keystore_backend import atomic_write_bytes


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
