"""BtnGroupCipher uses atomic_write_bytes for state durability."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tn.cipher import BtnGroupCipher


def test_create_persists_state_atomically(tmp_path: Path) -> None:
    BtnGroupCipher.create(tmp_path, "alpha")
    state_path = tmp_path / "alpha.btn.state"
    assert state_path.exists()
    assert state_path.read_bytes() != b""
    leftovers = [
        x
        for x in tmp_path.iterdir()
        if x.name.startswith(".alpha.btn.state.tmp")
        or x.name.startswith(".alpha.btn.mykit.tmp")
    ]
    assert leftovers == [], f"tmp files leaked: {leftovers}"


def test_persist_state_atomic_no_partial_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If persist_state fails mid-write, original state is preserved."""
    cipher = BtnGroupCipher.create(tmp_path, "alpha")
    state_path = tmp_path / "alpha.btn.state"
    original = state_path.read_bytes()

    def boom(fd: int) -> None:
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError, match="simulated fsync failure"):
        cipher._persist_state()  # noqa: SLF001 — testing durability boundary

    monkeypatch.undo()
    assert state_path.read_bytes() == original
    leftovers = [
        x
        for x in tmp_path.iterdir()
        if x.name.startswith(".alpha.btn.state.tmp")
    ]
    assert leftovers == [], f"tmp files leaked: {leftovers}"
