"""On-disk layout policy for btn keystore: active state, retired states,
atomic promote dance, legacy-shape compatibility."""

from __future__ import annotations

from pathlib import Path

import pytest

from tn.btn_keystore import BtnKeystore, KitFiles


def test_write_and_load_active(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"STATE", self_kit=b"KIT")
    loaded = ks.load_active("default")
    assert loaded.state_bytes == b"STATE"
    assert loaded.self_kit == b"KIT"


def test_load_active_missing_raises(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    with pytest.raises(FileNotFoundError):
        ks.load_active("default")


def test_load_retired_states_returns_empty_when_none(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"a", self_kit=b"k")
    assert ks.load_retired_states("default") == {}


def test_write_and_load_retired_pair(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"ACTIVE", self_kit=b"AKIT")
    ks.write_retired_pair("default", epoch=0, state_bytes=b"E0_S", self_kit=b"E0_K")
    ks.write_retired_pair("default", epoch=1, state_bytes=b"E1_S", self_kit=b"E1_K")

    retired = ks.load_retired_states("default")
    assert sorted(retired.keys()) == [0, 1]
    assert retired[0].state_bytes == b"E0_S"
    assert retired[0].self_kit == b"E0_K"
    assert retired[1].state_bytes == b"E1_S"
    assert retired[1].self_kit == b"E1_K"


def test_load_retired_states_skips_half_pairs(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"a", self_kit=b"k")
    # Lay down a state file with no matching kit (orphaned).
    (tmp_path / "default.btn.state.retired.5").write_bytes(b"ORPHAN")
    # Lay down a complete pair at epoch 3.
    (tmp_path / "default.btn.state.retired.3").write_bytes(b"S3")
    (tmp_path / "default.btn.mykit.retired.3").write_bytes(b"K3")

    retired = ks.load_retired_states("default")
    assert list(retired.keys()) == [3]
    assert retired[3].state_bytes == b"S3"


def test_load_retired_states_skips_non_numeric_suffix(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"a", self_kit=b"k")
    # Garbage entry — operator hand-edited the keystore.
    (tmp_path / "default.btn.state.retired.junk").write_bytes(b"x")
    (tmp_path / "default.btn.mykit.retired.junk").write_bytes(b"x")

    assert ks.load_retired_states("default") == {}


def test_promote_pending_swaps_pending_into_active(tmp_path: Path):
    """Happy path: write_retired_pair has already archived the prior
    generation as the canonical RetiredPublisherState; promote_pending
    just removes the now-redundant active files and renames pending →
    active."""
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"E0_STATE", self_kit=b"E0_KIT")
    ks.write_pending("default", state_bytes=b"E1_STATE", self_kit=b"E1_KIT")
    # Archive the prior generation FIRST (this is what cipher.rotate()
    # does — writes RetiredPublisherState wire bytes, distinct from the
    # raw PublisherState bytes that were in `default.btn.state`).
    ks.write_retired_pair(
        "default", epoch=0,
        state_bytes=b"E0_RETIRED_BYTES", self_kit=b"E0_KIT",
    )

    ks.promote_pending("default", retiring_epoch=0)

    assert (tmp_path / "default.btn.state").read_bytes() == b"E1_STATE"
    assert (tmp_path / "default.btn.mykit").read_bytes() == b"E1_KIT"
    # Retired archive is intact (NOT overwritten by promote_pending).
    assert (tmp_path / "default.btn.state.retired.0").read_bytes() == b"E0_RETIRED_BYTES"
    assert (tmp_path / "default.btn.mykit.retired.0").read_bytes() == b"E0_KIT"
    # Pending files cleared by the rename.
    assert not (tmp_path / "default.btn.state.pending").exists()
    assert not (tmp_path / "default.btn.mykit.pending").exists()


def test_promote_pending_refuses_missing_retired_archive(tmp_path: Path):
    """Forward secrecy guard: if write_retired_pair didn't run, the
    prior master_seed is about to be lost when promote_pending replaces
    the active state. Refuse rather than silently delete."""
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"E0", self_kit=b"E0K")
    ks.write_pending("default", state_bytes=b"E1", self_kit=b"E1K")
    # No write_retired_pair() called.

    with pytest.raises(FileNotFoundError):
        ks.promote_pending("default", retiring_epoch=0)


def test_promote_pending_refuses_missing_pending(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"a", self_kit=b"k")
    # write_retired_pair did run, but no write_pending().
    ks.write_retired_pair(
        "default", epoch=0, state_bytes=b"r", self_kit=b"r",
    )
    with pytest.raises(FileNotFoundError):
        ks.promote_pending("default", retiring_epoch=0)


def test_cleanup_orphan_pending_removes_pending(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"a", self_kit=b"k")
    ks.write_pending("default", state_bytes=b"orphan", self_kit=b"orphan")
    assert ks.cleanup_orphan_pending("default") is True
    assert not (tmp_path / "default.btn.state.pending").exists()
    assert not (tmp_path / "default.btn.mykit.pending").exists()
    # Active untouched.
    assert (tmp_path / "default.btn.state").read_bytes() == b"a"


def test_cleanup_orphan_pending_noop_when_clean(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"a", self_kit=b"k")
    assert ks.cleanup_orphan_pending("default") is False


def test_load_legacy_revoked(tmp_path: Path):
    ks = BtnKeystore(tmp_path)
    ks.write_active("default", state_bytes=b"a", self_kit=b"k")
    (tmp_path / "default.btn.state.revoked.1700000000").write_bytes(b"LEGACY_STATE")
    (tmp_path / "default.btn.mykit.revoked.1700000000").write_bytes(b"LEGACY_KIT")

    legacy = ks.load_legacy_revoked("default")
    assert len(legacy) == 1
    assert legacy[0].state_bytes == b"LEGACY_STATE"
    assert legacy[0].self_kit == b"LEGACY_KIT"
