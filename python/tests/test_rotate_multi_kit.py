"""Rotation preserves old kits; tn.read spans the boundary automatically.

Before this fix, `tn.admin.rotate("default")` overwrote `<group>.btn.state` and
`<group>.btn.mykit` in place, making pre-rotation entries permanently
unreadable. Now (0.4.3a1):

    - rotate archives old state+mykit as `.btn.state.retired.<N>` and
      `.btn.mykit.retired.<N>` where N is the cipher epoch of the
      retired material (1-indexed, monotonic).
    - Runtime::init globs all `.btn.mykit*` files and loads them into
      one BtnReaderCipher that tries each kit until one decrypts.
    - a single `tn.read()` returns pre- AND post-rotation entries.
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn.absorb import _absorb_group_keys
from tn.btn_keystore import BtnKeystore
from tn.config import load_or_create
from tn.tnpkg import TnpkgManifest


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_rotate_preserves_old_kits(tmp_path):
    """After rotate, old .btn.state and .btn.mykit are preserved as .retired.<N>."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("pre.rotate", n=1)
    tn.flush_and_close()

    keystore = tmp_path / ".tn/tn/keys"
    assert (keystore / "default.btn.state").exists()
    assert (keystore / "default.btn.mykit").exists()

    # Rotate — should archive old state+mykit rather than delete.
    tn.init(yaml)
    tn.admin.rotate("default")
    tn.flush_and_close()

    # Current files still there with fresh content.
    assert (keystore / "default.btn.state").exists()
    assert (keystore / "default.btn.mykit").exists()
    # Old files preserved under .retired.<N> suffixes (N = retired epoch).
    retired_states = list(keystore.glob("default.btn.state.retired.*"))
    retired_kits = list(keystore.glob("default.btn.mykit.retired.*"))
    assert len(retired_states) == 1, f"expected 1 retired state, got {retired_states}"
    assert len(retired_kits) == 1, f"expected 1 retired kit, got {retired_kits}"


def test_read_spans_rotation_boundary(tmp_path):
    """tn.read() returns pre-rotation and post-rotation entries in one call."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("order.created", order_id="A100", stage="pre")
    tn.info("order.created", order_id="A101", stage="pre")
    tn.flush_and_close()

    # Rotate.
    tn.init(yaml)
    tn.admin.rotate("default")
    # Emit two more events under the new keys.
    tn.info("order.created", order_id="A102", stage="post")
    tn.info("order.created", order_id="A103", stage="post")
    tn.flush_and_close()

    # Read everything — pre- AND post-rotation entries should decrypt.
    tn.init(yaml)
    entries = list(tn.read(all_runs=True))  # tn.rotation.completed is itself in the log
    # We expect at least 4 order.created entries plus 1 tn.rotation.completed.
    order_entries = [e for e in entries if e.event_type == "order.created"]
    assert len(order_entries) == 4, (
        f"expected 4 order.created entries, got {len(order_entries)}:\n"
        + "\n".join(f"  {e.event_type} seq={e.sequence} fields={e.fields}" for e in entries)
    )

    # Sort by sequence; verify we got the stages right.
    order_entries.sort(key=lambda e: e.sequence)
    assert order_entries[0].fields["order_id"] == "A100"
    assert order_entries[0].fields["stage"] == "pre"
    assert order_entries[1].fields["order_id"] == "A101"
    assert order_entries[1].fields["stage"] == "pre"
    assert order_entries[2].fields["order_id"] == "A102"
    assert order_entries[2].fields["stage"] == "post"
    assert order_entries[3].fields["order_id"] == "A103"
    assert order_entries[3].fields["stage"] == "post"


def test_multiple_rotations_accumulate_preserved_kits(tmp_path):
    """Every rotation stacks another .retired.<N> kit; reads still span all."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("era.one", n=1)
    tn.flush_and_close()

    # Two rotations in sequence (epoch index is monotonic; no need to sleep).
    tn.init(yaml)
    tn.admin.rotate("default")
    tn.info("era.two", n=2)
    tn.flush_and_close()

    tn.init(yaml)
    tn.admin.rotate("default")
    tn.info("era.three", n=3)
    tn.flush_and_close()

    keystore = tmp_path / ".tn/tn/keys"
    retired_kits = sorted(keystore.glob("default.btn.mykit.retired.*"))
    assert len(retired_kits) == 2, f"expected 2 retired kits, got {retired_kits}"

    # Read everything — all three eras' data entries decrypt.
    tn.init(yaml)
    entries = list(tn.read(all_runs=True))
    eras_seen = {e.event_type for e in entries if e.event_type.startswith("era.")}
    assert eras_seen == {"era.one", "era.two", "era.three"}, (
        f"expected all three eras readable, saw {eras_seen}"
    )


def test_rotate_crash_midpromote_leaves_publisher_writable(tmp_path, monkeypatch):
    """A rotation that crashes DURING the promote dance (active files removed,
    pending not yet renamed) must recover into a WRITABLE publisher on the next
    init - not a stranded one.

    Before the fix, the next init's cleanup deleted the surviving pending pair,
    so the publisher lost its active state (the .retired.<N> archive is a
    read-only snapshot) and the next emit raised NotAPublisherError.
    """
    yaml = tmp_path / "tn.yaml"
    keystore = tmp_path / ".tn/tn/keys"

    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("order.created", order_id="A1")
    tn.flush_and_close()

    # Patch promote_pending to run its REAL unlink half, then "crash" before
    # the pending->active rename - the exact documented crash window.
    real_state_path = BtnKeystore._state_path
    real_kit_path = BtnKeystore._kit_path

    def crashing_promote(self, group, *, retiring_epoch):
        real_state_path(self, group).unlink(missing_ok=True)
        real_kit_path(self, group).unlink(missing_ok=True)
        raise RuntimeError("simulated crash mid-promote")

    monkeypatch.setattr(BtnKeystore, "promote_pending", crashing_promote)

    tn.init(yaml)
    with pytest.raises(RuntimeError, match="simulated crash"):
        tn.admin.rotate("default")
    tn.flush_and_close()

    # Crash state on disk: active gone, pending + retired present.
    assert not (keystore / "default.btn.state").exists()
    assert (keystore / "default.btn.state.pending").exists()
    monkeypatch.undo()

    # Next init must roll the pending pair forward to active, restoring a
    # writable publisher. This emit MUST NOT raise NotAPublisherError.
    tn.init(yaml)
    tn.info("order.created", order_id="A2")
    tn.flush_and_close()

    # The recovered active pair is on disk; the post-recovery write landed.
    assert (keystore / "default.btn.state").exists()
    assert not (keystore / "default.btn.state.pending").exists()
    tn.init(yaml)
    ids = {
        e.fields.get("order_id")
        for e in tn.read(all_runs=True)
        if e.event_type == "order.created"
    }
    tn.flush_and_close()
    assert "A2" in ids, f"post-recovery write should be readable; saw {ids}"


def test_prior_member_keeps_old_access_through_a_synced_rotation(tmp_path):
    """A PRIOR group member must not lose pre-rotation read access when it
    catches up to a rotation through a group_keys SYNC (vs rotating itself).

    _absorb_group_keys must archive the superseded epoch as a LOADABLE
    ``.retired.<N>``, not a ``.previous.<ts>`` the cipher ignores - otherwise
    the member silently loses the ability to read everything from before the
    rotation it received. ("Invited to the meeting" forward-only is a separate
    case; this is a member who already had access.)
    """
    yaml = tmp_path / "tn.yaml"
    keystore = tmp_path / ".tn/tn/keys"

    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("order.created", order_id="OLD")
    did = tn.current_config().device.device_identity
    # The epoch-1 reader material (the prior-member view).
    s1 = (keystore / "default.btn.state").read_bytes()
    k1 = (keystore / "default.btn.mykit").read_bytes()
    # Rotate to mint epoch-2 material (what a peer device would publish).
    tn.admin.rotate("default")
    s2 = (keystore / "default.btn.state").read_bytes()
    k2 = (keystore / "default.btn.mykit").read_bytes()
    tn.flush_and_close()

    # Reset the keystore to a prior member still at epoch 1: active = epoch 1,
    # and NO local .retired (they never rotated themselves - they only RECEIVE
    # the rotation, below, via the sync).
    (keystore / "default.btn.state").write_bytes(s1)
    (keystore / "default.btn.mykit").write_bytes(k1)
    for r in keystore.glob("default.btn.*.retired.*"):
        r.unlink()

    # Baseline: as an epoch-1 member, the old message reads.
    tn.init(yaml)
    base = [e for e in tn.read(all_runs=True) if e.event_type == "order.created"]
    assert any(e.fields.get("order_id") == "OLD" for e in base), (
        "baseline broken: a prior member should read its own old message"
    )
    tn.flush_and_close()

    # RECEIVE the rotation via a group_keys absorb (the epoch-2 state + kit).
    cfg = load_or_create(yaml, cipher=_workflow_cipher("btn"))
    _absorb_group_keys(
        cfg,
        TnpkgManifest(
            kind="group_keys",
            publisher_identity=did,
            recipient_identity=did,  # self-addressed (required by group_keys)
            ceremony_id="sync",
            as_of="2026-06-10T00:00:00Z",
        ),
        {
            "body/keys/default.btn.state": s2,
            "body/keys/default.btn.mykit": k2,
        },
    )

    # The rule: the prior member STILL reads the pre-rotation message.
    tn.init(yaml)
    after = [e for e in tn.read(all_runs=True) if e.event_type == "order.created"]
    assert any(e.fields.get("order_id") == "OLD" for e in after), (
        "prior member LOST pre-rotation read access after a synced rotation: "
        "the superseded epoch was stranded in .previous instead of .retired"
    )
