"""Rotation preserves old kits; tn.read spans the boundary automatically.

Before this fix, `tn.admin.rotate("default")` overwrote `<group>.btn.state` and
`<group>.btn.mykit` in place, making pre-rotation entries permanently
unreadable. Now:

    - rotate renames old files to `.btn.state.revoked.<ts>` and
      `.btn.mykit.revoked.<ts>`
    - Runtime::init globs all `.btn.mykit*` files and loads them into
      one BtnReaderCipher that tries each kit until one decrypts
    - a single `tn.read()` returns pre- AND post-rotation entries
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_rotate_preserves_old_kits(tmp_path):
    """After rotate, old .btn.state and .btn.mykit are preserved as .revoked.<ts>."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("pre.rotate", n=1)
    tn.flush_and_close()

    keystore = tmp_path / ".tn/tn/keys"
    assert (keystore / "default.btn.state").exists()
    assert (keystore / "default.btn.mykit").exists()

    # Rotate — should rename old state+mykit rather than delete.
    tn.init(yaml)
    tn.admin.rotate("default")
    tn.flush_and_close()

    # Current files still there with fresh content.
    assert (keystore / "default.btn.state").exists()
    assert (keystore / "default.btn.mykit").exists()
    # Old files preserved under .revoked.<ts> suffixes.
    revoked_states = list(keystore.glob("default.btn.state.revoked.*"))
    revoked_kits = list(keystore.glob("default.btn.mykit.revoked.*"))
    assert len(revoked_states) == 1, f"expected 1 revoked state, got {revoked_states}"
    assert len(revoked_kits) == 1, f"expected 1 revoked kit, got {revoked_kits}"


def test_read_spans_rotation_boundary(tmp_path):
    """tn.read() returns pre-rotation and post-rotation entries in one call."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
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
    entries = list(tn.read())  # tn.rotation.completed is itself in the log
    # We expect at least 4 order.created entries plus 1 tn.rotation.completed.
    order_entries = [e for e in entries if e["event_type"] == "order.created"]
    assert len(order_entries) == 4, (
        f"expected 4 order.created entries, got {len(order_entries)}:\n"
        + "\n".join(f"  {e['event_type']} seq={e['sequence']} fields={e}" for e in entries)
    )

    # Sort by sequence; verify we got the stages right.
    order_entries.sort(key=lambda e: e["sequence"])
    assert order_entries[0]["order_id"] == "A100"
    assert order_entries[0]["stage"] == "pre"
    assert order_entries[1]["order_id"] == "A101"
    assert order_entries[1]["stage"] == "pre"
    assert order_entries[2]["order_id"] == "A102"
    assert order_entries[2]["stage"] == "post"
    assert order_entries[3]["order_id"] == "A103"
    assert order_entries[3]["stage"] == "post"


def test_multiple_rotations_accumulate_preserved_kits(tmp_path):
    """Every rotation stacks another .revoked.<ts> kit; reads still span all."""
    import time as _time

    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("era.one", n=1)
    tn.flush_and_close()

    # Two rotations in sequence (with small sleep so timestamps differ).
    tn.init(yaml)
    tn.admin.rotate("default")
    tn.info("era.two", n=2)
    tn.flush_and_close()
    _time.sleep(1.1)

    tn.init(yaml)
    tn.admin.rotate("default")
    tn.info("era.three", n=3)
    tn.flush_and_close()

    keystore = tmp_path / ".tn/tn/keys"
    revoked_kits = sorted(keystore.glob("default.btn.mykit.revoked.*"))
    assert len(revoked_kits) == 2, f"expected 2 revoked kits, got {revoked_kits}"

    # Read everything — all three eras' data entries decrypt.
    tn.init(yaml)
    entries = list(tn.read())
    eras_seen = {e["event_type"] for e in entries if e["event_type"].startswith("era.")}
    assert eras_seen == {"era.one", "era.two", "era.three"}, (
        f"expected all three eras readable, saw {eras_seen}"
    )
