"""tn.admin through the Rust path for btn ceremonies (Task 39).

Tests that the module-level admin helpers (admin_add_recipient,
admin_revoke_recipient, admin_revoked_count) wire through the Rust runtime
correctly, and that a revoked reader kit cannot decrypt post-revocation
envelopes.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]  # venv-installed test dep

# Ensure the tn package is importable when running from any directory.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


def _rebuild_rt(tmp_path: Path) -> None:  # referenced by fixtures when needed
    """Helper: flush_and_close and re-init from the same yaml."""
    tn.flush_and_close()
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")


@pytest.fixture(autouse=True)
def _clean_tn(tmp_path):  # pyright: ignore[reportUnusedFunction]  # autouse fixture
    """Ensure tn is closed after each test so module state is reset."""
    _ = tmp_path  # parameter is discovered by pytest via name; acknowledge
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_using_rust_is_true_for_btn_ceremony(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    assert tn.using_rust() is True, "btn ceremony must route through Rust"


def test_admin_add_recipient_returns_leaf_and_writes_file(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    assert tn.using_rust() is True

    kit_path = tmp_path / "reader_a.btn.mykit"
    leaf = tn.admin.add_recipient("default", out_path=str(kit_path)).leaf_index
    assert isinstance(leaf, int), f"leaf must be int, got {type(leaf)}"
    assert kit_path.exists(), "kit file must be written to disk"
    assert kit_path.stat().st_size > 0, "kit file must be non-empty"


def test_admin_revoke_recipient_increments_revoked_count(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")

    kit_path = tmp_path / "reader_b.btn.mykit"
    leaf = tn.admin.add_recipient("default", out_path=str(kit_path)).leaf_index
    assert tn.admin.revoked_count("default") == 0

    tn.admin.revoke_recipient("default", leaf_index=leaf)
    assert tn.admin.revoked_count("default") == 1

    # Idempotent: revoke again should stay at 1.
    tn.admin.revoke_recipient("default", leaf_index=leaf)
    assert tn.admin.revoked_count("default") == 1


def test_revoke_then_decrypt_fails_for_revoked_reader(tmp_path):
    """The full revocation story: emit before and after revocation, verify
    that the revoked reader cannot decrypt post-revocation envelopes."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    assert tn.using_rust() is True

    # Baseline emit — before any external recipient.
    tn.info("order.created", amount=100)

    # Add a recipient, then revoke it.
    kit_path = tmp_path / "reader_a.btn.mykit"
    leaf_a = tn.admin.add_recipient("default", out_path=str(kit_path)).leaf_index
    assert kit_path.exists()

    tn.admin.revoke_recipient("default", leaf_index=leaf_a)
    assert tn.admin.revoked_count("default") == 1

    # Post-revoke emit.
    tn.info("order.created", amount=200)

    tn.flush_and_close()

    # --- Verify log structure ---
    # Log now contains: order.created (baseline), tn.recipient.added (mint),
    # tn.recipient.revoked (revoke), order.created (post-revoke).
    log_file = yaml.parent / ".tn/tn/logs" / "tn.ndjson"
    lines = log_file.read_text(encoding="utf-8").splitlines()
    parsed = [json.loads(ln) for ln in lines]
    orders = [env for env in parsed if env["event_type"] == "order.created"]
    assert len(orders) == 2, f"expected 2 order.created entries, got {len(orders)}"

    env_after = orders[1]  # the post-revoke order.created

    # Reader A (revoked) cannot decrypt the post-revoke envelope.
    import tn_btn  # PyO3 extension built via maturin develop

    ct_b64 = env_after["default"]["ciphertext"]
    ct_bytes = base64.standard_b64decode(ct_b64)
    kit_bytes = kit_path.read_bytes()

    try:
        pt = tn_btn.decrypt(kit_bytes, ct_bytes)
        raise AssertionError(f"revoked reader should not decrypt, got {pt!r}")
    except tn_btn.NotEntitled:
        pass  # expected
    except tn_btn.BtnRuntimeError:
        pass  # also acceptable (e.g. cover empty = NotEntitled variant)


def test_add_recipient_state_survives_runtime_reload(tmp_path):
    """State written by add_recipient_btn must be loadable by a fresh Runtime."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")

    kit_path1 = tmp_path / "reader1.btn.mykit"
    tn.admin.add_recipient("default", out_path=str(kit_path1))
    assert kit_path1.exists()

    tn.flush_and_close()

    # Reload.
    tn.init(yaml, cipher="btn")
    assert tn.using_rust() is True

    # Mint a second kit from the reloaded runtime — must work.
    kit_path2 = tmp_path / "reader2.btn.mykit"
    tn.admin.add_recipient("default", out_path=str(kit_path2))
    assert kit_path2.exists()
