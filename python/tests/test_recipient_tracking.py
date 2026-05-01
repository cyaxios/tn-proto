"""Recipient tracking via attested events.

Every tn.admin_add_recipient call (with recipient_did) writes a
`tn.recipient.added` event. Every tn.admin_revoke_recipient call writes
a `tn.recipient.revoked` event. Both are signed, chained, verified.

`tn.admin.recipients(group)` replays the log and returns the current recipient
map. No sidecar state file; the attested log is the source of truth.
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


def test_add_recipient_with_did_emits_attested_event(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    leaf = tn.admin.add_recipient("default", recipient_did="did:key:zFrank", out_path=str(tmp_path / "frank.btn.mykit")).leaf_index
    tn.flush_and_close()

    tn.init(yaml)
    added = [e for e in tn.read() if e["event_type"] == "tn.recipient.added"]
    assert len(added) == 1, f"expected one recipient.added event, got {len(added)}"
    assert added[0]["group"] == "default"
    assert added[0]["leaf_index"] == leaf
    assert added[0]["recipient_did"] == "did:key:zFrank"
    assert added[0]["kit_sha256"].startswith("sha256:")


def test_add_recipient_without_did_still_emits_event_without_did_field(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.admin.add_recipient("default", out_path=str(tmp_path / "anon.btn.mykit"))
    tn.flush_and_close()

    tn.init(yaml)
    added = [e for e in tn.read() if e["event_type"] == "tn.recipient.added"]
    assert len(added) == 1
    # DID field is absent (or None) when not provided.
    assert added[0].get("recipient_did") is None


def test_recipients_returns_active_only_by_default(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    leaf_frank = tn.admin.add_recipient("default", recipient_did="did:key:zFrank", out_path=str(tmp_path / "frank.btn.mykit")).leaf_index
    leaf_carol = tn.admin.add_recipient("default", recipient_did="did:key:zCarol", out_path=str(tmp_path / "carol.btn.mykit")).leaf_index
    tn.admin.revoke_recipient("default", leaf_index=leaf_frank)
    tn.flush_and_close()

    tn.init(yaml)
    active = tn.admin.recipients("default")
    # Only Carol should be active.
    assert len(active) == 1, f"expected 1 active, got {active}"
    assert active[0]["leaf_index"] == leaf_carol
    assert active[0]["recipient_did"] == "did:key:zCarol"
    assert active[0]["revoked"] is False


def test_recipients_include_revoked_returns_full_history(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    leaf_frank = tn.admin.add_recipient("default", recipient_did="did:key:zFrank", out_path=str(tmp_path / "frank.btn.mykit")).leaf_index
    leaf_carol = tn.admin.add_recipient("default", recipient_did="did:key:zCarol", out_path=str(tmp_path / "carol.btn.mykit")).leaf_index
    tn.admin.revoke_recipient("default", leaf_index=leaf_frank)
    tn.flush_and_close()

    tn.init(yaml)
    all_recips = tn.admin.recipients("default", include_revoked=True)
    assert len(all_recips) == 2
    # Both returned; revoked flag distinguishes.
    by_leaf = {r["leaf_index"]: r for r in all_recips}
    assert by_leaf[leaf_frank]["revoked"] is True
    assert by_leaf[leaf_frank]["revoked_at"] is not None
    assert by_leaf[leaf_carol]["revoked"] is False


def test_recipients_scopes_to_named_group(tmp_path):
    """A recipient.added event for group 'default' does not leak into group 'other'."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "a.btn.mykit"))
    tn.flush_and_close()

    tn.init(yaml)
    # Query for a group that doesn't exist: empty list, no exception.
    assert tn.admin.recipients("nonexistent") == []
    # Query for 'default' returns the one recipient.
    assert len(tn.admin.recipients("default")) == 1
