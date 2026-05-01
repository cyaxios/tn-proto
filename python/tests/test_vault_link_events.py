"""tn.vault.link / tn.vault.unlink emit the corresponding admin events."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_vault_link_emits_event(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.vault.link("did:web:tnproto.org", "proj_test")
    tn.flush_and_close()

    tn.init(yaml)
    events = [e for e in tn.read() if e["event_type"] == "tn.vault.linked"]
    assert len(events) == 1, f"expected 1 link event, got {len(events)}"
    e = events[0]
    assert e["vault_did"] == "did:web:tnproto.org"
    assert e["project_id"] == "proj_test"
    assert e["linked_at"]  # non-empty ISO 8601


def test_vault_unlink_emits_event_with_reason(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.vault.link("did:web:tnproto.org", "proj_test")
    tn.vault.unlink("did:web:tnproto.org", "proj_test", reason="user_request")
    tn.flush_and_close()

    tn.init(yaml)
    events = [e for e in tn.read() if e["event_type"] == "tn.vault.unlinked"]
    assert len(events) == 1
    assert events[0]["reason"] == "user_request"


def test_vault_unlink_without_reason(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.vault.link("did:web:tnproto.org", "proj_test")
    tn.vault.unlink("did:web:tnproto.org", "proj_test")  # reason=None
    tn.flush_and_close()

    tn.init(yaml)
    events = [e for e in tn.read() if e["event_type"] == "tn.vault.unlinked"]
    assert len(events) == 1
    assert events[0].get("reason") is None


def test_vault_link_is_idempotent(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.vault.link("did:web:tnproto.org", "proj_test")
    tn.vault.link("did:web:tnproto.org", "proj_test")  # duplicate
    tn.flush_and_close()

    tn.init(yaml)
    events = [e for e in tn.read() if e["event_type"] == "tn.vault.linked"]
    assert len(events) == 1, f"vault_link should be idempotent; got {len(events)} events"


def test_vault_link_to_different_project_emits_again(tmp_path):
    """Changing either vault_did or project_id is a new link."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.vault.link("did:web:tnproto.org", "proj_a")
    tn.vault.link("did:web:tnproto.org", "proj_b")  # different project
    tn.flush_and_close()

    tn.init(yaml)
    events = [e for e in tn.read() if e["event_type"] == "tn.vault.linked"]
    assert len(events) == 2


def test_vault_link_after_unlink_emits_again(tmp_path):
    """Re-linking after an unlink is a new event."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.vault.link("did:web:tnproto.org", "proj_test")
    tn.vault.unlink("did:web:tnproto.org", "proj_test", reason="temp")
    tn.vault.link("did:web:tnproto.org", "proj_test")  # re-link
    tn.flush_and_close()

    tn.init(yaml)
    events = [e for e in tn.read() if e["event_type"] == "tn.vault.linked"]
    assert len(events) == 2
