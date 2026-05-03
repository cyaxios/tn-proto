"""tn.admin.state() aggregates all catalog kinds from the local log."""

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


def test_admin_state_fresh_ceremony_has_ceremony_and_no_recipients(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    tn.init(yaml)
    s = tn.admin.state()
    assert s["ceremony"] is not None
    assert s["ceremony"]["cipher"] == "btn"
    assert s["ceremony"]["device_did"].startswith("did:")
    assert s["recipients"] == []
    assert s["rotations"] == []
    assert s["vault_links"] == []


def test_admin_state_includes_recipients(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.admin.add_recipient("default", recipient_did="did:key:zFrank", out_path=str(tmp_path / "frank.btn.mykit"))
    tn.flush_and_close()

    tn.init(yaml)
    s = tn.admin.state()
    assert len(s["recipients"]) == 1
    r = s["recipients"][0]
    assert r["recipient_did"] == "did:key:zFrank"
    assert r["active_status"] == "active"


def test_admin_state_marks_retired_after_rotation(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.admin.add_recipient("default", recipient_did="did:key:zFrank", out_path=str(tmp_path / "frank.btn.mykit"))
    tn.admin.rotate("default")
    tn.flush_and_close()

    tn.init(yaml)
    s = tn.admin.state()
    assert len(s["rotations"]) == 1
    frank = next(r for r in s["recipients"] if r["recipient_did"] == "did:key:zFrank")
    assert frank["active_status"] == "retired"
    assert frank["retired_at"] is not None


def test_admin_state_records_vault_link_and_unlink(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.vault.link("did:web:tn-proto.org", "proj_test")
    tn.vault.unlink("did:web:tn-proto.org", "proj_test", reason="user_request")
    tn.flush_and_close()

    tn.init(yaml)
    s = tn.admin.state()
    assert len(s["vault_links"]) == 1
    link = s["vault_links"][0]
    assert link["vault_did"] == "did:web:tn-proto.org"
    assert link["unlinked_at"] is not None


def test_admin_state_group_filter(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.admin.add_recipient("default", recipient_did="did:key:zFrank", out_path=str(tmp_path / "frank.btn.mykit"))
    tn.flush_and_close()

    tn.init(yaml)
    # Nonexistent group: empty lists (ceremony still present).
    s = tn.admin.state(group="nonexistent")
    assert s["ceremony"] is not None
    assert s["recipients"] == []
    # Real group: has recipient.
    s = tn.admin.state(group="default")
    assert len(s["recipients"]) == 1
