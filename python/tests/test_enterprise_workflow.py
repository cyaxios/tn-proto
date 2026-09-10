"""Consumer regressions from the enterprise-pattern implementations."""
import json

import pytest
import tn

POLICY = """## account
### instruction
Calculate totals.
### use_for
Analysis.
### do_not_use_for
Individual disclosure.
### consequences
Review.
### on_violation_or_error
Refuse.
"""


def create(session):
    return session.create_obj_with_groups(
        {"default": {"balance": 1200}, "private": {"owner": "Ada"}},
        session.policy("account"), object_type="account",
    )


def test_complete_origin_one_snapshot_and_independent_sessions():
    with tn.Session(POLICY, groups=["default", "private"]) as first, \
            tn.Session(POLICY, groups=["default", "private"]) as second:
        obj = create(first)
        assert len(obj.history) == 1
        received = first.receive(obj.snapshot, purpose="analysis", groups=["default", "private"],
                                 decide=lambda c: c.writer == first.did)
        assert received.data["balance"] == 1200
        assert received.groups["private"]["owner"] == "Ada"
        assert received.governance.sources == []
        assert not received.has_unreleased_changes
        with pytest.raises(tn.governed.GovernedError):
            second.receive(obj.snapshot, purpose="analysis", decide=lambda c: True)
        first.close()
        assert create(second).snapshot.writer == second.did


def test_pending_edits_survive_refusal_and_reset_after_release():
    with tn.Session(POLICY, groups=["default", "private"]) as session:
        obj = create(session)
        initial = bytes(obj.snapshot)
        assert not obj.has_unreleased_changes
        obj.data["balance"] = 400
        assert obj.has_unreleased_changes and obj.state.has_unreleased_changes
        seen = []

        def refuse(context):
            seen.append(context.data.has_unreleased_changes)
            return False

        with pytest.raises(tn.governed.UseDenied):
            obj.release(to="public", purpose="analysis", decide=refuse)
        assert seen == [True]
        assert bytes(obj.snapshot) == initial
        assert obj.has_unreleased_changes
        result = obj.release(to="internal", purpose="analysis", decide=lambda c: c.data.has_unreleased_changes)
        assert not obj.has_unreleased_changes
        assert bytes(obj.history[0]) == initial
        assert bytes(obj.snapshot) == bytes(result)


def test_group_validation_precedes_creation_register(monkeypatch, tmp_path):
    register = tmp_path / "created.jsonl"
    monkeypatch.setenv("TN_OBJECT_CREATION_REGISTER", str(register))
    with tn.Session(POLICY, groups=["default", "private"]) as session:
        policy = session.policy("account")
        for groups in ({}, {"default": 7}, {"tn.agents": {}}, {"unknown": {}}):
            with pytest.raises((tn.governed.GovernedError, ValueError, TypeError)):
                session.create_obj_with_groups(groups, policy, object_type="account")
            assert not register.exists()
        with pytest.raises(ValueError):
            session.create_obj_with_groups({"private": {}}, policy, object_type="account")
        obj = create(session)
        entries = [json.loads(line) for line in register.read_text().splitlines()]
        assert len(entries) == 1
        assert obj.snapshot.id in register.read_text()
        assert not obj.has_unreleased_changes


def test_named_primary_view_and_accepted_source_policy():
    with tn.Session(POLICY, groups=["data", "private"]) as session, tn.Session(POLICY) as other:
        obj = session.create_obj_with_groups(
            {"data": {"balance": 8}, "private": {"owner": "Ada"}},
            session.policy("account"), object_type="account", primary_group="data",
        )
        assert obj.data["balance"] == 8
        source = obj.sources[0]
        assert source.references_with_policy(obj.snapshot, obj.governance)
        assert not source.references_with_policy(obj.snapshot, other.policy("account"))


def test_projection_and_callback_snapshot_show_hidden_groups():
    with tn.Session(POLICY, groups=["default", "private"]) as session:
        source = create(session).snapshot
        data = session.receive(source, purpose="analysis", decide=lambda c: c.writer == session.did)
        before = data.state
        assert before.hidden_groups == ["private"]
        with pytest.raises(ValueError, match="no group"):
            data.retain_groups(["default", "missing"])
        assert not data.has_unreleased_changes
        data.retain_groups(["default"])
        assert before.hidden_groups == ["private"]
        assert data.hidden_groups == []
        result = data.release(to="internal", purpose="analysis",
                              decide=lambda c: c.data.hidden_groups == [] and set(c.data.groups) == {"default"})
        assert set(result.group_names) == {"default", "tn.agents"}
        assert bytes(data.history[0]) == bytes(source)
