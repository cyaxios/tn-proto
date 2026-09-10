"""Application workflows use mutable data while Rust retains governed history."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
import tn

POLICY = """---
version: 1
schema: tn-agents-policy@v1
---
## finance.account
### instruction
Prepare aggregate analysis.
### use_for
Analysis.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"""


@pytest.fixture
def session():
    with tn.Session(POLICY, groups=["default", "secret"]) as value:
        yield value


def create(session, fields=None):
    return session.create_obj(
        fields or {"amount": 40, "rows": [{"cost": 2}, {"cost": 3}]},
        session.policy("finance.account"),
        object_type="finance.account",
    )


def release(obj, **kwargs):
    return obj.release(to="analysis", purpose="aggregate", decide=lambda context: True, **kwargs)


def test_live_nested_mutation_preserves_contract_and_exact_versions(session):
    obj = create(session)
    initial = obj.snapshot
    rows = obj.data["rows"]
    rows[0]["cost"] = 7
    rows.append({"cost": 8})
    rows.insert(-1, {"cost": 9})
    del rows[1]
    rows[-1]["cost"] = 10
    obj.data["amount"] += sum(row["cost"] for row in rows)
    assert obj.data.copy() == {"amount": 66, "rows": [{"cost": 7}, {"cost": 9}, {"cost": 10}]}
    sealed = release(obj, object_type="finance.report")
    assert obj.object_type == "finance.report"
    assert obj.snapshot.wire == sealed.wire
    assert [item.wire for item in obj.history] == [initial.wire, sealed.wire]
    assert obj.policies[0].matches_contract(session.policy("finance.account"))
    received = session.receive(sealed, purpose="aggregate", decide=lambda c: True)
    assert received.data == obj.data
    assert received.governance.sources[0].references(initial)
    assert session.verify(bytes(initial)).wire == initial.wire


def test_admission_gets_verified_source_contract_and_requested_operation(session):
    obj = create(session)
    sealed = release(obj)
    seen = []

    def admit(context):
        seen.append(context)
        return (
            context.writer == session.did
            and context.object_type == "finance.account"
            and context.operation == context.purpose == "aggregate"
            and context.object.wire == sealed.wire
            and context.governance.matches_contract(session.policy("finance.account"))
            and len(context.policies) == 1
            and context.sources[0].references(obj.history[0])
        )

    result = session.receive(bytes(sealed), purpose="aggregate", decide=admit)
    assert result.data["amount"] == 40
    assert len(seen) == 1
    with pytest.raises(tn.governed.UseDenied):
        session.receive(sealed, purpose="aggregate", decide=lambda c: c.writer != session.did)
    with pytest.raises(AttributeError):
        seen[0].operation = "other"


def test_attachment_checks_authority_and_retains_all_contracts(session):
    obj = create(session)
    with tn.Session(POLICY.replace("Analysis.", "Internal analysis.")) as authority:
        additional = authority.policy("finance.account")
        revision = obj.revision
        with pytest.raises(tn.governed.UseDenied):
            obj.attach(additional, decide=lambda c: False)
        assert obj.revision == revision
        assert len(obj.policies) == 1
        obj.attach(
            additional,
            decide=lambda c: (
                c.authority == session.did
                and c.policy.governed_by == authority.did
                and len(c.data.policies) == len(c.policies) == 1
            ),
        )
    obj.data["amount"] = 5
    assert len(obj.policies) == 2
    result = session.receive(
        release(obj), purpose="aggregate", decide=lambda c: len(c.policies) == 2
    )
    assert len(result.policies) == 2
    assert result.policies[1].matches_contract(additional)
    with pytest.raises(ValueError):
        obj.groups["tn.agents"] = {}
    with pytest.raises(AttributeError):
        obj.governance = additional


def test_include_retains_multiple_inputs_and_contracts(session):
    left, right = create(session), create(session, {"amount": 11})
    left_source, right_source = left.snapshot, right.snapshot
    left.include(right)
    left.data["amount"] += right.data["amount"]
    output = release(left)
    references = session.governance(output).governance.sources
    assert len(references) == 2
    assert references[0].references(left_source)
    assert references[1].references(right_source)
    assert references[1].operation == "create"
    assert references[1].groups == ["default"]
    assert references[1].revision_id is None


def test_release_decision_sees_detached_current_state_and_preserves_denied_work(session):
    obj = create(session)
    original = obj.snapshot.wire
    revision = obj.revision

    def refuse(context):
        assert context.writer == session.did
        assert context.destination == "analysis"
        assert context.purpose == "aggregate"
        assert context.data.groups["default"]["amount"] == 40
        assert context.sources[0].references(obj.snapshot)
        context.data.groups["default"]["amount"] = 999
        return False

    with pytest.raises(tn.governed.UseDenied):
        obj.release(to="analysis", purpose="aggregate", decide=refuse)
    assert obj.data["amount"] == 40
    assert obj.snapshot.wire == original
    assert obj.revision == revision


@pytest.mark.parametrize("operation", ["receive", "attach", "release"])
def test_strict_boolean_decisions_and_original_callback_errors(session, operation):
    obj = create(session)

    def run(callback):
        if operation == "receive":
            return session.receive(obj.snapshot, purpose="aggregate", decide=callback)
        if operation == "attach":
            return obj.attach(obj.governance, decide=callback)
        return obj.release(to="analysis", purpose="aggregate", decide=callback)

    for value in (None, 1, "yes", [], {}):
        with pytest.raises(TypeError, match="bool"):
            run(lambda c: value)
    error = LookupError("policy unavailable")

    def fail(context):
        raise error

    with pytest.raises(LookupError) as caught:
        run(fail)
    assert caught.value is error
    assert len(obj.history) == 1


@pytest.mark.parametrize("operation", ["attach", "release"])
def test_callback_mutation_requires_new_decision(session, operation):
    obj = create(session)

    def mutate(context):
        obj.data["amount"] = 99
        return True

    with pytest.raises(tn.governed.GovernedError, match="changed during"):
        if operation == "attach":
            obj.attach(obj.governance, decide=mutate)
        else:
            obj.release(to="analysis", purpose="aggregate", decide=mutate)
    assert obj.data["amount"] == 99
    assert len(obj.history) == 1


def test_concurrent_mutation_during_callback_never_releases_stale_approval(session):
    obj = create(session)
    evaluating, mutated = Event(), Event()

    def decide(context):
        evaluating.set()
        assert mutated.wait(10)
        return True

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(obj.release, to="analysis", purpose="aggregate", decide=decide)
        assert evaluating.wait(10)
        obj.data["amount"] = 71
        mutated.set()
        with pytest.raises(tn.governed.GovernedError, match="changed during"):
            pending.result(timeout=10)
    assert len(obj.history) == 1


def test_bound_session_closure_and_other_session_independence(session):
    obj = create(session)
    with tn.Session(POLICY) as other:
        independent = create(other)
        with pytest.raises(tn.governed.NotEntitled):
            other.receive(obj.snapshot, purpose="aggregate", decide=lambda c: True)
        session.close()
        obj.data["amount"] = 8
        with pytest.raises(tn.governed.SessionClosed):
            release(obj)
        with pytest.raises(tn.governed.SessionClosed):
            obj.attach(obj.governance, decide=lambda c: True)
        assert release(independent).writer == other.did
        assert obj.snapshot.writer != other.did


def test_callback_cannot_close_then_release(session):
    obj = create(session)

    def close(context):
        session.close()
        return True

    with pytest.raises(tn.governed.SessionClosed):
        obj.release(to="analysis", purpose="aggregate", decide=close)
    assert len(obj.history) == 1


def test_selected_data_keeps_unopened_ciphertext(session):
    source = session.seal(
        session.draft("finance.account")
        .group("default", {"amount": 8})
        .group("secret", {"name": "Alice"})
    )
    obj = session.receive(source, purpose="aggregate", groups=["default"], decide=lambda c: True)
    assert obj.hidden_groups == ["secret"]
    obj.data["amount"] = 16
    result = release(obj)
    all_data = session.receive(
        result, purpose="inspect", groups=["default", "secret"], decide=lambda c: True
    )
    assert all_data.groups["secret"]["name"] == "Alice"
    assert all_data.data["amount"] == 16
    old, new = source.envelope, result.envelope
    assert old["tn_aad"] == new["tn_aad"]


def test_publication_preflight_reports_all_groups(session):
    report = session.check_groups(["default", "missing", "missing"])
    assert report.required_groups == ["default", "missing", "tn.agents"]
    assert report.missing_groups == ["missing"]
    assert report.supported_groups == ["default", "tn.agents"]
    assert report.unavailable_groups == report.unknown_groups == []
    assert not report.is_ready
    with pytest.raises(ValueError, match="publication preflight failed"):
        session.require_groups(["missing"])
    assert session.check_groups(["default"]).is_ready
    session.require_groups(["default"])


def test_list_slices_and_detached_copies(session):
    obj = create(session, {"values": [0, 1, 2, 3]})
    obj.data["values"][1:3] = [5, 6, 7]
    del obj.data["values"][::2]
    assert obj.data["values"] == [5, 7]
    copy = obj.data.copy()
    copy["values"].append(99)
    assert obj.data["values"] == [5, 7]
    with pytest.raises(IndexError):
        obj.data["values"][9] = 2
    with pytest.raises(KeyError):
        obj.data["missing"]
    assert json.loads(json.dumps(obj.state.groups))["default"] == obj.data.copy()


def test_nested_mutator_results_are_detached_and_reverse_preserves_every_value(session):
    obj = create(session, {"rows": [{"n": 1}, {"n": 2}, {"n": 3}], "nested": {"label": "original"}})
    obj.data["rows"].reverse()
    assert obj.data["rows"] == [{"n": 3}, {"n": 2}, {"n": 1}]
    removed = obj.data["rows"].pop(0)
    assert removed == {"n": 3}
    obj.data["rows"][0]["n"] = 99
    assert removed == {"n": 3}
    nested = obj.data.pop("nested")
    assert nested == {"label": "original"}
    assert obj.data.pop("missing", "fallback") == "fallback"
    with pytest.raises(KeyError):
        obj.data.pop("missing")
    key, remaining = obj.data.popitem()
    assert key == "rows"
    assert remaining == [{"n": 99}, {"n": 1}]
    assert obj.data == {}
    obj.data.setdefault("nested", {})["x"] = 5
    assert obj.data["nested"] == {"x": 5}


def test_slice_rhs_mutation_and_self_extension_keep_every_value(session):
    obj = create(session, {"rows": [1, 2]})
    rows = obj.data["rows"]

    def additions():
        rows.append(3)
        yield 9

    rows[:1] = additions()
    assert rows == [9, 2, 3]
    rows.extend(rows)
    assert rows == [9, 2, 3, 9, 2, 3]


def test_zero_step_slice_rejects_before_consuming_rhs(session):
    obj = create(session, {"rows": [1, 2]})
    rows = obj.data["rows"]

    def additions():
        rows.append(3)
        yield 9

    with pytest.raises(ValueError, match="slice step cannot be zero"):
        rows[::0] = additions()
    assert rows == [1, 2]

    class SideEffectIndex:
        def __index__(self):
            rows.append(4)
            return 0

    with pytest.raises(ValueError, match="slice step cannot be zero"):
        rows[SideEffectIndex() :: 0] = additions()
    assert rows == [1, 2]


@pytest.mark.parametrize(
    "start, stop, step",
    [
        (None, None, -1),
        (-8, 99, 2),
        (4, 0, -2),
        (1, -1, 1),
        (4, 1, 1),
        (None, None, -2),
        (-99, 99, -3),
    ],
)
def test_atomic_slice_mutations_match_python_lists(session, start, stop, step):
    key = slice(start, stop, step)
    expected = [0, 1, 2, 3, 4]
    obj = create(session, {"rows": expected.copy()})
    replacement = [10 + i for i in range(len(expected[key]))]
    expected[key] = replacement
    obj.data["rows"][key] = replacement
    assert obj.data["rows"] == expected
    del expected[key]
    del obj.data["rows"][key]
    assert obj.data["rows"] == expected


def test_creation_and_release_registers_are_captured_per_session(tmp_path, monkeypatch):
    paths = {
        name: tmp_path / f"{name}.ndjson"
        for name in ["a-create", "a-release", "b-create", "b-release"]
    }
    monkeypatch.setenv("TN_OBJECT_CREATION_REGISTER", str(paths["a-create"]))
    monkeypatch.setenv("TN_OBJECT_RELEASE_REGISTER", str(paths["a-release"]))
    first = tn.Session(POLICY)
    monkeypatch.setenv("TN_OBJECT_CREATION_REGISTER", str(paths["b-create"]))
    monkeypatch.setenv("TN_OBJECT_RELEASE_REGISTER", str(paths["b-release"]))
    second = tn.Session(POLICY)
    try:
        secret = "private-business-data-excluded-from-registers"
        a, b = create(first, {"private_note": secret}), create(second)
        initial_a, initial_b = a.snapshot, b.snapshot
        output_a, output_b = release(a), release(b)
        for name, signer, snapshot, event in [
            ("a-create", first.did, initial_a, "tn.object.created"),
            ("a-release", first.did, output_a, "tn.object.released"),
            ("b-create", second.did, initial_b, "tn.object.created"),
            ("b-release", second.did, output_b, "tn.object.released"),
        ]:
            wire = paths[name].read_text()
            assert secret not in wire
            row = json.loads(wire)
            assert row["device_identity"] == signer
            assert row["object_id"] == snapshot.id
            assert row["event_type"] == event
            assert row["sequence"] == 1
            assert row["signature"]
        assert a.register_error is b.register_error is None
    finally:
        first.close()
        second.close()


def test_optional_register_failure_keeps_the_sealed_result(tmp_path, monkeypatch):
    path = tmp_path / "release.ndjson"
    path.write_text("torn register")
    monkeypatch.setenv("TN_OBJECT_RELEASE_REGISTER", str(path))
    with tn.Session(POLICY) as session:
        obj = create(session)
        output = release(obj)
        assert obj.snapshot.wire == output.wire
        assert obj.register_error
        assert path.read_text() == "torn register"
