"""A native publisher can release received data without input reader material."""

import pytest
import tn

from test_governed_sessions import POLICY, configured_session_files
from test_governed_dataset_workflow import workflow, approved_use


USE = tn.UseContext("reporting", "portfolio_analysis", "publish_report")


def test_separate_publisher_releases_native_data_with_unrelated_group_generations(tmp_path):
    input_config, _ = configured_session_files(tmp_path / "input")
    with (tn.Session.from_config(input_config) as source,
          tn.Session.from_config(input_config) as receiver,
          tn.Session(POLICY) as publisher):
        original = source.create_obj({"amount": 42}, source.policy("research.sample"),
                                     object_type="research.sample").snapshot
        with pytest.raises(tn.governed.NotEntitled):
            publisher.governance(original)
        data = receiver.receive(original, use=USE, decide=lambda context: True)
        expected = data.policies
        data.data["amount"] = 84
        calls = []

        def decide(context):
            calls.append(context)
            assert context.writer == publisher.did
            assert context.use_context == USE
            assert context.data.snapshot.id == original.id
            assert all(any(p.matches_contract(old) for old in expected) for p in context.policies)
            return True

        released = publisher.release(data, use=USE, to="recipient", decide=decide,
                                     object_type="report.generated")
        assert len(calls) == 1
        assert released.writer == publisher.did != original.writer
        assert data.snapshot.id == released.id
        assert data.history[-1].wire == released.wire
        with pytest.raises(tn.governed.NotEntitled):
            receiver.governance(released)
        opened = publisher.receive(released, use=USE, decide=lambda context: True)
        assert opened.data["amount"] == 84
        assert opened.governance.sources[0].references(original)


def test_explicit_publisher_preserves_all_native_dataset_bindings_and_contracts(workflow):
    receiver, _, _, entries = workflow
    first, second = entries
    data = receiver.receive(first[1], use=approved_use(), groups=["finance"],
                            selection=first[3], decide=lambda context: True)
    other = receiver.receive(second[1], use=approved_use(), groups=["finance"],
                             selection=second[3], decide=lambda context: True)
    data.include(other)
    expected_policies, expected_bindings = data.policies, data.dataset_bindings
    data.groups["default"] = {"report_html": "<p>Approved aggregate.</p>"}
    data.retain_groups(["default"])
    receiver.close()
    with tn.Session(POLICY) as publisher:
        released = publisher.release(data, use=USE, to="recipient", decide=lambda context: True,
                                     object_type="report.generated")
        reopened = publisher.receive(released, use=USE, decide=lambda context: True)
        assert len(reopened.policies) == len(expected_policies) == 2
        assert all(any(p.matches_contract(expected) for p in reopened.policies) for expected in expected_policies)
        assert reopened.dataset_bindings == expected_bindings
        assert set(released.group_names) == {"default", "tn.agents"}
        with pytest.raises(tn.governed.SessionClosed):
            data.release(use=USE, to="recipient", decide=lambda context: True)


def test_explicit_release_refusal_strict_bool_and_callback_failure_are_atomic():
    with tn.Session(POLICY) as receiver, tn.Session(POLICY) as publisher:
        data = receiver.create_obj({"amount": 42}, receiver.policy("research.sample"), object_type="research.sample")
        before = data.snapshot.id, data.revision, len(data.history)
        for decide, error in [(lambda context: False, tn.governed.UseDenied),
                              (lambda context: 1, TypeError)]:
            with pytest.raises(error):
                publisher.release(data, use=USE, to="recipient", decide=decide)
            assert (data.snapshot.id, data.revision, len(data.history)) == before
        failure = RuntimeError("publisher authority unavailable")
        def fail(context):
            raise failure
        with pytest.raises(RuntimeError) as caught:
            publisher.release(data, use=USE, to="recipient", decide=fail)
        assert caught.value is failure
        assert (data.snapshot.id, data.revision, len(data.history)) == before


def test_reentrant_mutation_and_closed_publisher_cannot_sign_a_stale_candidate():
    with tn.Session(POLICY) as receiver, tn.Session(POLICY) as publisher:
        data = receiver.create_obj({"amount": 42}, receiver.policy("research.sample"), object_type="research.sample")
        original = data.snapshot.id
        def mutate(context):
            data.data["amount"] = 99
            return True
        with pytest.raises(tn.governed.GovernedError, match="changed"):
            publisher.release(data, use=USE, to="recipient", decide=mutate)
        assert data.snapshot.id == original and data.data["amount"] == 99
        def close(context):
            publisher.close()
            return True
        with pytest.raises(tn.governed.SessionClosed):
            publisher.release(data, use=USE, to="recipient", decide=close)
        assert data.snapshot.id == original
