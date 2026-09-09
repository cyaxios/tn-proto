"""Signed policy revisions use the canonical Rust DAG and explicit authority."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
import tn

POLICY = """---
version: 1
schema: tn-agents-policy@v1
---
## research.sample
### instruction
Create an aggregate report.
### use_for
Aggregate research.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"""


@pytest.fixture
def session():
    with tn.Session(POLICY, groups=["policy_revision", "observations"]) as value:
        yield value


def draft(session, *, policy=POLICY, authority=None, scope="research"):
    return tn.governed.PolicyRevisionDraft.from_markdown(
        authority or session.did, policy, "agents.md", "research.sample", scope
    )


def opened_revision(session, revision_draft):
    source = session.seal(revision_draft.into_draft(session.policy("research.sample")))
    received = tn.GovernedObject.parse(bytes(source))
    admitted = session.governance(received).authorize(
        "policy.inspect",
        lambda contract, operation: (
            contract.governed_by == session.did and operation == "policy.inspect"
        ),
    )
    return session.open(admitted, ["policy_revision"])


def revision(session, revision_draft=None):
    return tn.governed.PolicyRevision.from_opened(
        opened_revision(session, revision_draft or draft(session))
    )


def test_signed_revision_round_trip_binds_normalized_policy_and_source(session):
    assert hasattr(tn.governed, "PolicyRevisionDraft"), "native policy revisions are required"
    from tn._native import governed as native

    assert tn.governed.PolicyDag is native.PolicyDag
    document = POLICY.replace("report.", "report café 🦀.")
    root = revision(session, draft(session, policy=document))
    expected = tn.Governance.from_markdown(session.did, document, "agents.md", "research.sample")
    assert root.governance.matches_contract(expected)
    assert root.writer == session.did
    assert root.scope == "research"
    assert not root.parents
    assert root.id == root.object.id
    assert root.object.object_type == "tn.policy.revision"
    # Field names remain in authenticated field hashes; document values are encrypted.
    assert "ciphertext" in root.object.envelope["policy_revision"]
    assert "document" not in root.object.envelope["policy_revision"]
    assert "Create an aggregate report café" not in root.object.wire
    reopened = session.open(
        session.governance(root.object).authorize("policy.inspect", lambda c, op: True),
        ["policy_revision"],
    )
    assert tn.governed.PolicyRevision.from_opened(reopened).object.wire == root.object.wire
    with pytest.raises(TypeError):
        tn.governed.PolicyRevision(root.object.envelope)
    with pytest.raises(TypeError):
        tn.governed.PolicyRevision.from_opened(root.object)


def test_dag_requires_every_parent_then_selects_exact_revision_and_scope(session):
    relation = tn.governed.PolicyRelation
    root_draft = draft(session)
    root = revision(session, root_draft)
    left = revision(
        session,
        draft(session, policy=POLICY.replace("version: 1", "version: 2")).parent(
            root.id, relation.Revise
        ),
    )
    right = revision(session, draft(session).parent(root.id, relation.Extend))
    merged = revision(
        session,
        draft(session).parent(left.id, relation.Combine).parent(right.id, relation.Combine),
    )
    dag = tn.governed.PolicyDag()
    calls = []

    def authorize(candidate, parent):
        calls.append((candidate, parent))
        return (
            candidate.writer == session.did
            and candidate.governance.governed_by == session.did
            and candidate.scope == "research"
            and (parent is None or parent[0].revision_id == parent[1].id)
        )

    with pytest.raises(ValueError):
        dag.admit(left, authorize)
    assert not calls and len(dag) == 0
    for item in (root, left, right, merged):
        dag.admit(item, authorize)
    assert len(dag) == 4
    assert [None if parent is None else parent[1].id for _, parent in calls] == [
        None,
        root.id,
        root.id,
        left.id,
        right.id,
    ]
    assert calls[1][1][0].relation == relation.Revise
    assert calls[2][1][0].relation == relation.Extend
    assert calls[3][1][0].relation == relation.Combine
    assert dag.get(root.id).object.wire == root.object.wire
    assert dag.get("sha256:" + "0" * 64) is None
    with pytest.raises(ValueError):
        dag.admit(root, authorize)
    assert len(dag) == 4 and len(calls) == 5
    with pytest.raises(ValueError):
        dag.select(root.id, "other", lambda item: True)
    with pytest.raises(ValueError):
        dag.select("sha256:" + "0" * 64, "research", lambda item: True)
    selected = dag.select(root.id, "research", lambda item: item.id == root.id)
    assert selected.revision_id == root.id
    assert selected.get("instruction") == "Create an aggregate report."
    assert dag.resolve(selected, "research").id == root.id
    with pytest.raises(ValueError):
        dag.resolve(selected, "other")
    with pytest.raises(ValueError):
        dag.resolve(root.governance, "research")
    # Adding a parent returns a new immutable draft and leaves the root usable.
    assert not revision(session, root_draft).parents


def test_selected_revision_survives_signed_object_and_derivation(session):
    root = revision(session)
    dag = tn.governed.PolicyDag()
    dag.admit(root, lambda candidate, parent: True)
    selected = dag.select(root.id, "research", lambda candidate: True)
    source = session.seal(
        tn.GovernedDraft("research.sample", selected).group("observations", {"amount": 4})
    )
    admitted = session.governance(source).authorize("aggregate", lambda c, op: True)
    opened = session.open(admitted, ["observations"])
    assert dag.resolve(opened.governance, "research").id == root.id
    with tn.Session(POLICY, groups=["observations"]) as other:
        derived = other.seal(opened.derive("research.report").group("observations", {"total": 4}))
        contract = other.governance(derived).governance
        assert derived.writer == other.did and other.did != session.did
        assert contract.governed_by == session.did
        assert dag.resolve(contract, "research").id == root.id
        assert contract.sources[0].references(source)


def test_application_rejects_forged_update_authority_with_real_independent_writer(session):
    root = revision(session)
    dag = tn.governed.PolicyDag()
    dag.admit(root, lambda candidate, parent: candidate.writer == session.did)
    with tn.Session(POLICY, groups=["policy_revision"]) as other:
        candidate = revision(
            other,
            draft(other, authority=session.did).parent(root.id, tn.governed.PolicyRelation.Revise),
        )
        assert candidate.writer == other.did and candidate.governance.governed_by == session.did
        with pytest.raises(tn.governed.UseDenied):
            dag.admit(candidate, lambda candidate, parent: candidate.writer == session.did)
        assert dag.get(candidate.id) is None and len(dag) == 1


@pytest.mark.parametrize("operation", ["admit", "select"])
def test_dag_callbacks_require_bool_and_preserve_original_errors(session, operation):
    root = revision(session)
    dag = tn.governed.PolicyDag()
    if operation == "select":
        dag.admit(root, lambda candidate, parent: True)

    def run(decision):
        if operation == "admit":
            return dag.admit(root, decision)
        return dag.select(root.id, "research", decision)

    for value in (None, 1, "yes", [], {}):
        with pytest.raises(TypeError, match="bool"):
            run(lambda *args: value)
    failure = LookupError("policy authority unavailable")

    def fail(*args):
        raise failure

    with pytest.raises(LookupError) as caught:
        run(fail)
    assert caught.value is failure
    with pytest.raises(tn.governed.UseDenied):
        run(lambda *args: False)
    assert len(dag) == (1 if operation == "select" else 0)


def test_combine_admission_is_atomic_when_later_parent_is_denied(session):
    roots = [revision(session), revision(session)]
    dag = tn.governed.PolicyDag()
    for root in roots:
        dag.admit(root, lambda candidate, parent: True)
    merged = revision(
        session,
        draft(session)
        .parent(roots[0].id, tn.governed.PolicyRelation.Combine)
        .parent(roots[1].id, tn.governed.PolicyRelation.Combine),
    )
    with pytest.raises(tn.governed.UseDenied):
        dag.admit(merged, lambda candidate, parent: parent[1].id == roots[0].id)
    assert len(dag) == 2 and dag.get(merged.id) is None
    dag.admit(merged, lambda candidate, parent: True)
    assert len(dag) == 3


def test_callback_revision_views_cannot_mutate_accepted_history(session):
    root = revision(session)
    child = revision(session, draft(session).parent(root.id, tn.governed.PolicyRelation.Extend))
    dag = tn.governed.PolicyDag()
    dag.admit(root, lambda candidate, parent: True)

    def authorize(candidate, parent):
        edge, accepted = parent
        for value, attribute in ((candidate, "scope"), (edge, "revision_id"), (accepted, "writer")):
            with pytest.raises(AttributeError):
                setattr(value, attribute, "forged")
        candidate.governance.fields["instruction"] = "Forged."
        accepted.object.envelope["event_type"] = "forged"
        return True

    dag.admit(child, authorize)
    assert dag.get(child.id).governance.get("instruction") == "Create an aggregate report."
    assert dag.get(root.id).object.object_type == "tn.policy.revision"


@pytest.mark.parametrize("operation", ["admit", "select"])
def test_reentrant_dag_change_requires_fresh_authority_decision(session, operation):
    candidate, nested = revision(session), revision(session)
    dag = tn.governed.PolicyDag()
    if operation == "select":
        dag.admit(candidate, lambda revision, parent: True)

    def change(*args):
        # Safe callback reads and nested writes must never deadlock or overwrite history.
        assert len(dag) == (1 if operation == "select" else 0)
        dag.admit(nested, lambda revision, parent: True)
        return True

    with pytest.raises(RuntimeError, match="changed"):
        if operation == "admit":
            dag.admit(candidate, change)
        else:
            dag.select(candidate.id, "research", change)
    assert dag.get(nested.id).object.wire == nested.object.wire
    assert len(dag) == (2 if operation == "select" else 1)
    if operation == "admit":
        assert dag.get(candidate.id) is None
        dag.admit(candidate, lambda revision, parent: True)


def test_concurrent_dag_admission_retains_winner_and_rejects_stale_callback(session):
    pending, winner = revision(session), revision(session)
    dag = tn.governed.PolicyDag()
    entered, resume = Event(), Event()

    def wait_for_winner(candidate, parent):
        entered.set()
        assert resume.wait(5), "concurrent admission did not finish"
        return True

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(dag.admit, pending, wait_for_winner)
        try:
            assert entered.wait(5), "authority callback did not run"
            dag.admit(winner, lambda candidate, parent: True)
        finally:
            resume.set()
        with pytest.raises(RuntimeError, match="changed"):
            future.result(timeout=5)
    assert len(dag) == 1 and dag.get(pending.id) is None
    assert dag.get(winner.id).object.wire == winner.object.wire


def test_revision_decoder_requires_admitted_revision_group_and_signed_integrity(session):
    root = revision(session)
    admitted = session.governance(root.object).authorize("policy.inspect", lambda c, op: True)
    with pytest.raises(ValueError, match="policy_revision"):
        tn.governed.PolicyRevision.from_opened(session.open(admitted, []))
    ordinary = session.seal(session.draft("research.sample").group("observations", {"amount": 4}))
    opened = session.open(
        session.governance(ordinary).authorize("aggregate", lambda c, op: True), ["observations"]
    )
    with pytest.raises(ValueError, match="tn.policy.revision"):
        tn.governed.PolicyRevision.from_opened(opened)
    with pytest.raises(tn.governed.VerificationError):
        tn.GovernedObject.parse(
            root.object.wire.replace("tn.policy.revision", "tn.policy.tampered")
        )


def test_native_revision_builder_rejects_invalid_parent_shapes(session):
    root, other = revision(session), revision(session)
    relation = tn.governed.PolicyRelation
    with pytest.raises(ValueError):
        draft(session).parent("not-a-row-hash", relation.Revise)
    with pytest.raises(ValueError):
        draft(session).parent(root.id, relation.Revise).parent(root.id, relation.Revise)
    for invalid in (
        draft(session).parent(root.id, relation.Combine),
        draft(session).parent(root.id, relation.Revise).parent(other.id, relation.Extend),
    ):
        with pytest.raises(ValueError):
            invalid.into_draft(session.policy("research.sample"))
    with pytest.raises(TypeError):
        draft(session).parent(root.id, "revise")
