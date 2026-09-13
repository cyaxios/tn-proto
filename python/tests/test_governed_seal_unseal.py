"""Governed seal/unseal retain native admission and publication enforcement."""

import json

import pytest
import tn
from tn import governed as g
from tn._native import governed as native

from test_governed_application_session import POLICY
from test_governed_dataset_workflow import approved_use, workflow


READ = g.UseContext("hello", "analysis", "read")
WRITE = g.UseContext("hello", "report", "publish")


@pytest.fixture
def session():
    with g.Session(POLICY, groups=["default", "private"]) as value:
        yield value


def source(session):
    return session.create_obj_with_groups(
        {"default": {"message": "hello"}, "private": {"number": 42}},
        session.policy("hello.message"),
    )


def configure(session, *, accept=lambda _: True, release=lambda _: True):
    session.configure_receive(use=READ, groups=["private"], decide=accept)
    session.configure_release(
        use=WRITE, to="report-service", object_type="hello.report", decide=release,
    )
    return session.workflow(receive="analysis", release="report")


@pytest.mark.parametrize("representation", ["object", "text", "bytes", "data"])
def test_session_unseal_accepts_publications_and_binds_explicit_use(session, representation):
    data = source(session)
    publication = data.snapshot
    sealed = {
        "object": publication, "text": publication.wire,
        "bytes": publication.forward(), "data": data,
    }[representation]
    calls = []

    def accept(context):
        calls.append(context)
        return context.writer == session.did and context.governance.matches_contract(data.governance)

    opened = session.unseal(sealed, use=READ, groups=["private"], decide=accept)
    assert type(opened) is native.DataObject is tn.DataObject is g.DataObject
    assert opened.get() == {"number": 42}
    assert opened.hidden_groups == ["default"]
    assert len(calls) == 1
    assert calls[0].use_context == READ
    assert calls[0].groups == ["private"]
    assert calls[0].object.id == publication.id
    assert calls[0].policies[0].matches_contract(data.governance)


def test_session_unseal_keeps_configured_admission_and_unreleased_checks(session):
    data = source(session)
    with pytest.raises(ValueError, match="not configured"):
        session.unseal(data, purpose="analysis")
    configure(session)
    opened = session.unseal(data, purpose="analysis")
    assert opened.get("number") == 42
    with pytest.raises(TypeError, match="requires decide"):
        session.unseal(data, purpose="analysis", groups=["default"])
    data.set("message", "edited")
    with pytest.raises(ValueError, match="release"):
        session.unseal(data, purpose="analysis")


@pytest.mark.parametrize("answer,error", [(False, g.UseDenied), (None, TypeError), (1, TypeError)])
def test_session_unseal_requires_positive_boolean_admission(session, answer, error):
    publication = source(session).snapshot
    with pytest.raises(error):
        session.unseal(publication, use=READ, decide=lambda _: answer)


def test_session_unseal_propagates_callback_failure_and_requires_complete_use(session):
    publication = source(session).snapshot
    failure = RuntimeError("admission authority unavailable")

    def fail(_):
        raise failure

    with pytest.raises(RuntimeError) as caught:
        session.unseal(publication, use=READ, decide=fail)
    assert caught.value is failure
    for kwargs in [{"groups": ["default"]}, {"use": READ, "purpose": "analysis"}]:
        with pytest.raises(TypeError):
            session.unseal(publication, **kwargs, decide=lambda _: pytest.fail("invalid use reached admission"))


def test_session_unseal_verifies_signature_and_groups_before_admission(session):
    publication = source(session).snapshot
    envelope = json.loads(publication.wire)
    envelope["signature"] = "invalid"

    def unexpected(_):
        pytest.fail("invalid publication reached admission")

    with pytest.raises(g.VerificationError):
        session.unseal(json.dumps(envelope), use=READ, decide=unexpected)
    with pytest.raises(ValueError):
        session.unseal(publication, use=READ, groups=["missing"], decide=unexpected)
    with g.Session(POLICY) as unrelated:
        with pytest.raises(g.NotEntitled):
            unrelated.unseal(publication, use=READ, decide=unexpected)


def test_session_draft_seal_still_publishes_native_governed_objects(session):
    draft = session.draft("hello.message").group("default", {"message": "draft"})
    publication = session.seal(draft)
    assert type(publication) is native.GovernedObject
    assert session.unseal(publication, use=READ, decide=lambda _: True).get("message") == "draft"
    with pytest.raises(TypeError):
        session.seal(source(session))


@pytest.mark.parametrize("entrypoint", ["session", "workflow"])
def test_unseal_preserves_dataset_selection_and_rejects_another_source(workflow, entrypoint):
    session, _, _, entries = workflow
    _, original, _, selection = entries[0]
    _, other, _, _ = entries[1]
    calls = []

    def accept(context):
        calls.append(context.object.id)
        return True

    if entrypoint == "workflow":
        session.configure_receive(use=approved_use(), groups=["finance"], decide=accept)
        session.configure_release(use=WRITE, to="report-service", object_type="market.result", decide=lambda _: True)
        unseal = session.workflow(receive=approved_use().purpose, release="report").unseal
        kwargs = {}
    else:
        unseal = session.unseal
        kwargs = {"use": approved_use(), "groups": ["finance"], "decide": accept}
    received = unseal(original, selection=selection, **kwargs)
    assert received.get("last_price") == 100
    assert received.dataset_bindings == [selection.binding]
    assert calls == [original.id]
    with pytest.raises((ValueError, g.UseDenied)):
        unseal(other, selection=selection, **kwargs)
    assert calls == [original.id]


def test_workflow_seal_runs_live_rules_and_preserves_contracts(session):
    active = [True]
    decisions = []

    def release(context):
        decisions.append(context)
        return active[0]

    work = configure(session, accept=lambda _: active[0], release=release)
    original = source(session)
    data = work.unseal(original)
    data.set("number", 84)
    before = data.snapshot.id, len(data.history)
    with pytest.raises(g.UseDenied):
        work.seal(data, decide=lambda _: False)
    assert (data.snapshot.id, len(data.history)) == before
    assert data.has_unreleased_changes
    publication = work.seal(data, decide=lambda context: context.data.groups["private"]["number"] == 84)
    assert type(work) is native.Workflow is tn.Workflow is g.Workflow
    assert publication.object_type == "hello.report"
    assert publication.writer == session.did
    assert set(publication.group_names) == {"default", "private", "tn.agents"}
    assert data.snapshot.id == publication.id
    assert len(data.history) == before[1] + 1
    assert not data.has_unreleased_changes
    assert decisions[-1].use_context == WRITE
    assert decisions[-1].destination == "report-service"
    reopened = work.unseal(publication)
    assert reopened.get("number") == 84
    assert reopened.hidden_groups == ["default"]
    assert session.unseal(publication, use=READ, decide=lambda _: True).get("message") == "hello"
    assert any(policy.matches_contract(original.governance) for policy in reopened.policies)
    assert any(item.references(original.snapshot) for item in reopened.governance.sources)
    active[0] = False
    with pytest.raises(g.UseDenied):
        work.seal(data, decide=lambda _: True)
    with pytest.raises(g.UseDenied):
        work.unseal(publication)


def test_data_seal_requires_release_authority_and_preserves_explicit_context(session):
    data = source(session)
    data.set("message", "edited")
    initial = data.snapshot.id
    with pytest.raises(TypeError):
        data.seal()
    with pytest.raises(TypeError, match="requires decide"):
        data.seal(use=WRITE, to="report-service")
    with pytest.raises(g.UseDenied):
        data.seal(use=WRITE, to="report-service", decide=lambda _: False)
    assert data.snapshot.id == initial
    publication = data.seal(use=WRITE, to="report-service", decide=lambda _: True, object_type="hello.report")
    assert publication.object_type == "hello.report"
    assert data.snapshot.id == publication.id
    assert session.governance(publication).governance.fields["release_context"] == {
        "application": "hello", "purpose": "report", "operation": "publish", "destination": "report-service",
    }
    assert session.unseal(publication, use=READ, decide=lambda _: True).get("message") == "edited"


def test_data_seal_uses_configured_release_and_cannot_override_denial(session):
    active = [True]
    configure(session, release=lambda _: active[0])
    data = source(session)
    publication = data.seal(purpose="report")
    assert publication.object_type == "hello.report"
    active[0] = False
    with pytest.raises(g.UseDenied):
        data.seal(purpose="report", decide=lambda _: True)
    assert data.snapshot.id == publication.id


@pytest.mark.parametrize("entrypoint", ["data", "workflow"])
def test_seal_rejects_mutation_during_release_without_signing_stale_state(session, entrypoint):
    work = configure(session)
    data = source(session)
    initial = data.snapshot.id, len(data.history)

    def mutate(_):
        data.set("message", "changed during release")
        return True

    with pytest.raises(g.GovernedError, match="changed"):
        if entrypoint == "data":
            data.seal(use=WRITE, to="report-service", decide=mutate)
        else:
            work.seal(data, decide=mutate)
    assert (data.snapshot.id, len(data.history)) == initial
    assert data.get("message") == "changed during release"


def test_seal_and_unseal_keep_native_session_lifecycle(session):
    work = configure(session)
    data = source(session)
    publication = data.snapshot
    session.close()
    for call in (
        lambda: session.unseal(publication, use=READ, decide=lambda _: True),
        lambda: work.unseal(publication),
        lambda: work.seal(data),
        lambda: data.seal(use=WRITE, to="report-service", decide=lambda _: True),
    ):
        with pytest.raises(g.SessionClosed):
            call()


def test_unseal_cannot_open_data_after_admission_closes_the_session(session):
    publication = source(session).snapshot

    def close(_):
        session.close()
        return True

    with pytest.raises(g.SessionClosed):
        session.unseal(publication, use=READ, decide=close)


def test_provider_created_native_sessions_support_governed_verbs():
    from test_governed_providers import setup

    providers, actor, _, _, request, workflow = setup()
    with providers.session(actor.application, workflows=[workflow]) as session:
        assert type(session) is native.Session is tn.Session is g.Session
        source = session.create({"value": 7}, providers.policy(request))
        data = session.unseal(source, purpose="analysis")
        work = session.workflow(receive="analysis", release="report")
        data.set("value", 8)
        publication = work.seal(data)
        assert publication.writer == actor.did
        assert work.unseal(publication).get("value") == 8
        assert data.seal(purpose="report").writer == actor.did
