"""Dataset editions use Rust-owned acceptance and the ordinary signed TN envelope."""

import pytest

import tn
from tn import governed as g


POLICY = """---
version: 1
schema: tn-agents-policy@v1
---
## market.prices
### instruction
Prepare approved prices.
### use_for
Portfolio research.
### do_not_use_for
Redistribution.
### consequences
Review.
### on_violation_or_error
Refuse.
"""


def approved_use():
    return g.UseContext("analytics", "portfolio_analysis", "join_prices")


def downstream_use():
    return g.UseContext("deepvest", "portfolio_analysis", "calculate")


def open_metadata(session, obj, group):
    admitted = session.governance(obj).authorize("inspect_metadata", lambda *_: True)
    return session.open(admitted, [group])


@pytest.fixture
def workflow():
    with g.Session(POLICY, groups=["finance", "audit", "policy_revision", "dataset_edition"]) as session:
        dag = g.PolicyDag()
        catalog = g.DatasetCatalog()
        entries = []
        administration = session.policy("market.prices")
        for version, edition in [("1", "close-2026-09-07"), ("2", "close-2026-09-08")]:
            revision_draft = g.PolicyRevisionDraft.from_markdown(
                session.did, POLICY.replace("version: 1", f"version: {version}"),
                "agents.md", "market.prices", "market.prices",
            )
            revision_obj = session.seal(revision_draft.into_draft(administration))
            revision = g.PolicyRevision.from_opened(open_metadata(session, revision_obj, "policy_revision"))
            dag.admit(revision, lambda record, parent: record.writer == session.did)
            policy = dag.select(revision.id, "market.prices", lambda _: True)
            source = session.seal(
                g.GovernedDraft("market.prices", policy)
                .group("finance", {"symbol": "TEST", "last_price": 100})
                .group("audit", {"batch": "fixed"})
            )
            contract = g.ContractBinding(revision.id, "market.prices")
            artifacts = g.EvaluatorArtifactSet(revision.id, "a" * 64, "b" * 64, "c" * 64, "d" * 64)
            draft = g.DatasetEditionDraft(
                "market.prices", edition, source, ["finance"], [contract],
                [approved_use(), downstream_use()], "grant:approved", [artifacts],
            )
            record_obj = session.seal(draft.into_draft(administration))
            record = g.DatasetEdition.from_opened(open_metadata(session, record_obj, "dataset_edition"))
            catalog.admit(record, dag, lambda item: item.writer == session.did)
            selection = catalog.select("market.prices", edition, record.id, approved_use())
            entries.append((revision, source, record, selection))
        yield session, dag, catalog, entries


def receive(session, source, selection=None, *, use=None, decide=lambda _: True, groups=None):
    return session.receive(source.wire, **{
        "use": use or approved_use(), "groups": groups or ["finance"],
        "selection": selection, "decide": decide,
    })


def test_native_editions_pin_equal_values_to_distinct_sources_and_revisions(workflow):
    session, dag, catalog, entries = workflow
    (old_revision, old_source, old_record, old_selection), (new_revision, new_source, new_record, new_selection) = entries
    assert g.DatasetCatalog is tn._native.governed.DatasetCatalog
    assert g.DatasetSelection is tn._native.governed.DatasetSelection
    assert old_source.id != new_source.id
    assert old_revision.id != new_revision.id
    assert old_record.id != new_record.id
    old = receive(session, old_source, old_selection)
    new = receive(session, new_source, new_selection)
    assert old.data["last_price"] == new.data["last_price"] == 100
    assert old.dataset_bindings == [old_selection.binding]
    assert new.dataset_bindings == [new_selection.binding]
    assert old.dataset_bindings[0].contracts[0].revision_id == old_revision.id
    assert old_selection.record.object.wire == old_record.object.wire
    assert old_record.source_writer == session.did
    assert old_record.source_type == "market.prices"
    assert old_record.source_groups == ["finance"]
    assert old_record.evaluator_artifacts[0].wasm_sha256 == "c" * 64
    with pytest.raises(ValueError):
        catalog.admit(old_record, dag, lambda _: True)
    assert len(catalog) == 2
    # Accepting and opening the later edition does not replace the retained earlier edition.
    assert receive(session, old_source, old_selection).data["last_price"] == 100


def test_wrong_source_group_and_recombined_use_refuse_before_final_callback(workflow):
    session, _, catalog, entries = workflow
    _, old_source, old_record, old_selection = entries[0]
    _, new_source, _, _ = entries[1]
    called = []
    for source, use, groups in [
        (new_source, approved_use(), ["finance"]),
        (old_source, approved_use(), ["audit"]),
        (old_source, g.UseContext("analytics", "portfolio_analysis", "calculate"), ["finance"]),
    ]:
        with pytest.raises((ValueError, g.UseDenied)):
            receive(session, source, old_selection, use=use, groups=groups, decide=lambda ctx: called.append(ctx) or True)
    assert called == []
    with pytest.raises(g.UseDenied):
        catalog.select("market.prices", old_record.edition, old_record.id,
                       g.UseContext("analytics", "portfolio_analysis", "calculate"))
    with pytest.raises(ValueError):
        catalog.select("market.prices", "wrong", old_record.id, approved_use())
    with pytest.raises(TypeError):
        receive(session, old_source, old_selection.binding.fields)
    with pytest.raises(TypeError, match="use|purpose"):
        session.receive(old_source.wire, purpose="legacy", **{
            "use": approved_use(), "groups": ["finance"], "decide": lambda _: True,
        })


def test_accepted_values_have_no_arbitrary_constructor_and_return_detached_views(workflow):
    _, _, _, entries = workflow
    _, _, _, selection = entries[0]
    for cls in [g.DatasetSelection, g.DatasetEdition, g.DatasetBinding, g.AdmittedObject]:
        with pytest.raises(TypeError):
            cls()
    with pytest.raises(AttributeError):
        selection.source_object_id = "forged"
    fields = selection.binding.fields
    fields["edition"] = "forged"
    fields["contracts"].clear()
    assert selection.binding.edition == "close-2026-09-07"
    assert len(selection.binding.contracts) == 1
    with pytest.raises(ValueError):
        g.ContractBinding("latest", "market.prices")
    with pytest.raises(ValueError):
        g.EvaluatorArtifactSet("sha256:" + "a" * 64, "bad", "b" * 64, "c" * 64, "d" * 64)


def test_catalog_callbacks_are_atomic_propagate_errors_and_handle_reentry(workflow):
    _, dag, _, entries = workflow
    old = entries[0][2]
    new = entries[1][2]
    catalog = g.DatasetCatalog()
    for answer in [False, None, 1, "yes"]:
        with pytest.raises((g.UseDenied, TypeError)):
            catalog.admit(old, dag, lambda _: answer)
        assert len(catalog) == 0
    error = RuntimeError("catalog authority unavailable")

    def fails(_):
        raise error

    with pytest.raises(RuntimeError) as caught:
        catalog.admit(old, dag, fails)
    assert caught.value is error
    assert len(catalog) == 0

    def reenters(_):
        assert catalog.get(old.id) is None
        catalog.admit(new, dag, lambda _: True)
        return True

    with pytest.raises(RuntimeError, match="changed during"):
        catalog.admit(old, dag, reenters)
    assert len(catalog) == 1
    assert catalog.get(old.id) is None
    assert catalog.get(new.id).id == new.id
    catalog.admit(old, dag, lambda _: True)
    assert len(catalog) == 2


def test_copies_and_releases_keep_native_bindings_for_current_downstream_use(workflow):
    session, dag, catalog, entries = workflow
    _, source, _, selection = entries[0]
    _, second_source, _, second_selection = entries[1]
    original = receive(session, source, selection)
    sibling = original.copy()
    child = original.copy()
    child.include(receive(session, second_source, second_selection))
    child.data["last_price"] = 200
    assert sibling.data["last_price"] == original.data["last_price"] == 100
    assert len(child.dataset_bindings) == len(child.policies) == 2
    assert len(sibling.dataset_bindings) == len(sibling.policies) == 1
    released = child.release(**{
        "use": approved_use(), "to": "deepvest", "decide": lambda _: True,
        "object_type": "market.result",
    })
    opened = receive(session, released, use=downstream_use(), decide=lambda ctx: catalog.accepts(ctx, dag))
    assert opened.data["last_price"] == 200
    assert opened.dataset_bindings == child.dataset_bindings
    assert opened.sources[0].object_id == released.id
    release_context = session.governance(released).governance.fields["release_context"]
    assert release_context["application"] == "analytics"
    assert release_context["operation"] == "join_prices"
    with pytest.raises(g.UseDenied):
        receive(session, released, use=g.UseContext("unknown", "portfolio_analysis", "calculate"),
                decide=lambda ctx: catalog.accepts(ctx, dag))


def test_final_callback_error_preserves_exception_and_source(workflow):
    session, _, _, entries = workflow
    _, source, _, selection = entries[0]
    error = RuntimeError("policy evaluator failed")
    original_wire = source.wire

    def fails(_):
        raise error

    with pytest.raises(RuntimeError) as caught:
        receive(session, source, selection, decide=fails)
    assert caught.value is error
    assert source.wire == original_wire
    assert receive(session, source, selection).data["last_price"] == 100
