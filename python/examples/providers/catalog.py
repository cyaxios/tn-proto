"""Publish, admit and resolve an edition using native Rust catalog objects."""
from io import BytesIO
from tn import governed as g
from tn.providers import CatalogEntry, CatalogRequest, EditionCatalog
from governance import POLICY


def opened_metadata(session, publication, group):
    view = session.governance(publication)
    accepted = view.authorize("catalog-administration", lambda contract, operation: publication.writer == session.did and contract.governed_by == session.did)
    return session.open(accepted, [group])


def provision(session, policy, use_context, dataset, edition, directory=None):
    dag = g.PolicyDag()
    revision_draft = g.PolicyRevisionDraft.from_markdown(
        session.did, POLICY, "agents.md", "example.value", "example.value"
    )
    revision_wire = session.seal(revision_draft.into_draft(policy))
    revision = g.PolicyRevision.from_opened(opened_metadata(session, revision_wire, "policy_revision"))
    dag.admit(revision, lambda record, parent: record.writer == session.did)
    contract = dag.select(revision.id, "example.value", lambda record: record.writer == session.did)
    if directory is not None:
        from tn.providers import PolicyRequest
        directory.approve_contract(PolicyRequest("example.value", use_context), contract)
    source = session.create({"value": 7}, contract)
    publication = g.GovernedObject.read(BytesIO(source.forward()))
    draft = g.DatasetEditionDraft(
        dataset, edition, publication, ["default"],
        [g.ContractBinding(revision.id, "example.value")], [use_context],
        contract.policy_ref, [],
    )
    record_wire = session.seal(draft.into_draft(policy))
    record = g.DatasetEdition.from_opened(opened_metadata(session, record_wire, "dataset_edition"))
    accepted = g.DatasetCatalog()
    accepted.admit(record, dag, lambda candidate: candidate.writer == session.did)
    selection = accepted.select(dataset, edition, record.id, use_context)
    catalog = EditionCatalog()
    catalog.insert(CatalogEntry(publication, selection))
    return catalog, CatalogRequest(dataset, edition, use_context)


if __name__ == "__main__":
    from hello import configured
    providers, session, request = configured()
    catalog, query = provision(session, providers.policy(request), request.use_context, "values", "closing")
    result = catalog.resolve(query)
    print(result.publication.id)
