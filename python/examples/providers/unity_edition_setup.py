"""Provision and resolve one signed invoice edition stored in a Unity volume."""
import argparse
import json
from pathlib import Path
import sys

import tn
from tn.providers import (
    CatalogEntry, FileKeyStore, FileRegisters, InputRule, PolicyDirectory,
    PolicyRequest, Providers, WorkflowPolicy, WorkflowRequest,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from providers.unity_client import read_publication, volume_directory


APPLICATION = "invoice-service"
DATASET, EDITION = "invoices", "closing"
SOURCE_TYPE, REPORT_TYPE = "invoice.batch", "invoice.total"
READ_USE = tn.UseContext(APPLICATION, "accounting", "total")
WRITE_USE = tn.UseContext(APPLICATION, "reporting", "publish")
METADATA_USE = tn.UseContext(APPLICATION, "catalog", "inspect")
POLICY = """## invoice.batch
### instruction
Total the supplied invoice amounts and retain the selected edition.
### use_for
Accounting and reporting.
### do_not_use_for
Unapproved uses.
### consequences
Review the operation.
### on_violation_or_error
Refuse the operation.
"""


def configure(workspace):
    """Reopen the existing enrollment and configure the two business operations."""
    private = Path(workspace).resolve() / "private"
    store = FileKeyStore.open(private / "keys/keystore.json")
    identity = store.resolve(APPLICATION)
    administration = tn.Governance.from_markdown(
        identity.did, (private / "agents.md").read_text(encoding="utf-8"),
        "agents.md", SOURCE_TYPE,
    )
    rules = PolicyDirectory()
    rules.trust(identity)
    for use in (READ_USE, WRITE_USE):
        rules.add_policy(PolicyRequest(SOURCE_TYPE, use), administration)
    workflow = WorkflowRequest(READ_USE, WRITE_USE)
    rules.add_workflow(workflow, WorkflowPolicy(
        [InputRule(["default"], object_type=SOURCE_TYPE)], REPORT_TYPE, "invoice-records",
    ))
    providers = Providers(store, store, rules, registers=FileRegisters(tn.ObjectRegisters()))
    return providers.session(APPLICATION, workflows=[workflow]), rules, administration


def open_metadata(session, publication, group, administration):
    """Accept the trusted writer, exact administration contract, and metadata use."""
    def accepted(context):
        return (
            context.writer == session.did and context.use_context == METADATA_USE
            and context.groups == [group] and len(context.policies) == 1
            and context.policies[0].matches_contract(administration)
        )

    admitted = session.governance(publication).accept(
        use=METADATA_USE, groups=[group], decide=accepted,
    )
    return session.open(admitted, [group])


def accepted_revision(session, publication, administration):
    revision = tn.PolicyRevision.from_opened(
        open_metadata(session, publication, "policy_revision", administration),
    )
    dag = tn.PolicyDag()
    dag.admit(revision, lambda record, parent: record.writer == session.did and parent is None)
    contract = dag.select(revision.id, SOURCE_TYPE, lambda record: record.writer == session.did)
    return dag, revision, contract


def approve_contract(rules, contract):
    for use in (READ_USE, WRITE_USE):
        rules.approve_contract(PolicyRequest(SOURCE_TYPE, use), contract)


def prepare(workspace) -> str:
    """Create a new private enrollment and three exact shared publications."""
    workspace = Path(workspace).expanduser().resolve()
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    private, publications = workspace / "private", workspace / "publications"
    private.mkdir(mode=0o700)
    publications.mkdir()
    FileKeyStore.create(private / "keys/keystore.json", APPLICATION,
                        ["default", "policy_revision", "dataset_edition"])
    (private / "agents.md").write_text(POLICY, encoding="utf-8")
    session, rules, administration = configure(workspace)
    with session:
        revision_wire = session.seal(tn.PolicyRevisionDraft.from_markdown(
            session.did, POLICY, "agents.md", SOURCE_TYPE, SOURCE_TYPE,
        ).into_draft(administration))
        dag, revision, contract = accepted_revision(session, revision_wire, administration)
        approve_contract(rules, contract)
        data = session.create({"amounts": [12, 18, 5]}, contract)
        source = data.seal(use=WRITE_USE, to="accounting", object_type=SOURCE_TYPE,
                           decide=rules.release)
        edition_wire = session.seal(tn.DatasetEditionDraft(
            DATASET, EDITION, source, ["default"], [tn.ContractBinding(revision.id, SOURCE_TYPE)],
            [READ_USE], contract.policy_ref, [],
        ).into_draft(administration))
        for name, publication in (("source", source), ("revision", revision_wire), ("edition", edition_wire)):
            publication.write(publications / f"{name}.tn")
        expected = {
            "dataset": DATASET, "edition": EDITION, "revision_id": revision.id,
            "record_id": edition_wire.id, "source_id": source.id,
        }
        (private / "expected-edition.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    return publications.as_uri()


def resolve(workspace, session, rules, administration, *, url, volume, use=READ_USE):
    """Locate bytes through Unity; native admission selects their exact edition."""
    workspace = Path(workspace).expanduser().resolve()
    expected = json.loads((workspace / "private/expected-edition.json").read_text(encoding="utf-8"))
    directory = volume_directory(url, volume, workspace / "publications")
    revision_wire = read_publication(directory, "revision.tn", expected["revision_id"])
    dag, revision, contract = accepted_revision(session, revision_wire, administration)
    edition_wire = read_publication(directory, "edition.tn", expected["record_id"])
    record = tn.DatasetEdition.from_opened(
        open_metadata(session, edition_wire, "dataset_edition", administration),
    )
    catalog = tn.DatasetCatalog()
    catalog.admit(record, dag, lambda candidate: candidate.writer == session.did)
    selection = catalog.select(expected["dataset"], expected["edition"], expected["record_id"], use)
    source = read_publication(directory, "source.tn", expected["source_id"])
    approve_contract(rules, contract)
    return CatalogEntry(source, selection)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    print(prepare(parser.parse_args().workspace))
