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
def edition_fixture():
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
            draft = g.DatasetEditionDraft(
                "market.prices", edition, source, ["finance"], [contract],
                [approved_use(), downstream_use()], "grant:approved", [],
            )
            record_obj = session.seal(draft.into_draft(administration))
            record = g.DatasetEdition.from_opened(open_metadata(session, record_obj, "dataset_edition"))
            catalog.admit(record, dag, lambda item: item.writer == session.did)
            selection = catalog.select("market.prices", edition, record.id, approved_use())
            entries.append((revision, source, record, selection))
        yield session, dag, catalog, entries
