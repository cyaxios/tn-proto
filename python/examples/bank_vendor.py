"""Run: python python/examples/bank_vendor.py

Startup provisions separate bank/vendor identities and assigned native capabilities.
The vendor opens amounts only, then publishes an aggregate with both input sources.
"""
from contextlib import contextmanager
from dataclasses import dataclass

import tn
from tn.providers import LocalIdentity, LocalKeys, PolicyDirectory, PolicyRequest, Providers


BANK_POLICY = """## bank.batch
### instruction
Calculate aggregate totals from amounts; keep customer identity confidential.
### use_for
Approved aggregate reporting.
### do_not_use_for
Marketing or identifying customers.
### consequences
Suspend access and review the disclosure.
### on_violation_or_error
Refuse processing and publication.
"""

REPORT_POLICY = """## vendor.report
### instruction
Publish only an aggregate; preserve the bank contract and input references.
### use_for
Bank aggregate reports.
### do_not_use_for
Individual transactions or customer disclosure.
### consequences
Withdraw the report and review the disclosure.
### on_violation_or_error
Refuse publication.
"""


@dataclass
class Parties:
    bank: tn.Session
    vendor: tn.Session
    bank_contract: tn.Governance
    report_contract: tn.Governance


def _contracts_match(actual, *expected):
    return len(actual) == len(expected) and all(
        any(policy.matches_contract(wanted) for policy in actual)
        for wanted in expected
    )


@contextmanager
def configured():
    """Application startup. Local providers generate fresh keys for this example."""
    bank_identity, vendor_identity = LocalIdentity("bank"), LocalIdentity("vendor")
    bank_actor = bank_identity.resolve("bank")
    vendor_actor = vendor_identity.resolve("vendor")
    grants = LocalKeys(["amounts", "identity"])
    grants.assign(bank_actor, read=["amounts", "identity"],
                  publish=["amounts", "identity", "tn.agents"])
    # Governance reading is automatic; no identity capability is assigned to the vendor.
    grants.assign(vendor_actor, read=["amounts"], publish=["amounts", "tn.agents"])

    bank_contract = tn.Governance.from_markdown(
        bank_actor.did, BANK_POLICY, "bank-policy.md", "bank.batch"
    )
    report_contract = tn.Governance.from_markdown(
        vendor_actor.did, REPORT_POLICY, "vendor-policy.md", "vendor.report"
    )
    deliver = tn.UseContext("bank", "deliver", "publish")
    calculate = tn.UseContext("vendor", "aggregate", "calculate")
    report = tn.UseContext("vendor", "report", "publish")
    inspect = tn.UseContext("bank", "inspect-report", "read")
    contracts = PolicyDirectory()
    contracts.trust(vendor_actor)
    contracts.add_policy(PolicyRequest("vendor.report", report), report_contract)
    bank_provider = Providers(bank_identity, grants, contracts)
    vendor_provider = Providers(vendor_identity, grants, contracts)

    with bank_provider.session("bank", workflows=[]) as bank, \
            vendor_provider.session("vendor", workflows=[]) as vendor:
        def accept_input(context):
            return (
                context.writer == bank.did
                and context.object_type == "bank.batch"
                and context.use_context == calculate
                and context.groups == ["amounts"]
                and _contracts_match(context.policies, bank_contract)
            )

        bank.configure_release(
            use=deliver, to=vendor.did, object_type="bank.batch",
            decide=lambda c: (
                c.writer == bank.did and c.use_context == deliver
                and c.destination == vendor.did
                and set(c.data.groups) == {"amounts", "identity"}
                and _contracts_match(c.policies, bank_contract)
            ),
        )
        vendor.configure_receive(
            use=calculate, groups=["amounts"], object_type="bank.batch", decide=accept_input
        )
        # The same decision refuses a different purpose before any amounts are opened.
        vendor.configure_receive(
            use=tn.UseContext("vendor", "marketing", "calculate"),
            groups=["amounts"], object_type="bank.batch", decide=accept_input,
        )
        vendor.configure_release(
            use=report, to=bank.did, object_type="vendor.report",
            decide=lambda c: (
                c.writer == vendor.did and c.use_context == report
                and c.destination == bank.did
                and _contracts_match(c.policies, bank_contract, report_contract)
                and set(c.data.groups) == {"amounts"}
                and set(c.data.groups["amounts"]) == {"aggregate"}
                and type(c.data.groups["amounts"]["aggregate"]) is int
                and not c.data.hidden_groups
                and len(c.sources) == 2
                and all(source.writer == bank.did for source in c.sources)
            ),
        )
        bank.configure_receive(
            use=inspect, groups=["amounts"], object_type="vendor.report",
            decide=lambda c: (
                c.writer == vendor.did and c.use_context == inspect
                and c.groups == ["amounts"]
                and _contracts_match(c.policies, bank_contract, report_contract)
            ),
        )
        yield Parties(bank, vendor, bank_contract, report_contract)


def publish_inputs(parties):
    """Bank application: publish two batches with separate encrypted identity groups."""
    publications = []
    for values, customers in [([12, 18], ["Alice", "Bob"]), ([5], ["Carol"])]:
        batch = parties.bank.create({"values": values}, parties.bank_contract, group="amounts")
        batch.set(None, {"customers": customers}, group="identity")
        publications.append(batch.release(purpose="deliver"))
    return tuple(publications)


def aggregate(parties, inputs):
    """Vendor application: business data is available only after successful receipt."""
    first = parties.vendor.receive(inputs[0].forward(), purpose="aggregate")
    second = parties.vendor.receive(inputs[1].forward(), purpose="aggregate")
    total = sum(first.get("values", group="amounts")) + sum(second.get("values", group="amounts"))
    first.include(second)
    first.set("aggregate", total, group="amounts")
    # Remove input values and the unopened identity ciphertext from the released object.
    first.select(["amounts"], fields={"amounts": ["aggregate"]})
    first.attach(parties.report_contract)
    return first.release(purpose="report")


def main():
    with configured() as parties:
        inputs = publish_inputs(parties)
        output = aggregate(parties, inputs)
        report = parties.bank.receive(output, purpose="inspect-report")
        # Even a permissive application decision cannot supply the missing identity key.
        try:
            parties.vendor.receive(
                inputs[0], use=tn.UseContext("vendor", "probe", "read"),
                groups=["identity"], decide=lambda _: True,
            )
        except tn.governed.NotEntitled:
            pass
        else:
            raise AssertionError("vendor unexpectedly opened customer identity")
        try:
            parties.vendor.receive(inputs[0], purpose="marketing")
        except tn.governed.UseDenied:
            pass
        else:
            raise AssertionError("unapproved use unexpectedly returned business data")
        print(f"Aggregate: {report.get('aggregate', group='amounts')}")
        print(f"Contracts: {len(report.policies)}")
        print(f"Sources: {len(report.governance.sources)}")
        print("Identity: unavailable")
        print("Denied use: no business data returned")


if __name__ == "__main__":
    main()
