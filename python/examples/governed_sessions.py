"""Two independent sessions carry a contract through computation and release."""

import tn
from tn.governed import GovernedReader, Session

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


def aggregate(
    wire: str,
    reader: GovernedReader,
    output_session: Session,
    trusted_writer: str,
    approved_policy: str,
) -> tn.GovernedObject:
    source = tn.GovernedObject.parse(wire)
    if source.writer != trusted_writer:
        raise ValueError("source writer is outside this application's accepted writers")

    # The application has approved this exact contract for this operation.
    view = reader.governance(source)
    admitted = view.authorize(
        "aggregate",
        lambda contract, operation: (
            operation == "aggregate"
            and contract.governed_by == trusted_writer
            and contract.policy_ref == approved_policy
        ),
    )
    opened = reader.open(admitted, ["observations"])
    counts = opened.groups["observations"]["counts"]
    if not isinstance(counts, list):
        raise ValueError("observations.counts must contain integer counts")
    total = 0
    for value in counts:
        if type(value) is not int:
            raise ValueError("observations.counts must contain integer counts")
        total += value

    # Derivation carries the source contract and records the admitted operation.
    result = output_session.seal(
        opened.derive("report.generated").group("reports", {"total": total})
    )
    assert opened.object.wire == wire
    assert opened.hidden_groups == ["identities"]
    return result


def main() -> None:
    with tn.Session(POLICY, groups=["observations", "identities"]) as producer:
        with tn.Session(POLICY, groups=["reports"]) as analyst:
            assert producer.did != analyst.did
            approved_policy = producer.policy("research.sample").policy_ref
            source = producer.seal(
                producer.draft("research.sample")
                .group("observations", {"counts": [12, 18]})
                .group("identities", {"names": ["Alice", "Bob"]})
            )
            reader = producer.reader(groups=["tn.agents", "observations"])
            result = aggregate(source.wire, reader, analyst, producer.did, approved_policy)
            contract = analyst.governance(result).governance
            assert result.writer == analyst.did
            assert contract.governed_by == producer.did
            assert contract.policy_ref == approved_policy
            lineage = contract.get("source_lineage")
            assert isinstance(lineage, list) and isinstance(lineage[0], dict)
            assert lineage[0]["object_id"] == source.id

            print("Two independent signing identities")
            print("Opened observations; identities stayed sealed")
            print("Aggregate: 30")
            print("Analyst signed the result with the source contract and lineage")


if __name__ == "__main__":
    main()
