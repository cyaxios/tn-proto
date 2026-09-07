"""Run with the built SDK: python python/examples/governed_data.py.

The local policy text stands in for a policy bundle resolved by the origin
service. Production adapters supply their authority and policy decisions.
"""

from tn import Session
from tn.governed import AdmissionContext, ReleaseContext

POLICY = """---
version: 1
schema: tn-agents-policy@v1
---
## finance.account
### instruction
Prepare an aggregate finance report.
### use_for
Internal analysis.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"""


def main() -> None:
    with Session(POLICY) as session:
        policy = session.policy("finance.account")
        session.require_groups(["default"])

        # The origin attaches policy and creates the first signed snapshot.
        account = session.create_obj({"balance": 1200}, policy, object_type="finance.account")
        sealed = account.snapshot

        def admit(context: AdmissionContext) -> bool:
            return (
                context.writer == session.did
                and context.object_type == "finance.account"
                and context.purpose == "analysis"
                and all(contract.matches_contract(policy) for contract in context.policies)
            )

        # A receiving adapter admits the object before opening its data.
        working = session.receive(sealed, purpose="analysis", decide=admit)
        working.data["total"] = working.data.pop("balance")

        def allow_release(context: ReleaseContext) -> bool:
            return (
                context.destination == "internal-reporting"
                and context.purpose == "analysis"
                and context.object_type == "finance.report"
                and set(context.data.groups["default"]) == {"total"}
                and all(contract.matches_contract(policy) for contract in context.policies)
            )

        report = working.release(
            to="internal-reporting",
            purpose="analysis",
            object_type="finance.report",
            decide=allow_release,
        )
        # Persist these exact signed bytes in the application's outbox for retry.
        outbox_payload = bytes(report)
        print(f"Released {report.object_type}: {report.id}")
        print(f"Retained {len(working.history)} signed versions; {len(outbox_payload)} wire bytes")


if __name__ == "__main__":
    main()
