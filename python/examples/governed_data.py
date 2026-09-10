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
    with Session(POLICY, groups=["default", "identities"]) as session:
        policy = session.policy("finance.account")
        session.require_groups(["default"])

        # The origin attaches policy and creates the first signed snapshot.
        account = session.create_obj_with_groups(
            {"default": {"balance": 1200}, "identities": {"owner": "Ada"}},
            policy, object_type="finance.account",
        )
        sealed = account.snapshot
        assert len(account.history) == 1 and not account.has_unreleased_changes

        def admit(context: AdmissionContext) -> bool:
            return (
                context.writer == session.did
                and context.object_type == "finance.account"
                and context.purpose == "analysis"
                and len(context.policies) == 1
                and all(contract.matches_contract(policy) and contract.fields == policy.fields
                        for contract in context.policies)
            )

        # A receiving adapter admits the object before opening its data.
        working = session.receive(sealed, purpose="analysis", decide=admit)
        working.data["total"] = working.data.pop("balance")
        working.retain_groups(["default"])
        assert working.has_unreleased_changes

        def allow_release(context: ReleaseContext) -> bool:
            return (
                context.destination == "internal-reporting"
                and context.purpose == "analysis"
                and context.object_type == "finance.report"
                and context.writer == session.did
                and set(context.data.groups) == {"default"}
                and set(context.data.groups["default"]) == {"total"}
                and context.data.hidden_groups == []
                and len(context.policies) == 1
                and all(contract.matches_contract(policy) and contract.fields == policy.fields
                        for contract in context.policies)
                and len(context.sources) == 1
                and context.sources[0].references_with_policy(sealed, policy)
                and context.sources[0].groups == ["default"]
                and context.sources[0].operation == "analysis"
            )

        report = working.release(
            to="internal-reporting",
            purpose="analysis",
            object_type="finance.report",
            decide=allow_release,
        )
        # Persist these exact signed bytes in the application's outbox for retry.
        outbox_payload = bytes(report)
        assert not working.has_unreleased_changes
        print(f"Released {report.object_type}: {report.id}")
        print(f"Retained {len(working.history)} signed versions; {len(outbox_payload)} wire bytes")


if __name__ == "__main__":
    main()
