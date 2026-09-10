"""Run with Python; every TN object operation executes in the native Rust SDK."""

import json

from tn import Session, UseContext

POLICY = """## finance.account
### instruction
Calculate account totals.
### use_for
Portfolio analysis.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"""


def run():
    with Session(POLICY, groups=["finance"], policy_id="portfolio.md") as session:
        policy = session.policy("finance.account")
        account = session.create_obj(
            {"rows": [{"quantity": 2, "unit_price": 1200}, {"quantity": 3, "unit_price": 500}]},
            policy, object_type="finance.account", group="finance",
        )
        source = account.release(
            use=UseContext("data.service", "portfolio_analysis", "supply_account"),
            to="analytics", decide=lambda context: True,
        )

        working = session.receive(
            source,
            use=UseContext("analytics", "portfolio_analysis", "calculate_total"),
            groups=["finance"],
            decide=lambda context: (
                context.object.id == source.id
                and context.writer == session.did
                and all(item.fields == policy.fields for item in context.policies)
            ),
        )
        total = sum(row["quantity"] * row["unit_price"] for row in working.data["rows"])
        working.groups["finance"] = {"total_minor_units": total}
        released = working.release(
            use=UseContext("analytics", "portfolio_analysis", "release_total"),
            object_type="finance.total", to="reporting",
            decide=lambda context: all(item.fields == policy.fields for item in context.policies),
        )
        return {
            "source_id": source.id, "source_wire": source.wire,
            "output_id": released.id, "output_wire": released.wire,
            "total_minor_units": total,
        }


if __name__ == "__main__":
    print(json.dumps(run()))
