"""Mutable governed receipts with a SQLite inbox, business effect, and outbox.

Run: python python/examples/governed_outbox.py
The broker dispatcher sends committed outbox bytes and marks them sent afterward.
"""

import sqlite3
import tempfile
from collections.abc import Callable
from pathlib import Path

import tn
from tn.governed import AdmissionContext, ReleaseContext

POLICY = """## finance.sale
### instruction
Apply one credit per sale ID and return a receipt.
### use_for
Internal settlement.
### do_not_use_for
Duplicate credits or personal disclosure.
### consequences
Reconcile the settlement.
### on_violation_or_error
Refuse the conflicting operation.
"""


class CreditService:
    """One service owns its TN context and a local transaction boundary."""

    def __init__(self, session: tn.Session, path: Path, writer: str, policy: tn.Governance):
        self.session, self.accepted_writer, self.policy = session, writer, policy
        session.require_groups(["default"])
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS inbox (
                source_id TEXT PRIMARY KEY, wire BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS effects (
                sale_id TEXT PRIMARY KEY,
                source_id TEXT UNIQUE NOT NULL REFERENCES inbox(source_id),
                credited INTEGER NOT NULL,
                result_id TEXT UNIQUE NOT NULL,
                result_wire BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbox (
                result_id TEXT PRIMARY KEY REFERENCES effects(result_id),
                wire BLOB NOT NULL,
                sent INTEGER NOT NULL DEFAULT 0 CHECK(sent IN (0, 1))
            );
        """)

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.db.close()

    def admit(self, context: AdmissionContext) -> bool:
        return (
            context.writer == self.accepted_writer
            and context.object_type == "finance.sale"
            and context.purpose == "settle"
            and len(context.policies) == 1
            and context.governance.matches_contract(self.policy)
        )

    def admit_release(self, context: ReleaseContext) -> bool:
        return (
            context.destination == "settlement-client"
            and context.purpose == "receipt"
            and context.object_type == "finance.receipt"
            and all(p.matches_contract(self.policy) for p in context.policies)
            and set(context.data.groups["default"]) == {"sale_id", "credited"}
        )

    def apply(
        self, sealed: tn.GovernedObject, *, before_commit: Callable[[], None] | None = None
    ) -> bytes:
        data = self.session.receive(sealed, purpose="settle", decide=self.admit)
        sale_id, amount = data.data["sale_id"], data.data["amount"]
        if not isinstance(sale_id, str) or not sale_id or type(amount) is not int or amount <= 0:
            raise ValueError("sale requires a business ID and positive integer amount")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute(
                "SELECT source_id, result_wire FROM effects WHERE sale_id = ?", (sale_id,)
            ).fetchone()
            if prior:
                if prior[0] != sealed.id:
                    raise ValueError("sale ID already belongs to a different signed request")
                self.db.commit()
                return bytes(prior[1])

            data.data.clear()
            data.data.update({"sale_id": sale_id, "credited": amount})
            reply = data.release(
                to="settlement-client",
                purpose="receipt",
                object_type="finance.receipt",
                decide=self.admit_release,
            )
            wire = bytes(reply)
            self.db.execute("INSERT INTO inbox VALUES (?, ?)", (sealed.id, bytes(sealed)))
            self.db.execute(
                "INSERT INTO effects VALUES (?, ?, ?, ?, ?)",
                (sale_id, sealed.id, amount, reply.id, wire),
            )
            self.db.execute("INSERT INTO outbox(result_id, wire) VALUES (?, ?)", (reply.id, wire))
            if before_commit is not None:
                before_commit()
            self.db.commit()
            return wire
        except BaseException:
            self.db.rollback()
            raise


def main() -> None:
    # This local fixture holds origin/receiver access together. Deployed services
    # load their own persistent contexts with Session.from_config(...).
    with tempfile.TemporaryDirectory() as directory, tn.Session(POLICY) as session:
        policy = session.policy("finance.sale")
        request = session.create_obj(
            {"sale_id": "sale-1", "amount": 1200}, policy, object_type="finance.sale"
        ).snapshot
        database = Path(directory) / "settlement.sqlite"
        with CreditService(session, database, session.did, policy) as receiver:
            reply = receiver.apply(request)
        with CreditService(session, database, session.did, policy) as restarted:
            assert restarted.apply(request) == reply
            assert restarted.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0] == 1
        print("One committed credit; exact signed receipt reused after service restart.")


if __name__ == "__main__":
    main()
