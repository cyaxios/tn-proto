"""A small enterprise consumer exercises mutable release at a real SQLite commit."""

import importlib.util
from pathlib import Path

import pytest
import tn


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "governed_outbox.py"
spec = importlib.util.spec_from_file_location("governed_outbox_example", EXAMPLE)
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


@pytest.fixture
def session():
    with tn.Session(example.POLICY) as value:
        yield value


def source(session, sale_id="sale-1", amount=10):
    return session.create_obj(
        {"sale_id": sale_id, "amount": amount},
        session.policy("finance.sale"),
        object_type="finance.sale",
    ).snapshot


def service(session, path):
    return example.CreditService(session, path, session.did, session.policy("finance.sale"))


def test_committed_reply_is_reused_after_service_restart(session, tmp_path):
    request = source(session)
    path = tmp_path / "credits.sqlite"
    with service(session, path) as receiver:
        reply = receiver.apply(request)
        assert receiver.apply(request) == reply
        assert receiver.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0] == 1
    with service(session, path) as restarted:
        assert restarted.apply(request) == reply
        assert restarted.db.execute("SELECT wire FROM outbox").fetchone()[0] == reply
    received = session.receive(reply, purpose="inspect", decide=lambda c: True)
    assert received.data == {"sale_id": "sale-1", "credited": 10}
    assert received.governance.sources[0].references(request)


def test_failed_commit_rolls_back_inbox_effect_and_released_outbox(session, tmp_path):
    request = source(session)
    with service(session, tmp_path / "credits.sqlite") as receiver:

        def fail():
            raise RuntimeError("simulated pre-commit failure")

        with pytest.raises(RuntimeError, match="pre-commit"):
            receiver.apply(request, before_commit=fail)
        for table in ("inbox", "effects", "outbox"):
            assert receiver.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        assert receiver.apply(request)
        assert receiver.db.execute("SELECT credited FROM effects").fetchone()[0] == 10


def test_new_object_for_existing_business_id_follows_conflict_rule(session, tmp_path):
    first, conflicting = source(session), source(session, amount=50)
    assert first.id != conflicting.id
    with service(session, tmp_path / "credits.sqlite") as receiver:
        reply = receiver.apply(first)
        with pytest.raises(ValueError, match="sale ID"):
            receiver.apply(conflicting)
        assert receiver.apply(first) == reply
        assert receiver.db.execute("SELECT credited FROM effects").fetchone()[0] == 10
        assert receiver.db.execute("SELECT COUNT(*) FROM inbox").fetchone()[0] == 1
