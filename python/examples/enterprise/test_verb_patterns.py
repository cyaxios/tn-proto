"""Execute every chapter excerpt against the installed Rust-backed SDK."""
import io
import sqlite3

import pytest
import tn
import verb_patterns as patterns
from verb_support import Approval, Edit, ObservationRequest, Outbox, Publications, QuoteSelection

from pattern_environment import POLICY, configured_example


@pytest.fixture
def app():
    session, work, policy = configured_example()
    with session:
        yield session, work, policy


def source(app, *, _group="result", _type=None, **fields):
    session, _, policy = app
    return session.create(fields, policy, group=_group, object_type=_type).snapshot


def result(app, publication):
    return app[1].receive(publication).get()


@pytest.fixture
def records(tmp_path):
    db = sqlite3.connect(tmp_path / "records.sqlite")
    yield Publications(db)
    db.close()


def test_01_review(app):
    value = source(app, total_minor=25000)
    report = patterns.approve(app[1], value, Approval(value.id, "client-7"), app[2])
    assert result(app, report)["recipient"] == "client-7"
    for approval in [Approval("another", "client-7"), Approval(value.id, "client-8")]:
        with pytest.raises((ValueError, tn.governed.UseDenied)):
            patterns.approve(app[1], value, approval, app[2])


def test_02_reply(app, records):
    valuation = source(app, total_minor=25000)
    request = source(app, request_id="request-7", valuation_id=valuation.id)
    first = patterns.reply(app[1], request, valuation, records)
    assert patterns.reply(app[1], request, valuation, records).forward() == first.forward()
    with pytest.raises(ValueError):
        patterns.reply(app[1], source(app, request_id="request-7", valuation_id=valuation.id), valuation, records)


def test_03_subscription(app, records):
    one = source(app, _group="prices", _type="market.prices", sequence=1, previous=None, price_minor=12500)
    holding = source(app, _group="holdings", _type="client.holdings", quantity=2)
    output = patterns.consume(app[1], one, holding, None, lambda row, pos: row["price_minor"] * pos["quantity"])
    records.commit("head", one, output, "accepted")
    previous = records.get("head")
    assert patterns.consume(app[1], one, holding, previous, lambda *_: pytest.fail("duplicate recalculated")).forward() == output.forward()
    two = source(app, _group="prices", _type="market.prices", sequence=2, previous=one.id, price_minor=13000)
    assert result(app, patterns.consume(app[1], two, holding, previous, lambda r, p: r["price_minor"] * p["quantity"]))["total_minor"] == 26000
    with pytest.raises(ValueError):
        patterns.consume(app[1], source(app, _group="prices", _type="market.prices", sequence=3, previous=one.id), holding, previous, lambda *_: 0)


def test_04_saga(app):
    pending = source(app, saga="s7", report="r7", state="pending")
    declined = source(app, saga="s7", report="r7", approved=False)
    output = patterns.cancel(app[1], pending, declined)
    assert result(app, output)["state"] == "cancelled"
    assert len(app[0].governance(output).governance.sources) == 2
    with pytest.raises(ValueError):
        patterns.cancel(app[1], pending, source(app, saga="s7", report="r8", approved=False))


def test_05_outbox_and_inbox(app, records, tmp_path):
    connection = sqlite3.connect(tmp_path / "outbox.sqlite")
    outbox = Outbox(connection)
    message = source(app, message_id="message-7", total_minor=25000)
    patterns.enqueue(app[1], message, outbox)
    for _ in range(2):
        name, pending = outbox.pending()[0]
        patterns.deliver(app[1], pending, records)
    assert records.db.execute("SELECT count(*) FROM accepted").fetchone()[0] == 1
    assert outbox.pending()[0][1].forward() == message.forward()
    with pytest.raises(ValueError):
        patterns.deliver(app[1], source(app, message_id="message-7", total_minor=26000), records)
    outbox.acknowledge(name)
    assert outbox.pending() == []
    connection.close()


def test_05_atomic_outbox_rollback(app, tmp_path):
    connection = sqlite3.connect(tmp_path / "rollback.sqlite")
    outbox = Outbox(connection)
    connection.execute("CREATE TRIGGER refuse_pending BEFORE INSERT ON pending BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        patterns.enqueue(app[1], source(app, message_id="message-7"), outbox)
    assert connection.execute("SELECT count(*) FROM publication").fetchone()[0] == 0
    connection.close()


def test_06_projection(app):
    one = source(app, previous=None, delta=1, account="account-7", instrument="ALPHA")
    two = source(app, previous=one.id, delta=1, account="account-7", instrument="ALPHA")
    assert result(app, patterns.project(app[1], [one, two], two.id))["quantity"] == 2
    with pytest.raises(ValueError):
        patterns.project(app[1], [one], two.id)


def test_07_view(app):
    price = source(app, _group="prices", _type="market.prices", instrument="ALPHA", price_minor=12500, as_of="2026-09-08", depth=[1, 2])
    holding = source(app, _group="holdings", _type="client.holdings", instrument="ALPHA", quantity=2, as_of="2026-09-08")
    body = result(app, patterns.analyst_view(app[1], price, holding))
    assert body == {"instrument": "ALPHA", "as_of": "2026-09-08", "price_minor": 12500, "quantity": 2}
    malformed = source(app, _group="prices", _type="market.prices", instrument="ALPHA", price_minor="12500", as_of="2026-09-08")
    with pytest.raises(ValueError, match="integer minor units"):
        patterns.analyst_view(app[1], malformed, holding)


def test_08_aggregation(app):
    holding = source(app, _group="holdings", _type="client.holdings", quantities={"ALPHA": 2, "BETA": 3}, as_of="2026-09-08")
    quotes = [source(app, _group="prices", _type="market.prices", instrument="ALPHA", price_minor=12500, as_of="2026-09-08", currency="USD"), source(app, _group="prices", _type="market.prices", instrument="BETA", price_minor=8000, as_of="2026-09-08", currency="USD")]
    selected = QuoteSelection(tuple(q.id for q in quotes), ("ALPHA", "BETA"), "2026-09-08")
    assert result(app, patterns.aggregate(app[1], holding, quotes, selected))["total_minor"] == 49000
    with pytest.raises(ValueError):
        patterns.aggregate(app[1], holding, quotes[:1], selected)


def test_09_pipeline(app):
    batch = source(app, _group="prices", _type="market.prices", complete=True, rows=[{"instrument": "ALPHA", "unit": "USD-dollar", "amount": "125.00"}])
    assert result(app, patterns.normalize(app[1], batch, ("ALPHA",)))["rows"][0]["price_minor"] == 12500
    with pytest.raises(ValueError):
        patterns.normalize(app[1], batch, ("ALPHA", "BETA"))
    incomplete = source(app, _group="prices", _type="market.prices", complete=False, rows=[{"instrument": "ALPHA", "unit": "USD-dollar", "amount": "125.00"}])
    with pytest.raises(ValueError, match="not complete"):
        patterns.normalize(app[1], incomplete, ("ALPHA",))


def test_11_repository(app, records):
    original = source(app, report_id="report-7", account="account-7", revision=1, title="Initial")
    records.commit("report-7", original, original, "created")
    output = patterns.edit(app[1], original, Edit("report-7", "account-7", "Reviewed"), records)
    assert result(app, output)["revision"] == 2
    with pytest.raises(ValueError):
        patterns.edit(app[1], original, Edit("report-7", "account-7", "Stale"), records)


def test_12_archive(app, records):
    approved = source(app, message_id="message-7", approved=True, text="Value is USD 250.00")
    patterns.archive(app[1], approved, records)
    assert records.get("message-7").effect == "Value is USD 250.00"
    with pytest.raises(ValueError):
        patterns.archive(app[1], source(app, message_id="message-8", approved=False, text="Unapproved"), records)


def test_13_cache(app):
    cached = source(app, instrument="ALPHA", as_of="2026-09-08")
    request = ObservationRequest(cached.id, "ALPHA", "2026-09-08")
    assert patterns.cached_observation(app[1], cached, request).get("instrument") == "ALPHA"
    with pytest.raises(ValueError):
        patterns.cached_observation(app[1], cached, ObservationRequest(cached.id, "BETA", request.as_of))


def test_14_checkpoint(app, records):
    approved = source(app, total_minor=25000)
    checkpoint = source(app, job_id="job-7", approved_id=approved.id, state="prepared")
    records.commit("job-7", checkpoint, checkpoint, "prepared")
    output = patterns.finish(app[1], approved, checkpoint, records)
    assert result(app, output)["state"] == "completed"
    assert patterns.finish(app[1], approved, checkpoint, records).forward() == output.forward()


def test_15_migration(app, records):
    request = source(app, operation_id="operation-7", price_minor=12500)
    first = patterns.execute(app[1], request, records, lambda price: price + price)
    repeated = patterns.execute(app[1], request, records, lambda _: pytest.fail("new service should recover accepted reply"))
    assert repeated.forward() == first.forward()


def test_delivery_refuses_foreign_writer(app, records):
    with tn.Session(POLICY, groups=["result"]) as other:
        foreign = other.create({"message_id": "message-7"}, other.policy("example.input"), group="result").snapshot
        with pytest.raises(tn.governed.GovernedError):
            patterns.deliver(app[1], foreign, records)
    assert records.db.execute("SELECT count(*) FROM accepted").fetchone()[0] == 0


from verb_edition_fixture import edition_fixture, approved_use


def test_10_real_dataset_selection(edition_fixture):
    session, dag, catalog, entries = edition_fixture
    session.configure_receive(use=approved_use(), groups=["finance"], decide=lambda c: c.writer == session.did and c.object_type == "market.prices")
    session.configure_release(use=approved_use(), to="analytics", object_type="market.prices", decide=lambda _: True)
    work = session.workflow(receive="portfolio_analysis", release="portfolio_analysis")
    _, publication, _, selection = entries[0]
    data = patterns.receive_edition(work, publication, selection)
    assert data.get("last_price") == 100
    assert data.dataset_bindings == [selection.binding]
    with pytest.raises(ValueError):
        patterns.receive_edition(work, entries[1][1], selection)
