"""Executable chapter excerpts using the fifteen TN verbs.

Workflows and storage are constructed by application startup. Pure calculation
functions receive business values; they do not receive a signer or store.
"""
from decimal import Decimal
import tn
from verb_support import Approval, Edit, ObservationRequest, QuoteSelection


# book:01:start
def approve(work, valuation, approval: Approval, publication_policy):
    report = work.receive(valuation)
    if valuation.id != approval.publication_id:
        raise ValueError("approval names a different valuation")
    work.attach(report, publication_policy)
    report.set("recipient", approval.recipient)
    report.select(["result"])
    return work.release(report)
# book:01:end


# book:02:start
def reply(work, request, valuation, replies):
    data = work.receive(request)
    request_id = data.get("request_id")
    accepted = replies.get(request_id)
    if accepted is not None:
        if accepted.source.forward() != request.forward():
            raise ValueError("request identity conflicts")
        return accepted.publication
    value = work.receive(valuation)
    if data.get("valuation_id") != valuation.id:
        raise ValueError("request selects a different valuation")
    data.include(value)
    data.set("total_minor", value.get("total_minor"))
    response = work.release(data)
    return replies.commit(request_id, request, response, "valuation reply")
# book:02:end


# book:03:start
def consume(work, event, holding, previous, calculate):
    data = work.receive(event)
    position = work.receive(holding)
    sequence = data.get("sequence")
    if previous is not None:
        if event.forward() == previous.source.forward():
            accepted = work.receive(previous.publication)
            sources = accepted.inspect().governance.sources
            if len(sources) != 2 or sources[1].object_id != holding.id:
                raise ValueError("duplicate event changed its position input")
            return previous.publication
        prior = work.receive(previous.source)
        if (sequence != prior.get("sequence") + 1
                or data.get("previous") != previous.source.id):
            raise ValueError("event does not follow the subscriber's accepted head")
    elif sequence != 1 or data.get("previous") is not None:
        raise ValueError("subscriber requires the first event")
    total = calculate(data.get(), position.get())
    data.include(position)
    data.set(None, {"sequence": sequence, "total_minor": total}, group="result")
    data.select(["result"])
    return work.release(data)
# book:03:end


# book:04:start
def cancel(work, reservation, review):
    pending = work.receive(reservation)
    decision = work.receive(review)
    if pending.get("state") != "pending" or decision.get("approved") is not False:
        raise ValueError("cancellation requires a pending reservation and declined review")
    for field in ("saga", "report"):
        if pending.get(field) != decision.get(field):
            raise ValueError("review identifies another reservation")
    pending.include(decision)
    pending.set("state", "cancelled")
    return work.release(pending)
# book:04:end


# book:05:start
def enqueue(work, approved, outbox):
    message = work.receive(approved)
    outbox.commit(message.get("message_id"), approved)


def deliver(work, publication, inbox):
    message = work.receive(publication)
    return inbox.commit(message.get("message_id"), publication, publication, "accepted delivery")
# book:05:end


# book:06:start
def project(work, events, expected_head):
    combined, previous, quantity = None, None, 0
    scope, count = None, 0
    for event in events:
        change = work.receive(event)
        if change.get("previous") != previous:
            raise ValueError("position history is incomplete or out of order")
        current_scope = (change.get("account"), change.get("instrument"))
        if scope is not None and current_scope != scope:
            raise ValueError("position history changes account or instrument")
        scope = current_scope
        delta = change.get("delta")
        if type(delta) is not int or not 0 <= quantity + delta <= 2**64 - 1:
            raise ValueError("invalid position quantity")
        quantity += delta
        count += 1
        if combined is None:
            combined = change
        else:
            combined.include(change)
        previous = event.id
    if combined is None or previous != expected_head:
        raise ValueError("position history does not reach the requested head")
    combined.set("quantity", quantity)
    combined.set("head", expected_head)
    combined.set("accepted_changes", count)
    combined.select(["result"], fields={"result": ["account", "instrument", "quantity", "head", "accepted_changes"]})
    return work.release(combined)
# book:06:end


# book:07:start
def analyst_view(work, price, holding):
    view = work.receive(price)
    position = work.receive(holding)
    if view.get("instrument") != position.get("instrument"):
        raise ValueError("price and position refer to different instruments")
    if view.get("as_of") != position.get("as_of"):
        raise ValueError("price and position have different valuation times")
    if type(view.get("price_minor")) is not int or view.get("price_minor") <= 0:
        raise ValueError("price must be positive integer minor units")
    if type(position.get("quantity")) is not int or position.get("quantity") < 0:
        raise ValueError("quantity must be a nonnegative integer")
    view.include(position)
    view.set(None, {
        "instrument": view.get("instrument"), "as_of": view.get("as_of"),
        "price_minor": view.get("price_minor"), "quantity": position.get("quantity"),
    }, group="result")
    view.select(["result"])
    return work.release(view)
# book:07:end


# book:08:start
def aggregate(work, holdings, quotes, selection: QuoteSelection):
    if (len(quotes) != len(selection.publication_ids)
            or {q.id for q in quotes} != set(selection.publication_ids)):
        raise ValueError("delivered quotes differ from the independently selected publications")
    data = work.receive(holdings)
    quantities = data.get("quantities")
    if data.get("as_of") != selection.as_of:
        raise ValueError("holding time differs from the selected valuation")
    total, seen = 0, set()
    for quote in quotes:
        price = work.receive(quote)
        instrument = price.get("instrument")
        if price.get("as_of") != selection.as_of or price.get("currency") != "USD":
            raise ValueError("price has the wrong time or currency")
        if instrument in seen or instrument not in quantities:
            raise ValueError("duplicate or unexpected instrument")
        seen.add(instrument)
        total += quantities[instrument] * price.get("price_minor")
        data.include(price)
    if seen != set(selection.instruments) or seen != set(quantities):
        raise ValueError("required prices are missing")
    data.set(None, {"total_minor": total, "currency": "USD"}, group="result")
    data.select(["result"])
    return work.release(data)
# book:08:end


# book:09:start
def normalize(work, batch, required_instruments):
    data = work.receive(batch)
    if data.get("complete") is not True:
        raise ValueError("source batch is not complete")
    normalized, seen = [], set()
    for row in data.get("rows"):
        instrument = row["instrument"]
        if instrument in seen or row["unit"] != "USD-dollar":
            raise ValueError("duplicate instrument or unsupported price unit")
        seen.add(instrument)
        minor = Decimal(row["amount"]) * 100
        if not minor.is_finite() or minor != minor.to_integral_value() or minor <= 0:
            raise ValueError("price must be an exact positive cent amount")
        normalized.append({"instrument": instrument, "price_minor": int(minor)})
    if seen != set(required_instruments):
        raise ValueError("batch differs from the required instrument set")
    data.set(None, {"rows": normalized, "complete": True}, group="result")
    data.select(["result"])
    return work.release(data)
# book:09:end


# book:10:start
def receive_edition(work, publication, selection: tn.DatasetSelection):
    return work.receive(publication, selection=selection)
# book:10:end


# book:11:start
def edit(work, prior, change: Edit, repository):
    data = work.receive(prior)
    if data.get("report_id") != change.report_id or data.get("account") != change.account:
        raise ValueError("edit identifies another report or account")
    data.set("title", change.title)
    data.set("revision", data.get("revision") + 1)
    output = work.release(data)
    return repository.replace(change.report_id, prior, output, "report revision")
# book:11:end


# book:12:start
def archive(work, approved, archive_records):
    communication = work.receive(approved)
    if communication.get("approved") is not True:
        raise ValueError("archive requires the approved communication")
    return archive_records.commit(
        communication.get("message_id"), approved, approved, communication.get("text")
    )
# book:12:end


# book:13:start
def cached_observation(work, cached, request: ObservationRequest):
    if cached.id != request.publication_id:
        raise ValueError("cache returned a different publication")
    data = work.receive(cached)
    if data.get("instrument") != request.instrument or data.get("as_of") != request.as_of:
        raise ValueError("observation does not answer this request")
    return data
# book:13:end


# book:14:start
def finish(work, approved, checkpoint, jobs):
    data = work.receive(approved)
    stage = work.receive(checkpoint)
    if (stage.get("state") != "prepared"
            or stage.get("approved_id") != approved.id):
        raise ValueError("checkpoint does not prepare this publication")
    accepted = jobs.get(stage.get("job_id"))
    if accepted is not None and accepted.effect == "completed":
        if accepted.source.forward() != checkpoint.forward():
            raise ValueError("job completed from another checkpoint")
        work.receive(accepted.publication)
        return accepted.publication
    data.include(stage)
    data.set("state", "completed")
    output = work.release(data)
    return jobs.replace(stage.get("job_id"), checkpoint, output, "completed")
# book:14:end


# book:15:start
def execute(work, request, accepted_replies, calculate):
    data = work.receive(request)
    operation_id = data.get("operation_id")
    accepted = accepted_replies.get(operation_id)
    if accepted is not None:
        if accepted.source.forward() != request.forward():
            raise ValueError("operation identity belongs to another request")
        return accepted.publication
    data.set("total_minor", calculate(data.get("price_minor")))
    output = work.release(data)
    return accepted_replies.commit(operation_id, request, output, "valuation")
# book:15:end
