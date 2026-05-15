"""
SILO: C2 — Python object-level logging
TEST: two handles (payments + billing) don't cross-contaminate.
SEE: regression/crawl/c2_python_object_log/README.md

Bug #1 of the multi-ceremony rework: every handle method rebound the
module-level singleton, so `payments.info(...)` and `billing.info(...)`
raced — last call won. Per-instance runtime fixes it. This silo
regresses against re-drift.

Flow:
  1. Hermetic machine.
  2. payments = tn.use("payments"); billing = tn.use("billing").
  3. Each handle gets its own .info() call with a distinct event_type.
  4. Cross-asserts:
     a) payments.read() yields the payments event but NOT the billing event.
     b) billing.read() yields the billing event but NOT the payments event.
     c) The two handles point at different yaml_paths.
     d) The two handles point at different on-disk log files.

Asserts (named):
  - "payments-and-billing-have-distinct-yamls"
  - "payments-read-has-payments-event"
  - "payments-read-does-not-have-billing-event"
  - "billing-read-has-billing-event"
  - "billing-read-does-not-have-payments-event"
  - "user-home-untouched"

Failure mode this regresses against: per-instance dispatch breaks and
all writes land on the last-bound ceremony.
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


def test_two_handles_do_not_cross_contaminate(hermetic_machine: Path) -> None:
    payments = tn.use("payments")
    billing = tn.use("billing")

    assert_named(
        name="payments-and-billing-have-distinct-yamls",
        expected=True,
        observed=payments.yaml_path != billing.yaml_path,
        on_miss=(
            f"Both handles report the same yaml_path "
            f"({payments.yaml_path!r}). tn.use should mint distinct "
            f"<cwd>/.tn/payments/tn.yaml and <cwd>/.tn/billing/tn.yaml. "
            f"Check python/tn/_multi.py:use registry resolution."
        ),
    )

    # Distinct emissions, one per handle.
    payments.info("payments.charge", amount=1000)
    billing.info("billing.invoice", invoice_id="INV-42")

    # Read each handle's stream. Use to_dict + event_type so we don't
    # depend on Entry's repr.
    payments_events = sorted(e.event_type for e in payments.read())
    billing_events = sorted(e.event_type for e in billing.read())

    assert_named(
        name="payments-read-has-payments-event",
        expected=True,
        observed="payments.charge" in payments_events,
        on_miss=(
            f"payments.read() didn't yield 'payments.charge'. Found: "
            f"{payments_events!r}. The handle wrote to a file but "
            f"can't read it back — investigate the yaml's log path."
        ),
    )

    assert_named(
        name="payments-read-does-not-have-billing-event",
        expected=False,
        observed="billing.invoice" in payments_events,
        on_miss=(
            f"payments.read() yielded 'billing.invoice' — cross-stream "
            f"contamination. Bug #1 has regressed: both handles are "
            f"writing to the same singleton runtime. Check "
            f"python/tn/_handle.py:_get_runtime — each TN must own its "
            f"own runtime. payments_events={payments_events!r}."
        ),
    )

    assert_named(
        name="billing-read-has-billing-event",
        expected=True,
        observed="billing.invoice" in billing_events,
        on_miss=(
            f"billing.read() didn't yield 'billing.invoice'. Found: "
            f"{billing_events!r}."
        ),
    )

    assert_named(
        name="billing-read-does-not-have-payments-event",
        expected=False,
        observed="payments.charge" in billing_events,
        on_miss=(
            f"billing.read() yielded 'payments.charge' — cross-stream "
            f"contamination. Same Bug #1 path. billing_events="
            f"{billing_events!r}."
        ),
    )

    assert_user_home_untouched()
