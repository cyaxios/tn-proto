"""
SILO: C2 — Python object-level logging
TEST: tn.use(name) returns a handle that can info(...) and read() back its
      own entries.
SEE: regression/crawl/c2_python_object_log/README.md

Flow:
  1. Hermetic machine — no vault contact, TN_NO_LINK=1.
  2. t = tn.use("payments")
  3. t.info("payments.charge", amount=1000, currency="USD")
  4. list(t.read()) yields the entry.

Asserts (named):
  - "handle-is-tn-instance"
  - "handle-name-is-payments"
  - "handle-info-event-on-disk"
  - "handle-read-returns-entry"
  - "fields-preserved-amount"
  - "fields-preserved-currency"
  - "user-home-untouched"
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def test_handle_info_read_round_trip(hermetic_machine: Path) -> None:
    t = tn.use("payments")

    assert_named(
        name="handle-is-tn-instance",
        expected=True,
        observed=hasattr(t, "info") and hasattr(t, "read") and hasattr(t, "yaml_path"),
        on_miss=(
            f"tn.use('payments') returned {type(t).__name__!r} without "
            f"the expected handle methods. Check python/tn/_handle.py:TN "
            f"and python/tn/_multi.py:use's return type."
        ),
    )

    assert_named(
        name="handle-name-is-payments",
        expected="payments",
        observed=t.name,
        on_miss=(
            f"Handle reports name={t.name!r} after tn.use('payments'). "
            f"The name property in _handle.py:TN should echo the "
            f"registry key."
        ),
    )

    t.info("payments.charge", amount=1000, currency="USD")

    # Read the entry back via the handle.
    log = LogQuery(ceremony_path=t.yaml_path)
    env = log.assert_contains(
        name="handle-info-event-on-disk",
        where={"event_type": "payments.charge"},
        on_miss=(
            "t.info('payments.charge', ...) didn't produce an attested "
            "envelope under the payments ceremony. Check "
            "python/tn/_handle.py:_emit per-instance dispatch and the "
            "payments yaml's log path resolution."
        ),
    )

    # Also exercise the handle's own read() — must return the entry.
    entries = list(t.read())
    ours = next((e for e in entries if e.event_type == "payments.charge"), None)
    assert_named(
        name="handle-read-returns-entry",
        expected=True,
        observed=ours is not None,
        on_miss=(
            f"t.read() on the payments handle didn't yield the just-"
            f"written entry. Got {len(entries)} total entries. Check "
            f"python/tn/_handle.py:read — replay-surface gate or "
            f"singleton activation may be wrong."
        ),
    )
    assert ours is not None

    flat = ours.to_dict() if hasattr(ours, "to_dict") else dict(ours.fields)
    assert_named(
        name="fields-preserved-amount",
        expected=1000,
        observed=flat.get("amount"),
        on_miss="Field 'amount' came back wrong from t.read(). Canonical-encode round-trip in tn.canonical.",
    )
    assert_named(
        name="fields-preserved-currency",
        expected="USD",
        observed=flat.get("currency"),
        on_miss="Field 'currency' came back wrong.",
    )

    # Belt-and-suspenders cross-check: the on-disk envelope's event_type
    # matches what t.read() surfaced (proves the read isn't synthesizing
    # entries — it's parsing the same file).
    assert_named(
        name="handle-disk-event-matches-read-event",
        expected=ours.event_type,
        observed=env.get("event_type"),
        on_miss=(
            "The envelope LogQuery found on disk has a different "
            "event_type than the one t.read() returned. read() may be "
            "pulling from a different file than the handler is writing "
            "to — check ceremony.log_path resolution in the payments "
            "yaml."
        ),
    )

    assert_user_home_untouched()
