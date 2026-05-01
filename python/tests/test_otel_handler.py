"""OpenTelemetry handler tests.

Runs without opentelemetry-api installed.  Uses a fake OtelLogger that
captures records so we can assert on what was forwarded.

The critical assertion: the full sealed envelope — including group
ciphertext payloads — arrives in the log-record body.  We do NOT strip
crypto fields; they are the attested evidence.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# ---------------------------------------------------------------------------
# Fake OTel logger
# ---------------------------------------------------------------------------


class _FakeOtelLogger:
    def __init__(self):
        self.records: list[dict] = []

    def emit(self, record) -> None:
        # Works with both the dict fallback (no SDK) and a real LogRecord.
        if isinstance(record, dict):
            self.records.append(record)
        else:
            # Real LogRecord — pull body + attributes out.
            self.records.append(
                {
                    "body": record.body,
                    "attributes": dict(record.attributes or {}),
                    "severity_number": int(record.severity_number),
                    "severity_text": record.severity_text,
                }
            )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_otel_handler_forwards_full_envelope():
    """Handler body = full sealed envelope with ciphertext."""
    from tn.handlers.otel import OpenTelemetryHandler

    logger = _FakeOtelLogger()
    h = OpenTelemetryHandler(name="otel-test", otel_logger=logger)

    envelope = {
        "did": "did:key:zTest",
        "timestamp": "2026-04-23T12:00:00.000000Z",
        "event_id": "evt-001",
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": "sha256:" + "0" * 64,
        "row_hash": "sha256:" + "a" * 64,
        "signature": "sig_b64_here",
        # A group ciphertext payload — must survive to body.
        "default": {
            "ciphertext": "base64_encrypted_data==",
            "field_hashes": {"amount": "hmac_abc123"},
        },
    }
    raw = (json.dumps(envelope, separators=(",", ":")) + "\n").encode()

    h.emit(envelope, raw)

    assert len(logger.records) == 1
    rec = logger.records[0]

    # Body is the full envelope — ciphertext present.
    body = rec["body"]
    assert body["event_type"] == "order.created"
    assert "default" in body, "ciphertext group must be in body"
    assert body["default"]["ciphertext"] == "base64_encrypted_data=="

    print("otel: full envelope (ciphertext included) in body ✓")


def test_otel_handler_attributes_are_flat_queryable_fields():
    """Six flat fields are promoted to tn.* attributes."""
    from tn.handlers.otel import OpenTelemetryHandler

    logger = _FakeOtelLogger()
    h = OpenTelemetryHandler(name="otel-attrs", otel_logger=logger)

    envelope = {
        "did": "did:key:zAttr",
        "timestamp": "2026-04-23T15:00:00.000000Z",
        "event_id": "evt-002",
        "event_type": "payment.failed",
        "level": "error",
        "sequence": 5,
        "prev_hash": "sha256:" + "0" * 64,
        "row_hash": "sha256:" + "b" * 64,
        "signature": "sig",
    }
    h.emit(envelope, b"")

    attrs = logger.records[0]["attributes"]
    assert attrs["tn.event_type"] == "payment.failed"
    assert attrs["tn.level"] == "error"
    assert attrs["tn.sequence"] == 5
    assert attrs["tn.did"] == "did:key:zAttr"
    assert "tn.signature" not in attrs, "signature must NOT be an attribute"
    assert "tn.row_hash" not in attrs, "row_hash must NOT be an attribute"

    print("otel: flat attributes correct, crypto fields absent ✓")


def test_otel_handler_severity_mapping():
    """TN level strings map to correct OTel SeverityNumber values."""
    from tn.handlers.otel import OpenTelemetryHandler

    cases = [
        ("debug", 5),
        ("info", 9),
        ("warning", 13),
        ("error", 17),
        ("UNKNOWN", 9),  # falls back to INFO
    ]
    for level, expected_sev in cases:
        logger = _FakeOtelLogger()
        h = OpenTelemetryHandler(name=f"sev-{level}", otel_logger=logger)
        h.emit({"event_type": "x", "level": level}, b"")
        rec = logger.records[0]
        rec.get("severity_number") or int(rec.get("body", {}).get("level_debug") or expected_sev)
        # The _make_log_record dict fallback stores it directly.
        assert rec["severity_number"] == expected_sev, (
            f"{level}: {rec['severity_number']} != {expected_sev}"
        )
    print("otel: severity mapping all correct ✓")


def test_otel_handler_null_logger_is_noop():
    """NullOtelLogger (default) swallows everything without raising."""
    from tn.handlers.otel import OpenTelemetryHandler

    h = OpenTelemetryHandler(name="noop")  # no otel_logger -> NullOtelLogger
    h.emit({"event_type": "x", "level": "info"}, b"")
    print("otel: null logger no-op ✓")


def test_otel_handler_filter_respected():
    """Filter spec prevents non-matching envelopes from reaching OTel."""
    from tn.handlers.otel import OpenTelemetryHandler

    logger = _FakeOtelLogger()
    h = OpenTelemetryHandler(
        name="filtered-otel",
        otel_logger=logger,
        filter_spec={"event_type": {"starts_with": "payment."}},
    )

    for env in [
        {"event_type": "order.created", "level": "info"},
        {"event_type": "payment.failed", "level": "error"},
        {"event_type": "order.shipped", "level": "info"},
    ]:
        if h.accepts(env):
            h.emit(env, b"")

    assert len(logger.records) == 1
    assert logger.records[0]["body"]["event_type"] == "payment.failed"
    print("otel: filter blocks non-matching events ✓")


def test_otel_handler_wired_into_tn_runtime():
    """End-to-end: real tn.init() + tn.info() fans out to OTel handler."""
    import tn
    from tn.handlers.otel import OpenTelemetryHandler

    logger = _FakeOtelLogger()
    otel_h = OpenTelemetryHandler(name="e2e-otel", otel_logger=logger)

    with tempfile.TemporaryDirectory(prefix="tnotel_") as td:
        ws = Path(td)
        tn.init(ws / "tn.yaml", extra_handlers=[otel_h])

        tn.info("order.created", amount=99, currency="USD")
        tn.warning("order.delayed", days=2)
        tn.error("payment.failed", code="402")

        tn.flush_and_close()

    # tn.init() emits protocol events (e.g. tn.group.added) — filter those out.
    user_recs = [r for r in logger.records if not r["body"]["event_type"].startswith("tn.")]
    assert len(user_recs) == 3

    # Every user record body must have the ciphertext group (default group).
    for rec in user_recs:
        body = rec["body"]
        assert "default" in body, f"missing 'default' group in {body['event_type']}"
        assert isinstance(body["default"]["ciphertext"], str)

    # Spot-check attributes on user events.
    by_type = {r["body"]["event_type"]: r for r in user_recs}
    assert by_type["order.created"]["attributes"]["tn.event_type"] == "order.created"
    assert by_type["payment.failed"]["attributes"]["tn.level"] == "error"

    print("otel e2e: 3 user events forwarded with ciphertext bodies ✓")


def main() -> int:
    test_otel_handler_forwards_full_envelope()
    test_otel_handler_attributes_are_flat_queryable_fields()
    test_otel_handler_severity_mapping()
    test_otel_handler_null_logger_is_noop()
    test_otel_handler_filter_respected()
    test_otel_handler_wired_into_tn_runtime()
    print("\nall OTel handler tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
