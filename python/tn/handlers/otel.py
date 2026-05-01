"""OpenTelemetry log-record handler for TN envelopes.

Forwards the COMPLETE sealed envelope — ciphertext groups and all — as the
OTel log record body.  The encrypted payloads are the attested evidence;
stripping them would lose the point.  A small set of flat envelope fields is
also promoted to OTel attributes so OTel backends can filter and index without
parsing the body.

"Not signed or linked" semantics: emitting to OTel does NOT call back into
``tn.emit()``, so no circular chain entry is created.  The handler is a pure
read-and-forward sink.

Install the optional extra::

    pip install 'tn-protocol[otel]'
    # or directly:
    pip install opentelemetry-api opentelemetry-sdk

Usage::

    from opentelemetry._logs import get_logger
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor
    from opentelemetry.sdk._logs.export.in_memory_exporter import InMemoryLogExporter

    provider = LoggerProvider()
    exporter = InMemoryLogExporter()
    provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    otel_logger = provider.get_logger("tn-protocol")

    import tn
    tn.init("tn.yaml", extra_handlers=[OpenTelemetryHandler("otel", otel_logger)])

If ``opentelemetry-api`` is not installed, the handler falls back to a
:class:`NullOtelLogger` no-op.  This keeps ceremonies that don't need OTel
from failing on import.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from .base import SyncHandler

_log = logging.getLogger("tn.handlers.otel")

# ---------------------------------------------------------------------------
# OTel SeverityNumber constants (opentelemetry-specification Table 7).
# Duplicated here so the handler doesn't need opentelemetry-api just to
# assign numeric values.
# ---------------------------------------------------------------------------

_SEVERITY: dict[str, int] = {
    "debug": 5,
    "info": 9,
    "warning": 13,
    "error": 17,
}

# Envelope fields promoted to OTel attributes (flat, indexable).
_ATTR_FIELDS = frozenset(
    {
        "did",
        "event_id",
        "event_type",
        "level",
        "sequence",
        "timestamp",
    }
)


# ---------------------------------------------------------------------------
# Minimal OTel Logger protocol — typed loosely so callers don't need to
# import OTel types.  Any object with a matching ``emit`` signature works.
# ---------------------------------------------------------------------------


@runtime_checkable
class OtelLogger(Protocol):
    def emit(self, record: Any) -> None: ...


class NullOtelLogger:
    """Drop-in no-op when opentelemetry-api is not installed."""

    def emit(self, record: Any) -> None:
        pass


def _make_log_record(
    body: dict[str, Any],
    severity_number: int,
    severity_text: str,
    attributes: dict[str, Any],
    timestamp_ns: int | None,
) -> Any:
    """Build an OTel LogRecord using the installed SDK if available.

    Returns a duck-typed object if the SDK is absent (no-ops downstream).
    """
    try:
        # Probe for the LogData symbol that was renamed/removed in newer OTel
        # releases — its presence means we're on a supported SDK. Any ImportError
        # or AttributeError drops us into the fallback path below.
        import opentelemetry.sdk._logs.export as _export_mod
        import opentelemetry.trace as trace_api
        from opentelemetry._logs.severity import SeverityNumber
        from opentelemetry.sdk._logs import LogRecord

        if not hasattr(_export_mod, "LogData"):
            raise ImportError("LogData symbol missing from opentelemetry.sdk._logs.export")

        sev = SeverityNumber(severity_number)
        return LogRecord(
            timestamp=timestamp_ns,
            observed_timestamp=timestamp_ns,
            trace_id=trace_api.INVALID_TRACE_ID,
            span_id=trace_api.INVALID_SPAN_ID,
            trace_flags=trace_api.DEFAULT_TRACE_OPTIONS,
            severity_text=severity_text,
            severity_number=sev,
            body=body,
            resource=None,
            attributes=attributes,
        )
    except ImportError:
        # SDK not available — return a plain dict so callers can still
        # inspect it in tests without a real OTel install.
        return {
            "severity_number": severity_number,
            "severity_text": severity_text,
            "body": body,
            "attributes": attributes,
            "timestamp_ns": timestamp_ns,
        }


def _parse_timestamp_ns(ts: str | None) -> int | None:
    """Parse ISO-8601 timestamp string to nanoseconds since epoch.

    Returns None on failure (OTel will use observed_timestamp instead).
    """
    if not ts:
        return None
    try:
        from datetime import datetime, timezone

        # Handle both "...Z" and "+00:00" suffixes.
        ts_clean = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean).astimezone(timezone.utc)
        return int(dt.timestamp() * 1e9)
    except (ValueError, TypeError):
        return None


class OpenTelemetryHandler(SyncHandler):
    """Forward sealed TN envelopes to an OpenTelemetry LoggerProvider.

    Constructor parameters
    ----------------------
    name
        Handler name (for logging and filter registration).
    otel_logger
        Any object with ``emit(record)`` — typically obtained from
        ``LoggerProvider.get_logger("tn-protocol")``.  Pass ``None`` or omit
        to use the :class:`NullOtelLogger` no-op.
    filter_spec
        Optional RFC §3.2 filter dict (same shape as other handlers).

    The full sealed envelope dict (including group ciphertext payloads) is
    forwarded as the log-record body.  Six flat fields are also copied to OTel
    attributes so that OTel backends can query without deserialising the body:
    ``tn.did``, ``tn.event_id``, ``tn.event_type``, ``tn.level``,
    ``tn.sequence``, ``tn.timestamp``.
    """

    def __init__(
        self,
        name: str,
        otel_logger: OtelLogger | None = None,
        *,
        filter_spec: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(name, filter_spec)
        self._otel_logger: OtelLogger = otel_logger if otel_logger is not None else NullOtelLogger()

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        level = str(envelope.get("level", "info")).lower()
        sev_num = _SEVERITY.get(level, 9)
        sev_text = level.upper()
        ts_ns = _parse_timestamp_ns(envelope.get("timestamp"))

        # Flat queryable attributes (primitives only).
        attributes: dict[str, Any] = {}
        for k in _ATTR_FIELDS:
            v = envelope.get(k)
            if isinstance(v, (str, int, float, bool)):
                attributes[f"tn.{k}"] = v

        record = _make_log_record(
            body=envelope,  # full sealed envelope — ciphertext included
            severity_number=sev_num,
            severity_text=sev_text,
            attributes=attributes,
            timestamp_ns=ts_ns,
        )
        try:
            self._otel_logger.emit(record)
        except Exception as exc:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _log.warning("[%s] otel emit failed: %s", self.name, exc)
