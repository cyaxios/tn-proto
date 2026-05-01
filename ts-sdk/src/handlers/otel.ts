// OpenTelemetry log-record handler for TN envelopes.
//
// Forwards the COMPLETE sealed envelope — ciphertext and all — as the OTel
// log record body. The encrypted groups are the attested payload; stripping
// them would lose the evidence. A small set of flat fields is also promoted
// to OTel attributes so backends can filter/index without parsing the body.
//
// "Not signed or linked" semantics: emitting to OTel does NOT call back
// into tn.emit(), so there is no circular chain entry created. The handler
// just reads what it receives.
//
// Usage:
//   import { logs } from "@opentelemetry/api-logs";
//   const logger = logs.getLogger("tn-protocol");
//   rt.addHandler(new OpenTelemetryHandler("otel", logger));
//
// @opentelemetry/api-logs is a peer dependency — install it separately.
// If you pass null, the handler is a no-op (useful for toggling in tests).

import { BaseTNHandler, type FilterSpec } from "./base.js";

// Minimal interface matching @opentelemetry/api-logs Logger.emit signature.
// Typed loosely so callers don't need to import OTel types just to wire us up.
export interface OtelLogger {
  emit(record: OtelLogRecord): void;
}

export interface OtelLogRecord {
  severityNumber?: number;
  severityText?: string;
  body?: unknown;
  attributes?: Record<string, string | number | boolean>;
  timestamp?: number;
}

// OTel SeverityNumber values (opentelemetry-specification Table 7).
const SEVERITY: Record<string, number> = {
  debug: 5,
  info: 9,
  warning: 13,
  error: 17,
};

// Envelope fields promoted to OTel attributes (flat, indexable).
const ATTR_FIELDS = new Set(["did", "event_id", "event_type", "level", "sequence", "timestamp"]);

export interface OpenTelemetryHandlerOptions {
  filter?: FilterSpec;
}

export class OpenTelemetryHandler extends BaseTNHandler {
  private readonly _logger: OtelLogger | null;

  constructor(
    name: string,
    /** OTel Logger from @opentelemetry/api-logs, or null to no-op. */
    logger: OtelLogger | null,
    options: OpenTelemetryHandlerOptions = {},
  ) {
    super(name, options.filter);
    this._logger = logger;
  }

  emit(envelope: Record<string, unknown>, _rawLine: string): void {
    if (!this._logger) return;

    const level = String(envelope["level"] ?? "info").toLowerCase();
    const ts = envelope["timestamp"];
    const tsMs = typeof ts === "string" ? Date.parse(ts) : typeof ts === "number" ? ts : Date.now();

    // Flat attributes for indexing — only primitives.
    const attributes: Record<string, string | number | boolean> = {};
    for (const k of ATTR_FIELDS) {
      const v = envelope[k];
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
        attributes[`tn.${k}`] = v;
      }
    }

    // Body = full sealed envelope (ciphertext groups included).
    this._logger.emit({
      severityNumber: SEVERITY[level] ?? 9,
      severityText: level.toUpperCase(),
      body: envelope,
      attributes,
      timestamp: tsMs,
    });
  }
}
