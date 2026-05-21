// Stdout handler — write canonical envelope NDJSON lines to stdout.
//
// Mirrors `tn.handlers.stdout.StdoutHandler` (Python) and Rust's
// `StdoutHandler`. Default-on: every `TNClient.init` registers one of
// these unless the `TN_NO_STDOUT=1` env var is set. Cross-language
// parity matters: same opt-out env var, same JSON line on the wire.

import { BaseTNHandler, type FilterSpec } from "./base.js";

/**
 * Write each accepted envelope's raw JSON line to `process.stdout`.
 *
 * The line is byte-for-byte what the file handler would persist to
 * `tn.ndjson`, so downstream tools (jq, log aggregators, jsonline
 * parsers) see the same canonical shape regardless of where they read.
 */
export class StdoutHandler extends BaseTNHandler {
  /**
   * Optional override for the write sink. Tests pass an in-memory
   * collector; production code defaults to `process.stdout`.
   */
  private readonly write: (s: string) => void;

  constructor(opts?: { name?: string; filter?: FilterSpec; write?: (s: string) => void }) {
    super(opts?.name ?? "stdout", opts?.filter);
    this.write = opts?.write ?? _defaultStdoutWrite;
  }

  emit(envelope: Record<string, unknown>, rawLine: string): void {
    // Format selection (precedence high → low):
    //   1. ``TN_STDOUT_FORMAT`` env var (``pretty`` | ``json``)
    //   2. ``format:`` constructor option (forthcoming)
    //   3. default: ``pretty`` (mirrors Python)
    const fmt = (process.env.TN_STDOUT_FORMAT ?? "pretty").toLowerCase();
    const line =
      fmt === "json"
        ? rawLine.endsWith("\n")
          ? rawLine
          : rawLine + "\n"
        : _formatPretty(envelope);
    try {
      this.write(line);
    } catch {
      // Best-effort — stdout being closed mid-process should not crash
      // the publish path.
    }
  }

  /**
   * Stdout dedups by sentinel — every StdoutHandler instance writes
   * to the same process stdout. When a custom ``write`` callback is
   * supplied, dedup uses an id-keyed sentinel so two handlers with
   * different write targets don't collide.
   */
  override resolved_address(): string {
    if (this.write !== _defaultStdoutWrite) {
      // Custom sink — dedup by function identity so two handlers with
      // separate test collectors stay independent.
      return `<stream:${_idForFn(this.write)}>`;
    }
    return "<stdout>";
  }
}

// Stable id-per-function for the resolved_address sentinel of custom
// write targets. Preserves dedup semantics when the *same* function is
// passed to two handlers.
type _WriteFn = (s: string) => void;
const _fnIdMap = new WeakMap<_WriteFn, number>();
let _fnIdCounter = 0;
function _idForFn(fn: _WriteFn): number {
  let id = _fnIdMap.get(fn);
  if (id === undefined) {
    id = ++_fnIdCounter;
    _fnIdMap.set(fn, id);
  }
  return id;
}

function _defaultStdoutWrite(s: string): void {
  process.stdout.write(s);
}

// Envelope keys that are *crypto* and never belong on stdout. Mirrors
// python/tn/handlers/stdout.py:_CRYPTO_KEYS.
const _CRYPTO_KEYS: ReadonlySet<string> = new Set([
  "prev_hash",
  "row_hash",
  "signature",
  "did",
  "timestamp",
  "level",
  "event_type",
  "sequence",
  "event_id",
]);

function _isGroupCiphertext(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    "ciphertext" in (value as Record<string, unknown>)
  );
}

function _short(s: string, n: number): string {
  if (!s || s.length <= n) return s;
  return s.slice(0, n) + "…";
}

/**
 * Render an envelope as a terse human-readable line.
 *
 * Mirrors python/tn/handlers/stdout.py:_format_pretty.
 *
 * Header: ``HH:MM:SS.mmm LEVEL  seq=N  event_type``.
 * Trailer: every public envelope field rendered as ``key=value``,
 * sorted by key. Crypto fields (signatures, hashes, full DID) and
 * group ciphertext blocks are suppressed. ``event_id`` and ``did``
 * are shown truncated as ``id=<short>`` / ``did=<short>``.
 */
function _formatPretty(envelope: Record<string, unknown>): string {
  let ts = String(envelope.timestamp ?? "");
  if (ts.includes("T")) ts = ts.split("T", 2)[1] ?? ts;
  if (ts.endsWith("Z")) ts = ts.slice(0, -1);
  if (ts.includes(".")) {
    const [head, frac] = ts.split(".", 2);
    ts = `${head}.${(frac ?? "").slice(0, 3)}`;
  }
  // ``level=""`` (severity-less ``tn.log``) renders as LOG to match
  // the public verb name. Mirrors python/tn/handlers/stdout.py.
  const rawLevel = String(envelope.level ?? "");
  const level = (rawLevel || "log").toUpperCase();
  const seq = envelope.sequence ?? "";
  const eventType = String(envelope.event_type ?? "");

  const parts: string[] = [
    `${ts.padEnd(12, " ")} ${level.padEnd(5, " ")}  seq=${seq}  ${eventType}`,
  ];

  const eid = envelope.event_id;
  if (typeof eid === "string" && eid) {
    parts.push(`id=${_short(eid, 8)}`);
  }
  const did = envelope.device_identity;
  if (typeof did === "string" && did) {
    parts.push(`did=${_short(did, 16)}`);
  }

  const extras: string[] = [];
  const sortedKeys = Object.keys(envelope).sort();
  for (const k of sortedKeys) {
    if (_CRYPTO_KEYS.has(k)) continue;
    const v = envelope[k];
    if (_isGroupCiphertext(v)) continue;
    extras.push(`${k}=${typeof v === "string" ? `'${v}'` : JSON.stringify(v)}`);
  }
  if (extras.length > 0) parts.push(extras.join(" "));

  return parts.join("  ") + "\n";
}
