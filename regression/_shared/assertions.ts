// Named-assertion sidecar for the TN regression suite (TS side).
//
// Mirrors `regression/_shared/assertions.py` — every check goes through
// `assertNamed(...)` (or `LogQuery.assertContains(...)` for TN-native log
// queries). Failure output has IDENTICAL shape across Python and TS so a
// maintainer reading a CI report doesn't have to context-switch.
//
// Reports: each named-assertion outcome is appended to a JSONL stream at
// `$REGRESSION_TS_REPORT` (env var set by the Makefile). At process end,
// `_shared/finalize_ts_report.py` reads that stream + the node exit code
// and emits the final silo report at `.reports/<silo>/last.json` with the
// same schema pytest produces.
//
// See `_shared/README.md` for the contract + Style-2 example.

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// ---------------------------------------------------------------------------
// Public types — keep field names identical to assertions.py's
// AssertionRecord so the JSON reports are interchangeable.
// ---------------------------------------------------------------------------

export interface AssertionRecord {
  name: string;
  style: "named" | "log-query";
  passed: boolean;
  expected: string;   // string-repr so JSON shape matches Python's
  observed: string;
  on_miss: string;    // pointer to "where to look"
  silo: string;
  test: string;       // `<file>::<test>` style, set by the per-test wrapper
}

export class NamedAssertionError extends Error {
  override name = "NamedAssertionError";
}

// ---------------------------------------------------------------------------
// Context — set by the per-test wrapper at silo runner level.
// ---------------------------------------------------------------------------

let currentSilo: string | null = null;
let currentTest: string | null = null;

/** Stamp silo + test id onto the recorder. Called by the per-test
 * wrapper at the start of every test. */
export function setTestContext(args: { silo: string; test: string }): void {
  currentSilo = args.silo;
  currentTest = args.test;
}

function resolveSilo(): string {
  if (currentSilo) return currentSilo;
  // Fallback: infer from cwd parts (e.g. ".../crawl/c3_ts_module_log/...")
  const parts = process.cwd().split(/[\\/]/);
  for (const p of parts) {
    if (p.length >= 2 && /^[cw]\d/.test(p)) {
      return p.split("_", 1)[0]!;
    }
  }
  return "unknown-silo";
}

function resolveTest(): string {
  return currentTest ?? "unknown-test";
}

// ---------------------------------------------------------------------------
// Recorder — writes to $REGRESSION_TS_REPORT JSONL stream.
// ---------------------------------------------------------------------------

const REPORT_STREAM = process.env["REGRESSION_TS_REPORT"] ?? null;

function record(rec: AssertionRecord): void {
  if (!REPORT_STREAM) return;
  try {
    mkdirSync(dirname(REPORT_STREAM), { recursive: true });
    appendFileSync(REPORT_STREAM, JSON.stringify(rec) + "\n", "utf-8");
  } catch (err) {
    // Best effort — losing a record shouldn't crash the test process.
    console.error(`[assertions.ts] failed to write report record: ${err}`);
  }
}

// ---------------------------------------------------------------------------
// Format — IDENTICAL shape to Python's `_format_failure`.
// ---------------------------------------------------------------------------

function formatFailure(args: {
  name: string;
  style: string;
  expected: unknown;
  observed: unknown;
  onMiss: string;
  silo: string;
  test: string;
}): string {
  return [
    `ASSERTION FAILED: ${args.name}`,
    `  silo: ${args.silo}`,
    `  test: ${args.test}`,
    `  style: ${args.style}`,
    `  expected: ${repr(args.expected)}`,
    `  observed: ${repr(args.observed)}`,
    `  look at: ${args.onMiss}`,
  ].join("\n");
}

function repr(v: unknown): string {
  if (v === null) return "None";
  if (v === undefined) return "undefined";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v, (_k, vv) => (typeof vv === "bigint" ? vv.toString() : vv));
  } catch {
    return String(v);
  }
}

// ---------------------------------------------------------------------------
// The two assertion verbs
// ---------------------------------------------------------------------------

export interface AssertNamedArgs<E, O> {
  name: string;
  expected: E;
  observed: O;
  onMiss: string;
  predicate?: (expected: E, observed: O) => boolean;
}

/**
 * Style-2 named assertion. Use whenever the check is not against a TN
 * envelope — HTTP responses, browser DOM, file existence, etc.
 *
 * @throws NamedAssertionError when the predicate returns false. The
 *         error message is the full formatted failure block.
 */
export function assertNamed<E, O>(args: AssertNamedArgs<E, O>): void {
  const silo = resolveSilo();
  const test = resolveTest();
  const predicate = args.predicate ?? ((e: E, o: O) => Object.is(e, o) || e === (o as unknown as E));

  const passed = Boolean(predicate(args.expected, args.observed));

  record({
    name: args.name,
    style: "named",
    passed,
    expected: repr(args.expected),
    observed: repr(args.observed),
    on_miss: args.onMiss,
    silo,
    test,
  });

  if (!passed) {
    throw new NamedAssertionError(
      formatFailure({
        name: args.name,
        style: "named",
        expected: args.expected,
        observed: args.observed,
        onMiss: args.onMiss,
        silo,
        test,
      }),
    );
  }
}

/**
 * Convenience wrapper for regex-pattern assertions.
 */
export function assertNamedMatch(args: {
  name: string;
  pattern: RegExp | string;
  observed: string;
  onMiss: string;
}): void {
  const pattern = args.pattern instanceof RegExp ? args.pattern : new RegExp(args.pattern);
  assertNamed({
    name: args.name,
    expected: pattern.source,
    observed: args.observed,
    onMiss: args.onMiss,
    predicate: (_e, o) => pattern.test(String(o)),
  });
}

// ---------------------------------------------------------------------------
// Re-export for log_query.ts internals (NOT public surface).
// ---------------------------------------------------------------------------

/** Internal — for log_query.ts. Not part of the public API. */
export function _recordForLogQuery(rec: AssertionRecord): void {
  record(rec);
}

/** Internal — for log_query.ts. Not part of the public API. */
export function _resolveSiloForLogQuery(): string {
  return resolveSilo();
}

/** Internal — for log_query.ts. Not part of the public API. */
export function _resolveTestForLogQuery(): string {
  return resolveTest();
}

/** Internal — for log_query.ts. Not part of the public API. */
export function _formatFailureForLogQuery(args: {
  name: string;
  style: string;
  expected: unknown;
  observed: unknown;
  onMiss: string;
  silo: string;
  test: string;
}): string {
  return formatFailure(args);
}
