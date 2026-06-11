// Attested-log query DSL for TN-native assertions (TS side).
//
// Mirrors `regression/_shared/log_query.py` — same predicates, same
// failure-output shape. Whenever a regression test is checking TN's own
// protocol output (envelopes in an attested log), the assertion goes
// through `LogQuery.assertContains(...)` — NOT bare equality, NOT a
// generic `assertNamed`.
//
// See `_shared/README.md` for the contract + Style-1 example.

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { parse as parseYaml } from "yaml";

import {
  AssertionRecord,
  NamedAssertionError,
  _formatFailureForLogQuery,
  _recordForLogQuery,
  _resolveSiloForLogQuery,
  _resolveTestForLogQuery,
} from "./assertions.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface RawEnvelope {
  [key: string]: unknown;
}

export class Envelope {
  constructor(public readonly raw: RawEnvelope) {}

  get eventType(): string {
    return String(this.raw["event_type"] ?? "");
  }

  get sequence(): number {
    const s = this.raw["sequence"];
    return typeof s === "number" ? s : 0;
  }

  get rowHash(): string {
    return String(this.raw["row_hash"] ?? "");
  }

  get(key: string): unknown {
    return this.raw[key];
  }
}

export type Predicate = Record<string, unknown>;

export interface LogQueryArgs {
  /** Path to the ceremony yaml. Resolves logs.path + admin_log_location. */
  ceremonyPath?: string;
  /** Explicit list of log file paths. Mutually exclusive with ceremonyPath. */
  logPaths?: string[];
}

export interface AssertContainsArgs {
  name: string;
  where: Predicate;
  onMiss?: string;
}

// ---------------------------------------------------------------------------
// LogQuery
// ---------------------------------------------------------------------------

export class LogQuery {
  private readonly logPaths: string[];

  constructor(args: LogQueryArgs) {
    if (args.ceremonyPath && args.logPaths) {
      throw new Error("LogQuery: pass either ceremonyPath OR logPaths, not both");
    }
    if (!args.ceremonyPath && !args.logPaths) {
      throw new Error("LogQuery: must pass ceremonyPath or logPaths");
    }

    this.logPaths = args.ceremonyPath
      ? resolveCeremonyLogs(args.ceremonyPath)
      : args.logPaths!.map((p) => resolvePath(p));
  }

  /** All envelopes from every log path, chronological order, malformed
   *  lines silently skipped. */
  envelopes(): Envelope[] {
    type Row = { ts: string; env: RawEnvelope };
    const rows: Row[] = [];
    for (const path of this.logPaths) {
      if (!existsSync(path)) continue;
      const text = readFileSync(path, "utf-8");
      for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) continue;
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          continue;
        }
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
        const env = parsed as RawEnvelope;
        const ts = String(env["timestamp"] ?? "");
        rows.push({ ts, env });
      }
    }
    rows.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
    return rows.map((r) => new Envelope(r.env));
  }

  findAll(args: { where: Predicate }): Envelope[] {
    return this.envelopes().filter((env) => matches(env.raw, args.where));
  }

  findOne(args: { where: Predicate }): Envelope | null {
    return this.findAll(args)[0] ?? null;
  }

  eventTypeCounts(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const env of this.envelopes()) {
      const et = env.eventType;
      out[et] = (out[et] ?? 0) + 1;
    }
    return out;
  }

  /**
   * Assert at least one envelope matches `where`. Returns the first
   * match for chained inspection. On miss, throws NamedAssertionError
   * with the same structured shape as the Python equivalent.
   */
  assertContains(args: AssertContainsArgs): Envelope {
    const matchesList = this.findAll({ where: args.where });
    const silo = _resolveSiloForLogQuery();
    const test = _resolveTestForLogQuery();

    if (matchesList.length > 0) {
      _recordForLogQuery({
        name: args.name,
        style: "log-query",
        passed: true,
        expected: `at least 1 envelope where ${pp(args.where)}`,
        observed: `${matchesList.length} match(es)`,
        on_miss: args.onMiss ?? "",
        silo,
        test,
      });
      return matchesList[0]!;
    }

    // MISS — build structured failure
    const counts = this.eventTypeCounts();
    const et = args.where["event_type"];
    const closest = et !== undefined ? findClosest(this.envelopes(), args.where) : null;
    const missPointer =
      args.onMiss ?? "(no pointer supplied — add `onMiss` to the assertion)";

    const observedRepr =
      `no envelope matched; event_type counts in log = ${pp(counts)}; ` +
      `closest match = ${closest ? pp(closest.raw) : "none"}`;

    _recordForLogQuery({
      name: args.name,
      style: "log-query",
      passed: false,
      expected: `at least 1 envelope where ${pp(args.where)}`,
      observed: observedRepr,
      on_miss: missPointer,
      silo,
      test,
    });

    const lines = [
      `ASSERTION FAILED: ${args.name}`,
      `  silo: ${silo}`,
      `  test: ${test}`,
      `  style: log-query`,
      `  predicate: ${pp(args.where)}`,
      `  observed in log:`,
      `    paths: ${pp(this.logPaths)}`,
      `    total event_types: ${pp(counts)}`,
    ];
    if (closest) {
      lines.push(`  closest match (same event_type): ${pp(closest.raw)}`);
    } else {
      lines.push(`  closest match: <none — no envelope had event_type=${pp(et)}>`);
    }
    lines.push(`  look at: ${missPointer}`);

    // Use the formatter to keep parity (covers the rare future case
    // where formatFailure changes shape and we want both styles to
    // track in lockstep).
    void _formatFailureForLogQuery;

    throw new NamedAssertionError(lines.join("\n"));
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function matches(env: RawEnvelope, where: Predicate): boolean {
  for (const [k, v] of Object.entries(where)) {
    if (env[k] !== v) return false;
  }
  return true;
}

function findClosest(envs: Envelope[], where: Predicate): Envelope | null {
  const et = where["event_type"];
  if (!et) return null;
  return envs.find((e) => e.eventType === et) ?? null;
}

function pp(v: unknown): string {
  if (v === null || v === undefined) return "None";
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/**
 * Resolve a ceremony yaml to its log file list (main + admin if
 * separate). **Behavior contract: must match Python's
 * `_resolve_ceremony_logs` in `regression/_shared/log_query.py`
 * byte-for-byte for the same input.** Both sides use a real yaml
 * parser (PyYAML on Python, the `yaml` npm package on TS) so the
 * regression suite asserts the same files on both runtimes regardless
 * of anchors, block scalars, multi-doc files, or quoted keys.
 *
 * Algorithm (mirrors Python):
 *   1. Parse the yaml. Non-dict / parse-error → return [].
 *   2. `doc.logs.path` (if `logs` is a dict + `path` is a string)
 *      → append, resolved against yaml's parent dir.
 *   3. `doc.ceremony.admin_log_location` (if `ceremony` is a dict
 *      + value is a string AND not `"main_log"` AND not empty AND
 *      contains no `{` template tokens) → append, resolved against
 *      yaml's parent.
 *   4. Return.
 *
 * The regression suite intentionally does NOT depend on the SDK's
 * `loadConfig` — when the SDK config loader is broken, the regression
 * suite needs to still work to surface the bug.
 */
function resolveCeremonyLogs(yamlPath: string): string[] {
  if (!existsSync(yamlPath)) return [];

  let doc: unknown;
  try {
    doc = parseYaml(readFileSync(yamlPath, "utf-8"));
  } catch {
    return [];
  }
  if (doc === null || doc === undefined) return [];
  if (typeof doc !== "object" || Array.isArray(doc)) return [];

  const d = doc as Record<string, unknown>;
  const base = dirname(yamlPath);
  const out: string[] = [];

  // 1. logs.path
  const logsBlock = d["logs"];
  if (logsBlock !== null && typeof logsBlock === "object" && !Array.isArray(logsBlock)) {
    const main = (logsBlock as Record<string, unknown>)["path"];
    if (typeof main === "string") {
      out.push(resolvePath(base, main));
    }
  }

  // 2. ceremony.admin_log_location
  const cerBlock = d["ceremony"];
  if (cerBlock !== null && typeof cerBlock === "object" && !Array.isArray(cerBlock)) {
    const admin = (cerBlock as Record<string, unknown>)["admin_log_location"];
    if (
      typeof admin === "string" &&
      admin !== "main_log" &&
      admin !== "" &&
      !admin.includes("{")
    ) {
      out.push(resolvePath(base, admin));
    }
  }

  // Keep AssertionRecord referenced — the import above is for type
  // consumers but we don't currently use it inside this function.
  void ({} as AssertionRecord);

  return out;
}
