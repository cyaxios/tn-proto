// `tn read [<log>]` — replay a ceremony's log, decoding each entry.
//
// Human-readable by DEFAULT (one flat line per entry, mirroring Python
// `cli_read.cmd_read`): `{ts}  {level:<7} {event_type}  k=v ...`. Pass
// `--json` for the structured envelope shape (pretty by default, one compact
// JSON line per entry with `--compact`/`--json --compact`); `--json`/`--compact`
// are a TS-only superset the cross-impl interop driver relies on (Python's read
// is human-only).
//
// Parity with Python `tn read`:
//   * `--yaml` is OPTIONAL — discover via the standard load-only chain.
//   * the positional `<log>` resolves a stream/ceremony NAME from the project's
//     `.tn/<name>/` registry first (re-init against that stream so decryption
//     uses the right per-stream config), then falls back to a literal log path.
//   * `--all-runs` (default true) / `--no-all-runs` restricts to this process'
//     run.

import { statSync } from "node:fs";
import { dirname } from "node:path";

import { NodeRuntime } from "../runtime/node_runtime.js";
import { flattenRawEntry } from "../core/read_shape.js";
import { ceremonyYamlPath } from "../multi.js";
import { resolveExistingYaml } from "./_discover.js";

/** Options for {@link readCmd}. Mirrors `[<log>] [--yaml] [--log] [--json]
 *  [--compact] [--all-runs|--no-all-runs]`. */
export interface ReadOptions {
  /** Path to tn.yaml (`--yaml`). Optional: discovered when omitted. */
  yaml?: string;
  /** Positional `<log>` or `--log`: a stream/ceremony name, or a literal log
   *  path; default = the ceremony's primary log. */
  log?: string;
  /** Print the structured envelope shape instead of the human one-line view. */
  json?: boolean;
  /** With `--json`: one compact JSON line per entry. (Implies `--json`.) */
  compact?: boolean;
  /** Include entries from previous runs (default true). `--no-all-runs`
   *  restricts to this process' TN_RUN_ID. */
  allRuns?: boolean;
}

/** Render the user-emitted kwargs of one entry as `k=v` pairs, matching the
 *  Python one-line view (envelope/chain plumbing omitted). */
function formatFields(fields: Record<string, unknown>): string {
  return Object.entries(fields)
    .map(([k, v]) => `${k}=${reprValue(v)}`)
    .join(" ");
}

/** Approximate Python `repr()` for the scalar field values the CLI surfaces. */
function reprValue(v: unknown): string {
  if (typeof v === "string") return `'${v.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
  if (typeof v === "boolean") return v ? "True" : "False";
  if (v === null) return "None";
  return JSON.stringify(v);
}

/** Print `tn: error: <msg>` to stderr (matches Python `_die`). */
function errln(msg: string): void {
  process.stderr.write(`tn: error: ${msg}\n`);
}

/**
 * Execute `tn read`. Returns the process exit code (0 success; 1 on a runtime
 * error like a missing ceremony, mirroring Python `_die`). Human-readable by
 * default; `--json`/`--compact` selects the structured output.
 */
export function readCmd(opts: ReadOptions): number {
  // Resolve the yaml: explicit arg (must exist) else load-only discovery.
  let yamlPath: string;
  if (opts.yaml) {
    yamlPath = opts.yaml;
  } else {
    const discovered = resolveExistingYaml();
    if (discovered === null) {
      errln(
        "no ceremony found here. Looked at $TN_YAML, ./tn.yaml, " +
          "./.tn/default/tn.yaml, and a sole .tn/<project>/tn.yaml.\n" +
          "  - Restoring a downloaded seed (.tnpkg)?  run: tn import <seed.tnpkg>\n" +
          "  - Starting a brand-new project?          run: tn init <name>\n" +
          "  - Ceremony lives elsewhere?              pass --yaml <path>, or cd into its directory.",
      );
      return 1;
    }
    yamlPath = discovered;
  }

  // Stream/ceremony NAME resolution: `tn read <name>` resolves a registered
  // stream from `.tn/<name>/tn.yaml` (anchored at the project root) before
  // falling back to a literal log path. Mirrors Python cli_read.cmd_read.
  let logPath: string | undefined;
  if (opts.log) {
    // .tn/<name>/tn.yaml -> project root (parent of `.tn`).
    const projectDir = dirname(dirname(dirname(yamlPath)));
    let candidateYaml: string | null;
    try {
      candidateYaml = ceremonyYamlPath(opts.log, projectDir);
    } catch {
      candidateYaml = null; // invalid name — fall through to literal path mode.
    }
    if (candidateYaml !== null && isFile(candidateYaml)) {
      // It IS a stream name. Re-init against that stream's yaml so decryption
      // uses the right per-stream config, then read its own main log.
      yamlPath = candidateYaml;
      logPath = undefined;
    } else {
      logPath = opts.log;
    }
  }

  let rt: NodeRuntime;
  try {
    rt = NodeRuntime.init(yamlPath);
  } catch (e) {
    errln(e instanceof Error ? e.message : String(e));
    return 1;
  }

  const asJson = opts.json === true || opts.compact === true;
  const allRuns = opts.allRuns ?? true;
  const runId = (process.env["TN_RUN_ID"] ?? "").trim();

  // Per-row run filter for `--no-all-runs` (mirrors Tn.read's matchesRun).
  const matchesRun = (env: Record<string, unknown>, plaintext: Record<string, unknown>): boolean => {
    if (allRuns) return true;
    for (const body of Object.values(plaintext)) {
      if (body && typeof body === "object" && "run_id" in (body as Record<string, unknown>)) {
        return (body as Record<string, unknown>)["run_id"] === runId;
      }
    }
    const envRid = env["run_id"];
    return typeof envRid === "string" && envRid === runId;
  };

  if (!asJson) {
    for (const entry of rt.read(logPath)) {
      if (!matchesRun(entry.envelope, entry.plaintext)) continue;
      const env = entry.envelope;
      const ts = typeof env.timestamp === "string" && env.timestamp ? env.timestamp : "?";
      const level = typeof env.level === "string" ? env.level : "";
      const et = typeof env.event_type === "string" && env.event_type ? env.event_type : "?";
      const flat = flattenRawEntry(entry, { includeValid: false });
      const fields: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(flat)) {
        if (k.startsWith("_")) continue;
        // Drop envelope basics + chain/run plumbing — Python's one-line view
        // surfaces only user-emitted kwargs (entry.fields); did/sequence/hashes/
        // signature/run_id/hidden_groups live on typed attributes.
        if (
          k === "timestamp" ||
          k === "event_type" ||
          k === "level" ||
          k === "device_identity" ||
          k === "sequence" ||
          k === "event_id" ||
          k === "run_id" ||
          k === "hidden_groups"
        ) {
          continue;
        }
        fields[k] = v;
      }
      const extra = formatFields(fields);
      process.stdout.write(`${ts}  ${level.padEnd(7)} ${et}  ${extra}`.replace(/\s+$/, "") + "\n");
    }
    return 0;
  }

  let first = true;
  for (const entry of rt.read(logPath)) {
    if (!matchesRun(entry.envelope, entry.plaintext)) continue;
    const out = {
      event_type: entry.envelope.event_type,
      sequence: entry.envelope.sequence,
      timestamp: entry.envelope.timestamp,
      device_identity: entry.envelope.device_identity,
      row_hash: entry.envelope.row_hash,
      plaintext: entry.plaintext,
      valid: entry.valid,
    };
    if (opts.compact) {
      process.stdout.write(JSON.stringify(out) + "\n");
    } else {
      if (!first) process.stdout.write("\n");
      process.stdout.write(JSON.stringify(out, null, 2) + "\n");
      first = false;
    }
  }
  return 0;
}

/** True iff `p` exists and is a regular file. */
function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}
