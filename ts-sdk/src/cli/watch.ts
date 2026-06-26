// `tn watch` — tail (or one-shot drain) a TN ndjson log to stdout.
// TypeScript port of the inline `watchCmd` from `bin/tn-js.mjs`.
//
// The inline version did `await import("../dist/index.js")` at call time;
// that is hoisted here to a static top-of-file import from the SOURCE
// `../tn.js`. The `--since` coercion (string | seq | iso-ts), the SIGINT
// stop flag, the `--once` snapshot drain, and the tail loop are ported
// verbatim. stdout/stderr are byte-for-byte identical to the inline version
// (the spawn test in test/cli_watch.test.ts asserts exact output and exit
// codes). The dispatcher parses argv into {@link WatchCmdOptions}; this
// module owns no argv.

import type { ReadOptions } from "../tn.js";
import { Tn } from "../tn.js";
import type { Entry } from "../core/types.js";

/** Options for {@link watchCmd}, one-to-one with the CLI flags
 *  (`--yaml`, `--since`, `--verify`, `--interval`/`--poll`, `--once`). */
export interface WatchCmdOptions {
  /** Path to tn.yaml (`--yaml`); default = discover via the standard chain. */
  yamlPath?: string | null;
  /** Starting point (`--since`): "start" | "now" | <seq> | <iso-ts>. The
   *  dispatcher passes the raw string; coercion to a number happens here. */
  since?: string;
  /** Integrity-check each entry (`--verify`). */
  verify?: boolean;
  /** Polling fallback interval in ms. The dispatcher derives this from the
   *  canonical `--interval <seconds>` (×1000) or the back-compat `--poll <ms>`
   *  alias. Default: 300 (== Python's `--interval` default of 0.3s). */
  pollMs?: number;
  /** Drain the current snapshot and exit instead of tailing (`--once`). */
  once?: boolean;
}

/**
 * Execute `tn watch`. Returns the process exit code (always 0), mirroring the
 * inline `watchCmd`.
 */
export async function watchCmd(opts: WatchCmdOptions): Promise<number> {
  const yamlPath = opts.yamlPath ?? null;
  const since = opts.since ?? "now";
  const verify = opts.verify ?? false;
  const pollMs = opts.pollMs ?? 300;
  const once = opts.once ?? false;

  // Coerce --since: "start" | "now" stay as strings; pure-digit value
  // becomes a sequence number; otherwise treat as ISO-8601 timestamp.
  let sinceVal: string | number = since;
  if (since !== "start" && since !== "now" && /^\d+$/.test(since)) {
    sinceVal = Number(since);
  }

  const tn = yamlPath ? await Tn.init(yamlPath) : await Tn.init();

  // Set up SIGINT to stop cleanly. We can't easily abort an in-flight
  // for-await iteration without an AbortSignal, so flip a flag and
  // break on the next yield.
  let stopping = false;
  const onSigint = () => {
    stopping = true;
    process.stderr.write("\ntn-js watch: stopping (SIGINT)\n");
  };
  process.on("SIGINT", onSigint);

  try {
    if (once) {
      // --once: drain everything currently in the log starting from
      // `since`, then exit. Use tn.read for the snapshot read; this
      // matches Python's `python -m tn.watch --once` shape.
      const opts: ReadOptions = {};
      if (verify) opts.verify = true;
      const startAt =
        sinceVal === "start" ? null :
        sinceVal === "now" ? "skip" :
        sinceVal;
      // Walk the snapshot. For "now", we'd skip everything — that's
      // a no-op, exit 0. For "start", iterate everything. For a
      // seq/timestamp, filter.
      if (startAt === "skip") {
        // no-op; exit 0
      } else if (startAt === null) {
        opts.allRuns = true;
        for (const entry of tn.read(opts)) {
          process.stdout.write(JSON.stringify(entry) + "\n");
        }
      } else {
        opts.allRuns = true;
        for (const entry of tn.read(opts)) {
          // entry.timestamp is a Date (Entry); coerce to ISO for the
          // string-comparison branch. entry.sequence is a number.
          const e = entry as Partial<Entry> & Record<string, unknown>;
          const tsIso =
            e.timestamp instanceof Date
              ? e.timestamp.toISOString()
              : typeof e.timestamp === "string"
                ? e.timestamp
                : "";
          const matches =
            typeof startAt === "number"
              ? typeof e.sequence === "number" && e.sequence >= startAt
              : tsIso !== "" && tsIso >= startAt;
          if (matches) {
            process.stdout.write(JSON.stringify(entry) + "\n");
          }
        }
      }
    } else {
      // Tail forever (until SIGINT).
      const watchOpts = { since: sinceVal, verify, pollIntervalMs: pollMs };
      for await (const entry of tn.watch(watchOpts)) {
        if (stopping) break;
        process.stdout.write(JSON.stringify(entry) + "\n");
      }
    }
  } finally {
    process.removeListener("SIGINT", onSigint);
    await tn.close();
  }
  return 0;
}
