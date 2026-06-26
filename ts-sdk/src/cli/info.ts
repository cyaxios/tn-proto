// `tn info` — emit one info-level (or `--level`) protocol event into the
// active ceremony's log.
//
// Human-readable confirmation by DEFAULT (mirroring Python
// `cli_info.cmd_info`): `info: emitted event_type='X' level='Y' fields=N`.
// Pass `--json` for the structured receipt ({event_id, row_hash, sequence}).
//
// The verb owns no argv parsing: the dispatcher parses `--yaml/--event/--level`
// and the `--field/--int/--bool` family (the `parseFieldArgs` helper) and
// hands this function the resolved, validated `InfoOptions` shape. The
// missing-`--yaml`/missing-`--event` guards stay in the dispatcher wrapper
// (they `die(...)` → exit 2, which only the dispatcher's `die` does).

import { NodeRuntime } from "../runtime/node_runtime.js";

/** Options for {@link infoCmd}. Mirrors the resolved output of the .mjs
 *  `parseFieldArgs` helper: `--yaml`, `--event`, `--level`, plus the merged
 *  `--field/--int/--bool` map. */
export interface InfoOptions {
  /** Path to tn.yaml (`--yaml`). Required by the verb; the dispatcher guards
   *  for its presence before calling. */
  yaml: string;
  /** Event type to emit (`--event`, e.g. "order.created"). Required; the
   *  dispatcher guards before calling. */
  event: string;
  /** Log level (`--level`); defaults to "info" in the parser. */
  level: string;
  /** Field map assembled from `--field` (string), `--int`, and `--bool`. */
  fields: Record<string, unknown>;
  /** Print the structured receipt ({event_id, row_hash, sequence}) instead of
   *  the human confirmation line (`--json`). */
  json?: boolean;
}

/**
 * Execute `tn info`. Emits the event and writes a human confirmation line by
 * default (mirroring Python `cli_info.cmd_info`), or the structured single-line
 * JSON receipt with `--json`. Returns the process exit code (0 on success).
 */
export function infoCmd(opts: InfoOptions): number {
  const rt = NodeRuntime.init(opts.yaml);
  const receipt = rt.emit(opts.level, opts.event, opts.fields);
  if (opts.json === true) {
    process.stdout.write(
      JSON.stringify({
        event_id: receipt.eventId,
        row_hash: receipt.rowHash,
        sequence: receipt.sequence,
      }) + "\n",
    );
    return 0;
  }
  // Human confirmation — mirrors Python cli_info.cmd_info:
  //   `info: emitted event_type='X' level='Y' fields=N`
  const fieldCount = Object.keys(opts.fields).length;
  process.stdout.write(
    `info: emitted event_type='${opts.event}' level='${opts.level}' fields=${fieldCount}\n`,
  );
  return 0;
}
