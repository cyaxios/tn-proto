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
    this.write = opts?.write ?? ((s: string) => {
      process.stdout.write(s);
    });
  }

  emit(_envelope: Record<string, unknown>, rawLine: string): void {
    // Defensive newline append — same behavior as the Python and Rust
    // handlers. The runtime should hand us a newline-terminated line,
    // but if a caller passes a bare envelope (e.g. via a test fixture),
    // we still produce one entry per `console.log`-style line.
    const line = rawLine.endsWith("\n") ? rawLine : rawLine + "\n";
    try {
      this.write(line);
    } catch {
      // Best-effort — stdout being closed mid-process should not crash
      // the publish path.
    }
  }
}
