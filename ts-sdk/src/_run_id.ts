// Process-singleton `run_id` + `$TN_RUN_ID` env stamp.
//
// Mirrors Python `tn.__init__._run_id` and the env-var dance at
// python/tn/__init__.py:268. Every emit in this process carries the
// SAME `run_id` so `tn.read()` can default-filter to "this run only".
// The Rust wasm runtime reads `TN_RUN_ID` at init
// (crypto/tn-core/src/runtime.rs:860), so the JS side stamps the env
// BEFORE constructing a wasm runtime — otherwise wasm mints its own
// fresh UUID and the two sides stamp mismatched `run_id`s, making the
// read filter silently drop every entry written via the wasm path.
//
// Mint policy mirrors Python:
//   1. If `_runId` already chosen this process, return it (singleton).
//   2. Else mint a fresh UUID-hex.
//   3. Always overwrite `process.env["TN_RUN_ID"]` — a child process
//      that inherits a stale value from a parent shell must NOT
//      silently join the parent's run.

import { randomUUID } from "node:crypto";

let _processRunId: string | null = null;

/**
 * Lazily mint (or return) the process's `run_id`. Also writes
 * `process.env["TN_RUN_ID"]` so the wasm runtime — invoked separately
 * via `NodeRuntime.attachWasm` — reads the same value at its own init
 * and stamps matching `run_id`s on its own writes.
 *
 * Idempotent: every call after the first returns the same string and
 * re-stamps the env var defensively (cheap, and catches the case where
 * some other code transiently cleared it).
 */
export function ensureProcessRunId(): string {
  if (_processRunId === null) {
    _processRunId = randomUUID().replace(/-/g, "");
  }
  // Re-stamp every call. Two reasons:
  //   1. A child-process inherited TN_RUN_ID will be overwritten the
  //      first time WE call ensureProcessRunId() — the env then
  //      reflects OUR run, not the parent's.
  //   2. If something between calls cleared the env (test harness,
  //      cleanup hook), the next call restores it.
  process.env["TN_RUN_ID"] = _processRunId;
  return _processRunId;
}

/** Test-only: reset the singleton so a follow-up `ensureProcessRunId()`
 *  mints fresh. Mirrors python/tn/_autoinit.reset_state_for_tests. */
export function _resetProcessRunIdForTests(): void {
  _processRunId = null;
}
