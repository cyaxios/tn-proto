/**
 * Process-singleton `run_id` + `$TN_RUN_ID` env stamp.
 *
 * Every emit in a TN process carries the same `run_id` so
 * `tn.read()` can default-filter to "entries written by this run."
 * The Rust wasm runtime reads `$TN_RUN_ID` at its own init
 * ({@link https://github.com/cyaxios/tn-protocol/blob/main/crypto/tn-core/src/runtime.rs#L860 | tn-core/src/runtime.rs:860}),
 * so the JS side stamps the env *before* constructing a `WasmRuntime` —
 * otherwise wasm mints its own UUID and the two sides emit mismatched
 * `run_id`s, which makes the read filter silently drop every entry
 * written via the wasm path.
 *
 * Mint policy (mirrors `python/tn/__init__.py:268`):
 *
 * 1. If `_runId` is already chosen for this process, return it.
 * 2. Else mint a fresh UUID-hex via `crypto.randomUUID`.
 * 3. Always overwrite `process.env["TN_RUN_ID"]` — a child process
 *    that inherits a stale value from a parent shell must NOT silently
 *    join the parent's run.
 *
 * @packageDocumentation
 */

import { randomUUID } from "node:crypto";

/**
 * Process-singleton run-id. `null` until {@link ensureProcessRunId} is
 * called for the first time; thereafter, holds the 32-hex-char id used
 * by every emit + every consumer of `process.env["TN_RUN_ID"]`.
 *
 * @internal
 */
let _processRunId: string | null = null;

/**
 * Lazily mint (or return) the process's `run_id` and stamp it into
 * `process.env["TN_RUN_ID"]`.
 *
 * The first call mints a fresh 32-char hex string; subsequent calls
 * return the same string. Every call (re-)writes the env var so the
 * wasm runtime — which reads `TN_RUN_ID` at its own init — sees the
 * matching value and stamps congruent `run_id`s on the envelopes it
 * writes via the storage callback.
 *
 * @returns The 32-character lowercase-hex `run_id` for this process.
 *   Guaranteed identical across all calls within a single Node process.
 *
 * @example
 * ```ts
 * import { ensureProcessRunId } from "tn-proto/_run_id";
 *
 * const runId = ensureProcessRunId();
 * // process.env.TN_RUN_ID is now set; the wasm runtime will pick it up.
 * ```
 *
 * @remarks
 * Idempotent and cheap — safe to call from any module-load hook,
 * including the side-effect import at the top of
 * `src/runtime/node_runtime.ts`. The re-stamp on every call covers
 * two edge cases:
 *
 * 1. A child process inherits a stale `TN_RUN_ID` from its parent
 *    shell. We overwrite on first call so the child doesn't quietly
 *    join the parent's "current run."
 * 2. Test harnesses or cleanup hooks may clear the env between calls.
 *    The defensive re-stamp restores it before the next wasm init.
 *
 * Mirrors `python/tn/__init__.py:_run_id` and the Rust runtime's
 * `TN_RUN_ID` read at `crypto/tn-core/src/runtime.rs:860`.
 *
 * @see {@link _resetProcessRunIdForTests} — test-only reset hook.
 * @see [spec/env-vars#tn_run_id](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/env-vars.md) - the cross-process run-id contract.
 * @see [spec/envelope](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/envelope.md) - where the run_id appears (as a public field on every emit).
 * @public
 */
export function ensureProcessRunId(): string {
  if (_processRunId === null) {
    _processRunId = randomUUID().replace(/-/g, "");
  }
  process.env["TN_RUN_ID"] = _processRunId;
  return _processRunId;
}

/**
 * Reset the singleton so the next {@link ensureProcessRunId} call
 * mints fresh. Test-only — production code must not call this; mid-run
 * `run_id` flips would break the read filter's "this run only"
 * contract.
 *
 * @example
 * ```ts
 * import { _resetProcessRunIdForTests, ensureProcessRunId } from "tn-proto/_run_id";
 *
 * beforeEach(() => {
 *   _resetProcessRunIdForTests();
 *   ensureProcessRunId();   // fresh run_id per test
 * });
 * ```
 *
 * @see {@link ensureProcessRunId}
 * @remarks
 * Mirrors `python/tn/_autoinit.reset_state_for_tests`.
 * @internal
 */
export function _resetProcessRunIdForTests(): void {
  _processRunId = null;
}
