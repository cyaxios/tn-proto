/**
 * Console handler — print each emit to `globalThis.console` per level.
 *
 * JS / browser equivalent of the Node SDK's `StdoutHandler`. Default-on:
 * {@link BrowserRuntime.init} constructs one of these unless the caller
 * passes `console: false`. The verb pair is intentional:
 *
 * | Side    | Sink                | Option         |
 * |---------|---------------------|----------------|
 * | Node    | `process.stdout`    | `opts.stdout`  |
 * | Browser | `globalThis.console`| `opts.console` |
 *
 * Same role (default-on visibility for the developer),
 * language-appropriate sink + option name.
 *
 * Routes plaintext `(level, event_type, fields)` to the matching
 * `console.*` method so DevTools' built-in level filter works:
 *
 * | TN level    | console method   |
 * |-------------|------------------|
 * | `"debug"`   | `console.debug`  |
 * | `"info"`    | `console.info`   |
 * | `""`        | `console.info`   |
 * | `"warning"` | `console.warn`   |
 * | `"error"`   | `console.error`  |
 *
 * Format: `"[<event_type>]"` as the message string, with the plaintext
 * fields object as the second argument so DevTools renders it as an
 * expandable object inline with the message.
 *
 * **Why this is plaintext-based, not envelope-based:** the wasm-side
 * `addHandler` callback runs *after* encryption — by that point every
 * useful field has been swallowed by a group ciphertext blob and the
 * console would show nothing but headers. The right cut-point is the
 * browser runtime's emit verbs (where the caller's plaintext args are
 * still in hand); see `BrowserRuntime.{info,log,warning,error,debug}`.
 *
 * @packageDocumentation
 */

interface ConsoleLike {
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
  log(...args: unknown[]): void;
}

/**
 * What `BrowserRuntime` invokes for each emit. Constructed via
 * {@link consoleHandler} for the default-on case; advanced consumers
 * can write their own object satisfying the same shape and pass it to
 * `Tn.init({ console: customHandler })` for an opt-in custom sink (e.g.
 * a remote log shipper, an in-page debug overlay, a test capture).
 *
 * @example
 * ```ts
 * import { Tn, type ConsoleHandler } from "@tnproto/sdk/browser";
 *
 * const captured: Array<[string, string, Record<string, unknown>]> = [];
 * const fake: ConsoleHandler = {
 *   emit(level, eventType, fields) {
 *     captured.push([level, eventType, fields]);
 *   },
 * };
 *
 * const tn = await Tn.init({ console: fake });
 * tn.info("test.event", { ok: true });
 * // captured -> [["info", "test.event", { ok: true, run_id: "..." }]]
 * ```
 *
 * @public
 */
export interface ConsoleHandler {
  /**
   * Receive a single emit. Always called BEFORE the wasm runtime
   * encrypts and persists the envelope, so `fields` is the plaintext
   * caller-supplied dict plus any active `tn.scope()` overlay.
   *
   * @param level - one of `"debug"`, `"info"`, `"warning"`, `"error"`,
   *   or `""` (severity-less `tn.log`).
   * @param eventType - the event type the caller passed (e.g.
   *   `"user.signed_in"`).
   * @param fields - merged plaintext fields (caller args + scope
   *   overlay + auto-injected `run_id`).
   */
  emit(level: string, eventType: string, fields: Record<string, unknown>): void;
}

/**
 * Build a {@link ConsoleHandler} that routes each emit to
 * `console.{debug|info|warn|error}` per level.
 *
 * @param opts - optional knobs.
 * @param opts.sink - the console-shaped object to invoke. Defaults to
 *   `globalThis.console`. Tests pass a fake to inspect what got
 *   printed without polluting the runner's stdout. Must expose the
 *   five methods `debug` / `info` / `warn` / `error` / `log`; missing
 *   methods fall through to `log`.
 *
 * @returns A {@link ConsoleHandler} ready to pass to
 *   `Tn.init({ console: ... })`.
 *
 * @example
 * ```ts
 * import { Tn, consoleHandler } from "@tnproto/sdk/browser";
 *
 * // Default: console-on at the global object.
 * await Tn.init();   // -> uses consoleHandler() implicitly
 *
 * // Custom sink that prefixes everything.
 * const prefixed = consoleHandler({
 *   sink: {
 *     debug: (...a) => console.debug("[tn]", ...a),
 *     info: (...a) => console.info("[tn]", ...a),
 *     warn: (...a) => console.warn("[tn]", ...a),
 *     error: (...a) => console.error("[tn]", ...a),
 *     log: (...a) => console.log("[tn]", ...a),
 *   },
 * });
 * await Tn.init({ console: prefixed });
 * ```
 *
 * @see {@link ConsoleHandler} - the type a custom handler must satisfy.
 * @see {@link httpHandler} - the orthogonal "ship envelopes to a
 *   server" sink. Both can be active simultaneously.
 *
 * @remarks
 * Wraps `console.*` calls in a try/catch so a custom sink throwing
 * never aborts the emit pipeline — mirrors the Rust-side handler
 * contract.
 *
 * Auto-injected SDK-internal fields like `run_id` are stripped from
 * the displayed payload to reduce per-line clutter.
 *
 * @public
 */
export function consoleHandler(opts?: { sink?: ConsoleLike }): ConsoleHandler {
  const sink: ConsoleLike = opts?.sink ?? (globalThis as { console: ConsoleLike }).console;
  return {
    emit(level: string, eventType: string, fields: Record<string, unknown>): void {
      const method = _methodFor(level, sink);
      const payload = _stripInternal(fields);
      try {
        // Single call: header string + payload object. DevTools shows
        // the message inline and the payload as an expandable object.
        // Two-arg call is the canonical JS-console shape.
        if (Object.keys(payload).length === 0) {
          method.call(sink, `[${eventType}]`);
        } else {
          method.call(sink, `[${eventType}]`, payload);
        }
      } catch {
        // Best-effort — a custom sink throwing must never abort the
        // emit pipeline.
      }
    },
  };
}

/**
 * Pick the right `console` method for a level. Falls back to
 * `sink.log` if the named one is missing (some embedded JS hosts
 * stub only a subset).
 */
function _methodFor(level: string, sink: ConsoleLike): (...args: unknown[]) => void {
  switch (level) {
    case "debug":
      return sink.debug ?? sink.log;
    case "warning":
      return sink.warn ?? sink.log;
    case "error":
      return sink.error ?? sink.log;
    // info + "" (severity-less `tn.log`) both go to console.info.
    default:
      return sink.info ?? sink.log;
  }
}

/**
 * Drop SDK-internal fields from the payload before showing it. `run_id`
 * is auto-injected by `Tn._mergeForEmit`; it clutters every line and
 * the developer didn't ask to see it.
 */
function _stripInternal(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (k === "run_id") continue;
    out[k] = v;
  }
  return out;
}
