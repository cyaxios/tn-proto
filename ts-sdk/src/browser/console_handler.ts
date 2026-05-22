// Console handler — print each emit to `globalThis.console` per level.
//
// JS / browser equivalent of the Node SDK's `StdoutHandler`. Default-on:
// `BrowserRuntime.init` constructs one of these unless the caller passes
// `console: false`. The verb pair is intentional:
//
//   Node     -> writes to `process.stdout`     (`opts.stdout`)
//   Browser  -> writes to `globalThis.console` (`opts.console`)
//
// Each speaks its language. Same role (default-on visibility for the
// developer), language-appropriate sink + option name.
//
// Routes plaintext (level, event_type, fields) -> console method so
// DevTools' built-in level filter works:
//
//   level "debug"    -> console.debug
//   level "info"     -> console.info
//   level ""         -> console.info   (severity-less `tn.log`)
//   level "warning"  -> console.warn
//   level "error"    -> console.error
//
// Format: `"[<event_type>]"` as the message string, with the plaintext
// fields object as the second argument so DevTools renders it as an
// expandable object inline with the message.
//
// **Why this is plaintext-based, not envelope-based:** the wasm-side
// `addHandler` callback runs *after* encryption — by that point every
// useful field has been swallowed by a group ciphertext blob and the
// console would show nothing but headers. The right cut-point is the
// browser runtime's emit verbs (where the caller's plaintext args are
// still in hand); see `BrowserRuntime.{info,log,warning,error,debug}`.

interface ConsoleLike {
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
  log(...args: unknown[]): void;
}

/**
 * What `BrowserRuntime` invokes for each emit. Constructed via
 * `consoleHandler()` for the default-on case; advanced consumers can
 * write their own object satisfying the same shape and pass it to
 * `Tn.init({ console: customHandler })` for an opt-in custom sink.
 */
export interface ConsoleHandler {
  emit(level: string, eventType: string, fields: Record<string, unknown>): void;
}

/**
 * Build a `ConsoleHandler` that routes each emit to
 * `console.{debug|info|warn|error}` per level.
 *
 * The default `sink` is `globalThis.console`. Tests pass a fake to
 * inspect what got printed without polluting the runner's stdout.
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
