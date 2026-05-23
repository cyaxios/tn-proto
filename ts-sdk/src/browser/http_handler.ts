// HTTP handler — ship each attested envelope to a remote URL.
//
// Witness-style transport: the wasm runtime fans every signed envelope
// through here, and we POST it to `opts.url`. The body is the canonical
// ndjson line the runtime would have written to a log file — byte-for-
// byte identical, so the server's signature / row_hash / chain checks
// run against exactly what was attested.
//
// Cut-point note: this handler attaches via wasm `addHandler`, so it
// fires AFTER encryption + signing. That's intentional — the wire bytes
// must be the attested envelope, not the caller's plaintext. The
// JS-layer `consoleHandler` is the opposite (plaintext, pre-encrypt);
// the two are complementary, not competitors.
//
// Default behavior is a 2-second batched queue with retries on 5xx and
// best-effort flushes on `pagehide` / `beforeunload`. Mirrors what the
// witness template does today.

/**
 * Knobs for `httpHandler`. The only required field is `url`; everything
 * else has a sensible default.
 */
export interface HttpHandlerOptions {
  /**
   * Where to POST each envelope. Method is hardcoded to `POST`; the
   * `Content-Type` defaults to `application/json` unless overridden in
   * `headers`.
   */
  url: string;
  /**
   * Extra request headers. Use this for auth tokens / agreement ids /
   * tenant headers. `Content-Type` defaults to `application/json` but
   * can be overridden here.
   */
  headers?: Record<string, string>;
  /**
   * Flush cadence in milliseconds. `0` ships every envelope immediately
   * in the emit callback (one fetch per emit, useful for low-volume
   * sources). Any positive number batches: envelopes accumulate in a
   * queue and flush together every `batchIntervalMs`.
   *
   * Default: `2000` (same as the witness harness).
   */
  batchIntervalMs?: number;
  /**
   * Attach `pagehide` + `beforeunload` listeners that drain the queue
   * before the tab dies. Uses `keepalive: true` on the lifecycle flush
   * so the browser is allowed to finish the request after the page
   * unloads. No-op when `globalThis.addEventListener` is missing (Node
   * tests, Web Workers without the BroadcastChannel-style lifecycle).
   *
   * Default: `true`.
   */
  flushOnUnload?: boolean;
  /**
   * Test seam — swap in a fake `fetch` to capture outgoing requests
   * without standing up an HTTP server.
   */
  fetch?: typeof fetch;
  /**
   * Called with the network error and the envelope that couldn't be
   * shipped. 5xx responses also surface here (the handler will retry
   * them on the next flush automatically). Default: `console.warn`.
   */
  onError?: (err: unknown, envelope: Record<string, unknown>) => void;
  /**
   * Handler name reported to the wasm runtime. Used for dedup and
   * debug output. Default: `"http"`.
   */
  name?: string;
}

/**
 * Shape the wasm runtime's `addHandler(...)` accepts. Same as
 * `crypto/tn-wasm/src/handlers.rs::JsHandler::from_js`.
 */
export interface WasmHandlerCallbacks {
  name: string;
  emit(envelope: Record<string, unknown>, rawLine: Uint8Array): void;
  accepts?(envelope: Record<string, unknown>): boolean;
  close?(): void;
}

/**
 * Returned by `httpHandler`. Carries the wasm-bound callback shape
 * (passed to `wasm.addHandler`) plus a JS-facing `flushPending()` so
 * `BrowserRuntime.close()` can `await` the final drain before tearing
 * down the wasm runtime.
 *
 * Wasm-side `close()` is fire-and-forget from JS's POV; relying on it
 * to ship in-flight envelopes before the script exits is racey. The
 * `flushPending()` Promise resolves once every queued envelope has
 * either succeeded (2xx), failed terminally (4xx), or been requeued for
 * retry (5xx / network). Caller can choose to keep awaiting if it
 * cares about the requeued ones — typically they let those wait for
 * the next page load or just let them drop.
 */
export interface HttpHandlerInstance extends WasmHandlerCallbacks {
  /** Await every queued envelope's first ship attempt. */
  flushPending(): Promise<void>;
}

/**
 * Build an HTTP-shipping handler suitable for
 * `wasm.addHandler(httpHandler({ url: "..." }))` or for the `http:`
 * knob on `Tn.init(...)`.
 */
export function httpHandler(opts: HttpHandlerOptions): HttpHandlerInstance {
  const url = opts.url;
  const batchIntervalMs = opts.batchIntervalMs ?? 2000;
  const flushOnUnload = opts.flushOnUnload !== false;
  const fetchImpl = opts.fetch ?? (globalThis as { fetch: typeof fetch }).fetch.bind(globalThis);
  const onError = opts.onError ?? _defaultOnError;
  const name = opts.name ?? "http";
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers ?? {}),
  };

  // Each queue entry pairs the parsed envelope (for diagnostics) with
  // the exact ndjson bytes the runtime wrote — that's what goes on the
  // wire. Server-side signature checks recompute over the canonical
  // bytes, so we must not re-serialize.
  interface QueueEntry {
    envelope: Record<string, unknown>;
    body: Uint8Array;
  }
  const queue: QueueEntry[] = [];
  let flushing = false;
  let timer: ReturnType<typeof setInterval> | null = null;

  function shipOne(entry: QueueEntry, lifecycle: boolean): Promise<void> {
    return fetchImpl(url, {
      method: "POST",
      headers,
      body: entry.body,
      keepalive: lifecycle,
    })
      .then((resp) => {
        if (!resp.ok) {
          // 5xx -> requeue for the next flush; 4xx -> drop with diagnostic.
          if (resp.status >= 500) {
            queue.push(entry);
            onError(new Error(`http ${resp.status} ${resp.statusText}`), entry.envelope);
          } else {
            onError(
              new Error(`http ${resp.status} ${resp.statusText} (dropping envelope)`),
              entry.envelope,
            );
          }
        }
      })
      .catch((err: unknown) => {
        // Network failure: requeue so the next flush retries.
        queue.push(entry);
        onError(err, entry.envelope);
      });
  }

  function flush(lifecycle = false): Promise<void> {
    if (flushing || queue.length === 0) return Promise.resolve();
    flushing = true;
    const batch = queue.splice(0, queue.length);
    return Promise.all(batch.map((e) => shipOne(e, lifecycle))).then(() => {
      flushing = false;
    });
  }

  function maybeStartTimer(): void {
    if (timer !== null || batchIntervalMs <= 0) return;
    timer = setInterval(() => {
      void flush(false);
    }, batchIntervalMs);
    // Some hosts (Node test runners) keep alive on pending timers; the
    // unref() opt-out lets the process exit naturally when no real work
    // is queued. No-op in browsers (the method doesn't exist there).
    const t = timer as unknown as { unref?: () => void };
    if (typeof t.unref === "function") t.unref();
  }

  // Page-lifecycle drain: best-effort, runs even after unload. The
  // duck-typed `addEventListener` lookup avoids needing the DOM lib in
  // tsconfig (this file is the only place that would need it, and the
  // SDK ships from a tsconfig that targets ES2022 without DOM).
  type AddListener = (
    type: string,
    listener: () => void,
    options?: unknown,
  ) => void;
  const target = globalThis as unknown as { addEventListener?: AddListener };
  if (flushOnUnload && typeof target.addEventListener === "function") {
    const drain = (): void => {
      void flush(true);
    };
    target.addEventListener("pagehide", drain);
    target.addEventListener("beforeunload", drain);
  }

  return {
    name,
    emit(envelope, rawLine): void {
      // Defensive copy of `rawLine`: the wasm-bindgen marshalling may
      // hand us a view backed by wasm linear memory; a later wasm call
      // could invalidate it before our flush runs.
      const body = new Uint8Array(rawLine);
      if (batchIntervalMs <= 0) {
        // Immediate ship — no queue, no timer.
        void shipOne({ envelope, body }, false);
        return;
      }
      queue.push({ envelope, body });
      maybeStartTimer();
    },
    close(): void {
      // Synchronous wasm-side close. Cancels the timer + fires a final
      // best-effort flush. JS callers who want to `await` the drain
      // should call `flushPending()` first.
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      void flush(true);
    },
    flushPending(): Promise<void> {
      // Stop the timer first so a concurrent timer-tick doesn't double-
      // start `flushing`. We intentionally leave `timer` un-nulled so a
      // subsequent emit re-starts it; callers who really want to retire
      // the handler should call `close()` after `flushPending()`.
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      return flush(true);
    },
  };
}

function _defaultOnError(err: unknown, envelope: Record<string, unknown>): void {
  const seq = envelope["sequence"];
  const et = envelope["event_type"];
  const safe: { console?: { warn?: (...args: unknown[]) => void } } = globalThis;
  safe.console?.warn?.("[tn:http] ship failed", { seq, event_type: et, error: err });
}
