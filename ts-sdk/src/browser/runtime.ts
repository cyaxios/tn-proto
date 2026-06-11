/**
 * Browser-side runtime.
 *
 * Thin JS wrapper around wasm `WasmRuntime`. Mirrors the slice of
 * `NodeRuntime` that the {@link Tn} class actually calls — emit verbs,
 * read, did, close, level management — without any of the Node-specific
 * infrastructure (handler registry, log rotation, agent-policy load,
 * admin BtnPublisher cache). Those land in later PRs as the
 * corresponding namespaces are ported.
 *
 * All disk I/O routes through a {@link JsStorageCallbacks} adapter —
 * {@link localStorageStorageAdapter} by default. The wasm runtime calls
 * those callbacks for every read/write/append; this class never
 * touches storage directly.
 *
 * @packageDocumentation
 */

import { WasmRuntime } from "tn-wasm";
import { createFreshCeremony, type CreateFreshOptions } from "./create_fresh.js";
import { createFromSeed, type CreateFromSeedOptions } from "./create_from_seed.js";
import { consoleHandler, type ConsoleHandler } from "./console_handler.js";
import { httpHandler, type HttpHandlerOptions, type HttpHandlerInstance } from "./http_handler.js";
import { localStorageStorageAdapter } from "../runtime/storage_localstorage.js";
import { memoryStorageAdapter } from "../runtime/storage_memory.js";
import type { JsStorageCallbacks } from "../runtime/storage_node.js";

/**
 * Options for {@link BrowserRuntime.init}. All optional; sensible
 * defaults for the standard browser use case (localStorage, console-on,
 * no HTTP shipping).
 *
 * @public
 */
export interface BrowserRuntimeOptions {
  /**
   * Storage adapter used for every fs-like callback the wasm runtime
   * makes. Defaults to a fresh `localStorageStorageAdapter()` rooted at
   * the standard `"tn/"` prefix.
   *
   * Tests and advanced consumers can pass a memory adapter, a
   * differently-prefixed localStorage adapter, or any other
   * `JsStorageCallbacks` impl.
   */
  storage?: JsStorageCallbacks;
  /**
   * Knobs forwarded to `createFreshCeremony` when the yaml doesn't
   * already exist in `storage`. Ignored when loading an existing
   * ceremony.
   */
  createFresh?: CreateFreshOptions;
  /**
   * Yaml storage key. Default: `"/v/tn.yaml"`, matching the default
   * `createFreshCeremony` output. If you change `createFresh.root` you
   * almost certainly want to change this too.
   */
  yamlPath?: string;
  /**
   * Default-on console handler — every emit also prints to
   * `globalThis.console` via the level-appropriate method
   * (`console.debug` / `console.info` / `console.warn` /
   * `console.error`). Pass `false` to silence the handler; the wasm
   * runtime still writes the encrypted envelope to storage either way.
   * Pass a `ConsoleHandler` to swap in a custom sink (useful for tests
   * and for piping logs to a remote endpoint in production).
   *
   * The JS / browser equivalent of Node's `opts.stdout`. Default: true.
   */
  console?: boolean | ConsoleHandler;
  /**
   * Default-off HTTP shipping. Pass a URL string (or full
   * `HttpHandlerOptions`) to register an `httpHandler` on the wasm
   * runtime; every attested envelope is then POSTed to that endpoint
   * (default: 2-second batched queue, retries on 5xx, drains on
   * `pagehide` / `beforeunload`).
   *
   * The handler ships the canonical ndjson bytes the runtime wrote —
   * byte-for-byte what would persist to a log file — so server-side
   * signature / row_hash / chain checks run against exactly what was
   * attested. The wasm runtime's local log write still happens; pair
   * with a `memoryStorageAdapter()` if you want the local copy to be
   * ephemeral.
   *
   * Default: no HTTP shipping.
   */
  http?: string | HttpHandlerOptions;
}

/**
 * Options for {@link BrowserRuntime.initFromSeed} / {@link Tn.initFromSeed}.
 * The seed material is required; storage + side-effect knobs are
 * optional with witness-friendly defaults (in-memory storage, no
 * console, HTTP shipping opt-in).
 *
 * Extends {@link CreateFromSeedOptions} — every keystore knob from
 * there is also accepted here.
 *
 * @public
 */
export interface BrowserRuntimeFromSeedOptions extends CreateFromSeedOptions {
  /**
   * Storage adapter. Default: a fresh `memoryStorageAdapter()` — the
   * witness pattern is "every page load re-bootstraps from server-
   * provisioned creds, never persists between sessions." Pass an
   * explicit adapter for other shapes.
   */
  storage?: JsStorageCallbacks;
  /**
   * Same shape as `BrowserRuntimeOptions.console`. Default `false` for
   * `initFromSeed` — server-shipped credentials usually mean a
   * production session where dev-mode console noise is unwanted. Set to
   * `true` (or a custom `ConsoleHandler`) to enable.
   */
  console?: boolean | ConsoleHandler;
  /** Same shape as `BrowserRuntimeOptions.http`. Default: off. */
  http?: string | HttpHandlerOptions;
}

/**
 * Wraps a single wasm `WasmRuntime` handle plus the JS-side console +
 * HTTP sinks. Construct via the static {@link BrowserRuntime.init} or
 * {@link BrowserRuntime.initFromSeed} factories; never
 * `new BrowserRuntime` directly.
 *
 * Most consumers should use the higher-level {@link Tn} class instead
 * — it adds context-stack merging, level filters, run-id stamping, and
 * the namespaced `tn.admin` / `tn.pkg` / `tn.vault` / `tn.agents` /
 * `tn.handlers` placeholders. `BrowserRuntime` is the low-level
 * runtime layer underneath.
 *
 * @example
 * ```ts
 * import { BrowserRuntime } from "tn-proto/browser";
 *
 * const rt = BrowserRuntime.init();   // mints fresh ceremony on first call
 * rt.info("hello.world", { who: "alice" });
 * for (const e of rt.read()) console.log(e);
 * await rt.close();   // awaits HTTP flush + closes wasm
 * ```
 *
 * @public
 */
export class BrowserRuntime {
  /** The wasm runtime handle this instance owns. */
  private readonly _wasm: WasmRuntime;
  /** The storage adapter we handed to the wasm runtime. Kept so admin /
   *  pkg verbs can call back into it without re-resolving. */
  readonly storage: JsStorageCallbacks;
  /** Resolved yaml path the wasm runtime loaded from. */
  readonly yamlPath: string;
  /** Console handler invoked before each wasm emit. `null` when the
   *  caller passed `console: false`. */
  private readonly _console: ConsoleHandler | null;
  /** HTTP handler registered with the wasm runtime, if any. Kept on
   *  the JS side so `close()` can await its `flushPending()` before
   *  tearing down the wasm runtime (wasm-side close is fire-and-
   *  forget). `null` when the caller didn't opt in to HTTP shipping. */
  private readonly _http: HttpHandlerInstance | null;

  private constructor(
    wasm: WasmRuntime,
    storage: JsStorageCallbacks,
    yamlPath: string,
    consoleSink: ConsoleHandler | null,
    httpSink: HttpHandlerInstance | null,
  ) {
    this._wasm = wasm;
    this.storage = storage;
    this.yamlPath = yamlPath;
    this._console = consoleSink;
    this._http = httpSink;
  }

  /**
   * Load a ceremony from `storage`, minting fresh on first call.
   *
   * If the yaml doesn't exist at `opts.yamlPath`,
   * {@link createFreshCeremony} runs first; then the yaml + storage
   * are handed to `WasmRuntime.initWith` and the handle is cached.
   *
   * @param opts - see {@link BrowserRuntimeOptions}.
   *
   * @returns A ready-to-use `BrowserRuntime`. Subsequent calls in the
   *   same origin with the same `storage` re-load the same ceremony
   *   (same DID, same chain).
   *
   * @throws Error - propagated from `createFreshCeremony` (clobber
   *   guard) or `WasmRuntime.initWith` (malformed yaml, missing
   *   keystore members).
   *
   * @example
   * ```ts
   * import { BrowserRuntime } from "tn-proto/browser";
   *
   * // Default: localStorage adapter, console-on, no HTTP.
   * const rt = BrowserRuntime.init();
   *
   * // With HTTP shipping + custom storage.
   * const rt2 = BrowserRuntime.init({
   *   storage: memoryStorageAdapter(),
   *   http: "https://ingest.example.com/intake",
   *   console: false,
   * });
   * ```
   *
   * @see {@link BrowserRuntime.initFromSeed} - the variant for
   *   server-provisioned credentials.
   * @see {@link Tn.init} - the higher-level wrapper.
   */
  static init(opts: BrowserRuntimeOptions = {}): BrowserRuntime {
    const storage = opts.storage ?? localStorageStorageAdapter();
    const yamlPath = opts.yamlPath ?? "/v/tn.yaml";

    if (!storage.exists(yamlPath)) {
      createFreshCeremony(storage, opts.createFresh ?? {});
    }

    return BrowserRuntime._wireUpWasm(storage, yamlPath, {
      console: opts.console,
      http: opts.http,
      consoleDefaultOn: true,
    });
  }

  /**
   * Bootstrap a runtime from caller-supplied seed material instead of
   * minting fresh on the JS side.
   *
   * Use when a server has already generated the device key + BTN
   * publisher state (witness-style flows where every browser session
   * adopts server-provisioned credentials).
   *
   * Defaults differ from {@link BrowserRuntime.init}:
   *
   * - `storage` defaults to a fresh in-memory adapter (no persistence
   *   between sessions — server re-issues creds on every page load).
   * - `console` defaults to OFF (production-session vibes; turn on
   *   explicitly for debugging).
   *
   * @param opts - see {@link BrowserRuntimeFromSeedOptions}. `seed` +
   *   `btnPublisherState` are required.
   *
   * @returns A ready-to-use `BrowserRuntime` bound to the supplied
   *   identity. `rt.did()` matches `DeviceKey.fromSeed(opts.seed).did`.
   *
   * @throws Error - propagated from {@link createFromSeed} (bad seed
   *   length, empty publisher state, clobber guard).
   *
   * @example
   * ```ts
   * import { BrowserRuntime } from "tn-proto/browser";
   *
   * const rt = BrowserRuntime.initFromSeed({
   *   seed: b64decode(PUBLISHER_SEED_B64),
   *   btnPublisherState: b64decode(BTN_PUBLISHER_STATE_B64),
   *   http: { url: INGEST_URL, headers: { "X-Agreement": agreementId } },
   * });
   * ```
   *
   * @see {@link BrowserRuntime.init} - the fresh-mint variant.
   * @see {@link createFromSeed} - the lower-level synthesis helper.
   * @see {@link Tn.initFromSeed} - the higher-level wrapper with the
   *   full `Tn` surface.
   *
   * @remarks
   * The yaml + keystore the wasm runtime reads are byte-identical to
   * what {@link BrowserRuntime.init} produces — only the source of the
   * seed + publisher-state bytes differs. See {@link createFromSeed}
   * for the synthesis details.
   */
  static initFromSeed(opts: BrowserRuntimeFromSeedOptions): BrowserRuntime {
    const storage = opts.storage ?? memoryStorageAdapter();
    const result = createFromSeed(storage, opts);
    return BrowserRuntime._wireUpWasm(storage, result.yamlPath, {
      console: opts.console,
      http: opts.http,
      consoleDefaultOn: false,
    });
  }

  /**
   * Shared plumbing: hand the yaml + storage to wasm, wire up the
   * console + http handlers per the caller's opts, and box the result
   * in a `BrowserRuntime` instance.
   *
   * `consoleDefaultOn` is the only place `init` and `initFromSeed`
   * disagree on default behavior. `init` defaults to console-on (dev
   * usage); `initFromSeed` defaults to off (production usage).
   */
  private static _wireUpWasm(
    storage: JsStorageCallbacks,
    yamlPath: string,
    sinks: {
      console: boolean | ConsoleHandler | undefined;
      http: string | HttpHandlerOptions | undefined;
      consoleDefaultOn: boolean;
    },
  ): BrowserRuntime {
    // `initWith` is the variant that takes an opts object; we pass an
    // empty bag for now. `skipCeremonyInitEmit` is a NodeRuntime concern
    // (it attaches wasm lazily after the TS side has already taken
    // responsibility for the init event) and doesn't apply here — the
    // browser runtime IS the wasm runtime, no lazy attach.
    const wasm = WasmRuntime.initWith(yamlPath, storage, {});

    // Resolve the console sink. The default depends on the caller —
    // `init` defaults console on (dev usage); `initFromSeed` defaults
    // off (production usage).
    let consoleSink: ConsoleHandler | null;
    if (sinks.console === false) {
      consoleSink = null;
    } else if (sinks.console && typeof sinks.console === "object") {
      consoleSink = sinks.console;
    } else if (sinks.console === true) {
      consoleSink = consoleHandler();
    } else {
      consoleSink = sinks.consoleDefaultOn ? consoleHandler() : null;
    }

    // Resolve the HTTP sink. Default off. String -> URL only; object ->
    // full options. The handler is registered on the wasm side so it
    // gets the post-encryption / post-signing envelope bytes — what the
    // server must see to verify the chain. We also keep a JS-side
    // reference so `close()` can await the final flush.
    let httpSink: HttpHandlerInstance | null = null;
    if (sinks.http !== undefined) {
      const httpOpts: HttpHandlerOptions =
        typeof sinks.http === "string" ? { url: sinks.http } : sinks.http;
      httpSink = httpHandler(httpOpts);
      wasm.addHandler(httpSink);
    }

    return new BrowserRuntime(wasm, storage, yamlPath, consoleSink, httpSink);
  }

  /** The publisher DID this runtime emits as. `did:key:z…`. */
  did(): string {
    return this._wasm.did();
  }

  /** Severity-less attested event. See `WasmRuntime.log`. */
  log(eventType: string, fields: Record<string, unknown>): void {
    this._console?.emit("", eventType, fields);
    this._wasm.log(eventType, fields);
  }

  /** DEBUG-level attested event. */
  debug(eventType: string, fields: Record<string, unknown>): void {
    this._console?.emit("debug", eventType, fields);
    this._wasm.debug(eventType, fields);
  }

  /** INFO-level attested event. */
  info(eventType: string, fields: Record<string, unknown>): void {
    this._console?.emit("info", eventType, fields);
    this._wasm.info(eventType, fields);
  }

  /** WARNING-level attested event. */
  warning(eventType: string, fields: Record<string, unknown>): void {
    this._console?.emit("warning", eventType, fields);
    this._wasm.warning(eventType, fields);
  }

  /** ERROR-level attested event. */
  error(eventType: string, fields: Record<string, unknown>): void {
    this._console?.emit("error", eventType, fields);
    this._wasm.error(eventType, fields);
  }

  /**
   * Read every entry from the main log as flat JS objects. Each entry
   * carries the six envelope basics (timestamp, event_type, level, did,
   * sequence, event_id) plus every readable group's decrypted fields
   * hoisted to the top level.
   *
   * Routes through wasm's `readAllRuns()` rather than `read()`. The
   * `read()` variant filters to the process's `$TN_RUN_ID`, which is a
   * Node-CLI invariant ("each CLI invocation is a new run, only show
   * mine") that doesn't translate to the browser — a tab IS the run.
   * `readAllRuns()` matches Python's `tn.read(all_runs=True)` default
   * and is what browser callers actually want.
   */
  read(): Array<Record<string, unknown>> {
    return this._wasm.readAllRuns() as Array<Record<string, unknown>>;
  }

  /** Audit-grade read returning `{envelope, plaintext}` per entry. */
  readRaw(): Array<Record<string, unknown>> {
    return this._wasm.readRaw() as Array<Record<string, unknown>>;
  }

  /** Process-wide level threshold as a name (`debug` / `info` / `warning` / `error`). */
  static getLevel(): string {
    return WasmRuntime.getLevel();
  }

  /** Set the process-wide level threshold by name. */
  static setLevel(level: string): void {
    WasmRuntime.setLevel(level);
  }

  /** True iff `level` would currently emit. */
  static isEnabledFor(level: string): boolean {
    return WasmRuntime.isEnabledFor(level);
  }

  /**
   * Drain pending out-of-process handlers (e.g. the HTTP queue) without
   * tearing down the runtime. Use before navigating away if you want to
   * give every queued envelope a chance to land. No-op when no handler
   * has anything queued.
   */
  async flush(): Promise<void> {
    if (this._http !== null) {
      await this._http.flushPending();
    }
  }

  /**
   * Explicit flush + close. Awaits any pending HTTP shipments before
   * closing the wasm runtime so envelopes the caller already enqueued
   * don't get dropped on shutdown.
   */
  async close(): Promise<void> {
    await this.flush();
    this._wasm.close();
  }
}
