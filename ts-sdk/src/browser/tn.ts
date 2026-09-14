/**
 * Browser TN client with localStorage or injected storage.
 *
 * Supports ceremony creation, server-provisioned credentials, logging,
 * context, reads, sealed objects, and HTTP delivery.
 *
 * @packageDocumentation
 */

import {
  BrowserRuntime,
  type BrowserRuntimeOptions,
  type BrowserRuntimeFromSeedOptions,
} from "./runtime.js";
import { normalizeLogFields } from "../_log_fields.js";
import {
  sealWithBrowserRuntime,
  unsealWithBrowserRuntime,
  type BrowserUnsealOptions,
} from "./seal.js";
import type {
  SealOptions,
  SealedObject,
  SealedTriple,
  UnsealSource,
} from "../core/sealed_object.js";
import type { Entry } from "../Entry.js";

// ---------------------------------------------------------------------------
// Module-level state — mirrors src/tn.ts (`_tnLogLevelThreshold`, run_id).
// ---------------------------------------------------------------------------

const _LOG_LEVELS = {
  debug: 10,
  info: 20,
  warning: 30,
  error: 40,
} as const;

/**
 * Standard log-level numeric values. Mirrors stdlib Python `logging`.
 *
 * Use the int values when porting code from Python that compares
 * levels numerically. Prefer the string forms ("debug", "info",
 * "warning", "error") when calling {@link Tn.setLevel} or
 * {@link Tn.isEnabledFor}.
 *
 * @example
 * ```ts
 * import { LOG_LEVELS, Tn } from "tn-proto/browser";
 *
 * Tn.setLevel("warning");   // string form (idiomatic)
 * if (LOG_LEVELS.warning <= myThreshold) emit();   // int form (Python parity)
 * ```
 *
 * @public
 */
export const LOG_LEVELS: typeof _LOG_LEVELS = _LOG_LEVELS;

/**
 * String union of valid log-level names. Pass to {@link Tn.setLevel} or
 * {@link Tn.isEnabledFor}.
 *
 * @public
 */
export type LogLevel = keyof typeof _LOG_LEVELS;

/** Process-wide level threshold. Default: debug (10). */
let _tnLogLevelThreshold: number = _LOG_LEVELS.debug;

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * Options forwarded to {@link Tn.init}. Identical to
 * {@link BrowserRuntimeOptions} — see that interface for field docs.
 *
 * Aliased (rather than `interface ... extends`) so the typechecker
 * carries the field-by-field shape into hover output instead of an
 * opaque supertype reference, and so eslint's `no-empty-object-type`
 * rule doesn't fire on the empty interface body.
 *
 * @public
 */
export type TnInitOptions = BrowserRuntimeOptions;

/**
 * Options forwarded to {@link Tn.initFromSeed}. Identical to
 * {@link BrowserRuntimeFromSeedOptions} — see that interface for
 * field docs. Aliased for the same reasons as {@link TnInitOptions}.
 *
 * @public
 */
export type TnInitFromSeedOptions = BrowserRuntimeFromSeedOptions;

// ---------------------------------------------------------------------------
// Tn class
// ---------------------------------------------------------------------------

/**
 * Browser-side TN client.
 *
 * Construct a client through the static factories:
 *
 * - {@link Tn.init} — load from localStorage, mint fresh on first call.
 * - {@link Tn.initFromSeed} — adopt server-provisioned credentials.
 *
 * @example
 * ```ts
 * import { Tn } from "tn-proto/browser";
 *
 * // Standard usage: mint or load from localStorage.
 * const tn = await Tn.init();
 *
 * tn.info("user.signed_in", { user_id: "u_123" });
 * tn.warning("rate_limit.approaching", { remaining: 5 });
 *
 * for (const e of tn.read()) {
 *   console.log(e.sequence, e.event_type, e.user_id);
 * }
 *
 * await tn.close();
 * ```
 *
 * @example
 * ```ts
 * // Witness-style: server provisions credentials, ship to ingest URL.
 * import { Tn } from "tn-proto/browser";
 *
 * const tn = await Tn.initFromSeed({
 *   seed: b64decode(PUBLISHER_SEED_B64),
 *   btnPublisherState: b64decode(BTN_PUBLISHER_STATE_B64),
 *   http: { url: INGEST_URL, headers: { "X-Agreement": agreementId } },
 * });
 *
 * tn.info("witness.observer", { kind: "agreement.success" });
 * await tn.close();   // awaits HTTP flush before tearing down
 * ```
 *
 * @public
 */
export class Tn {
  private readonly _rt: BrowserRuntime;
  private readonly _runId: string;
  private _contextStack: Array<Record<string, unknown>> = [{}];

  private constructor(rt: BrowserRuntime) {
    this._rt = rt;
    // Cheap browser-safe run id: 16 random bytes hex-encoded. Mirrors
    // the shape of `randomUUID().replace(/-/g, "")` from src/tn.ts but
    // doesn't depend on `node:crypto`.
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    let s = "";
    for (let i = 0; i < buf.length; i += 1) {
      const b = buf[i] ?? 0;
      s += b.toString(16).padStart(2, "0");
    }
    this._runId = s;
  }

  // -------------------------------------------------------------------------
  // Static factory methods
  // -------------------------------------------------------------------------

  /**
   * Load or create a ceremony in browser storage and return a client
   * bound to it. Mirrors Python `tn.init` and Node `Tn.init`.
   *
   * On first call in a given origin (or after `localStorage.clear()`
   * + page reload), a fresh ceremony is minted: device key, BTN
   * publisher + self-kit, index master, full `tn.yaml`. Every
   * subsequent call loads the existing material — same DID, same
   * chain.
   *
   * @param opts - see {@link TnInitOptions}. All optional.
   *
   * @returns A ready-to-use `Tn`. The returned Promise resolves on the
   *   next microtask — async is for API parity with Node.
   *
   * @throws Error - propagated from the underlying
   *   {@link BrowserRuntime.init} (clobber guard, malformed yaml).
   *
   * @example
   * ```ts
   * import { Tn } from "tn-proto/browser";
   *
   * // Default: localStorage adapter, console-on.
   * const tn = await Tn.init();
   * tn.info("hello.world", { who: "alice" });
   * for (const e of tn.read()) console.log(e);
   * await tn.close();
   * ```
   *
   * @example
   * ```ts
   * // With HTTP shipping + custom storage prefix.
   * const tn = await Tn.init({
   *   storage: memoryStorageAdapter(),
   *   http: "https://ingest.example.com/intake",
   *   console: false,
   * });
   * ```
   *
   * @see {@link Tn.initFromSeed} - the variant for server-provisioned credentials.
   * @see {@link TnInitOptions}
   *
   * @public
   */
  static async init(opts?: TnInitOptions): Promise<Tn> {
    const rt = BrowserRuntime.init(opts ?? {});
    return new Tn(rt);
  }

  /**
   * Bootstrap a `Tn` from caller-supplied seed material (32-byte
   * Ed25519 seed + a pre-minted `BtnPublisher.toBytes()` state) rather
   * than minting fresh on the client.
   *
   * Use when a server has already generated the device identity +
   * publisher state per session / agreement and delivers them to the
   * browser (witness-style flow).
   *
   * **Defaults differ from {@link Tn.init}:**
   *
   * - `storage` defaults to a fresh in-memory adapter (no persistence
   *   between sessions).
   * - `console` defaults to OFF — production-session vibes; pass
   *   `console: true` to opt in to dev visibility.
   *
   * @param opts - see {@link TnInitFromSeedOptions}. `seed` and
   *   `btnPublisherState` are required.
   *
   * @returns A ready-to-use `Tn`. `tn.did()` matches
   *   `DeviceKey.fromSeed(opts.seed).did`.
   *
   * @throws Error - propagated from {@link BrowserRuntime.initFromSeed}
   *   (bad seed length, empty publisher state, clobber guard).
   *
   * @example
   * ```ts
   * import { Tn } from "tn-proto/browser";
   *
   * // Witness-style: server provisions seed + state, ships to ingest.
   * const tn = await Tn.initFromSeed({
   *   seed: b64decode(PUBLISHER_SEED_B64),
   *   btnPublisherState: b64decode(BTN_PUBLISHER_STATE_B64),
   *   http: { url: INGEST_URL, headers: { "X-Agreement": agreementId } },
   * });
   *
   * tn.info("witness.observer", { kind: "agreement.success" });
   * await tn.close();   // awaits HTTP flush
   * ```
   *
   * @see {@link Tn.init} - the fresh-mint variant.
   * @see {@link TnInitFromSeedOptions}
   * @see {@link createFromSeed} - lower-level keystore-synthesis helper.
   *
   * @public
   */
  static async initFromSeed(opts: TnInitFromSeedOptions): Promise<Tn> {
    const rt = BrowserRuntime.initFromSeed(opts);
    return new Tn(rt);
  }

  /**
   * Set the process-wide level threshold. Verbs below the threshold
   * become no-ops; verbs at-or-above emit normally. `tn.log` ignores
   * the threshold (it's severity-less by design).
   *
   * Default threshold: `"debug"` (everything emits).
   *
   * @param level - one of `"debug"`, `"info"`, `"warning"`, `"error"`.
   *
   * @example
   * ```ts
   * Tn.setLevel("warning");
   * tn.info("noise");         // dropped
   * tn.warning("real event"); // emits
   * tn.error("worse event");  // emits
   * tn.log("audit fact");     // emits (severity-less)
   * ```
   *
   * @see {@link Tn.getLevel} {@link Tn.isEnabledFor}
   * @see {@link LOG_LEVELS} - numeric values mirroring Python `logging`.
   * @public
   */
  static setLevel(level: LogLevel | string): void {
    BrowserRuntime.setLevel(String(level));
    if (level in _LOG_LEVELS) {
      _tnLogLevelThreshold = _LOG_LEVELS[level as LogLevel];
    }
  }

  /**
   * Read the active level threshold as a name.
   *
   * @returns One of `"debug"`, `"info"`, `"warning"`, `"error"` (or
   *   the stringified numeric value if a custom threshold was set via
   *   {@link Tn.setLevel}).
   *
   * @example
   * ```ts
   * Tn.setLevel("info");
   * Tn.getLevel();   // "info"
   * ```
   *
   * @see {@link Tn.setLevel}
   * @public
   */
  static getLevel(): string {
    return BrowserRuntime.getLevel();
  }

  /**
   * Whether emits at `level` would currently fire. Useful to gate
   * expensive field construction.
   *
   * Mirrors Python `tn.is_enabled_for(level)` and stdlib
   * `logging.Logger.isEnabledFor`.
   *
   * @param level - the level to check.
   *
   * @returns `true` iff a call to the matching emit verb would
   *   produce an envelope (i.e. the level threshold permits it).
   *
   * @example
   * ```ts
   * if (Tn.isEnabledFor("debug")) {
   *   tn.debug("expensive.trace", buildExpensivePayload());
   * }
   * ```
   *
   * @see {@link Tn.setLevel}
   * @public
   */
  static isEnabledFor(level: LogLevel | string): boolean {
    return BrowserRuntime.isEnabledFor(String(level));
  }

  // -------------------------------------------------------------------------
  // Identity / diagnostics
  // -------------------------------------------------------------------------

  /** This client's publisher DID (`did:key:z…`). */
  did(): string {
    return this._rt.did();
  }

  /** Whether the underlying runtime is the Rust wasm core. Always true here. */
  usingRust(): boolean {
    return true;
  }

  /** The browser runtime backing this Tn. Exposed for tests + advanced use. */
  runtime(): BrowserRuntime {
    return this._rt;
  }

  // -------------------------------------------------------------------------
  // Context management — same shape as src/tn.ts.
  // -------------------------------------------------------------------------

  /** Build the merged fields dict: scope-stack + caller fields + run_id. */
  private _mergeForEmit(rawFields: Record<string, unknown>): Record<string, unknown> {
    const merged: Record<string, unknown> = {};
    for (const layer of this._contextStack) {
      for (const [k, v] of Object.entries(layer)) merged[k] = v;
    }
    for (const [k, v] of Object.entries(rawFields)) merged[k] = v;
    if (!("run_id" in merged)) merged["run_id"] = this._runId;
    return merged;
  }

  /** Block-scoped context overlay. Mirrors Python `with tn.scope(**fields):`. */
  scope<T>(fields: Record<string, unknown>, body: () => T): T {
    this._contextStack.push({ ...fields });
    try {
      return body();
    } finally {
      this._contextStack.pop();
    }
  }

  /** Replace the long-lived context with `fields`. */
  setContext(fields: Record<string, unknown>): void {
    this._contextStack[0] = { ...fields };
  }

  /** Merge `fields` into the long-lived context (additive). */
  updateContext(fields: Record<string, unknown>): void {
    this._contextStack[0] = { ...this._contextStack[0], ...fields };
  }

  /** Drop the long-lived context and any nested scopes. */
  clearContext(): void {
    this._contextStack = [{}];
  }

  /** A shallow copy of the merged context. */
  getContext(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const layer of this._contextStack) {
      for (const [k, v] of Object.entries(layer)) out[k] = v;
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Write verbs — same overload shape as src/tn.ts.
  // -------------------------------------------------------------------------

  /**
   * Severity-less attested event. ALWAYS emits — bypasses the
   * `Tn.setLevel` threshold filter by design. Use for "this is a
   * fact" assertions whose visibility shouldn't depend on the active
   * log level (audit landmarks, schema migrations, ceremony boundary
   * markers).
   *
   * Mirrors Python `tn.log(event_type, **fields)`.
   *
   * @param eventType - dotted event identifier. Must match
   *   `[A-Za-z0-9._-]{1,64}`. Examples: `"user.signed_in"`,
   *   `"schema.migrated"`, `"ceremony.opened"`.
   * @param msgOrFields - either a plain string message (auto-promoted
   *   to `{message: <str>}`) or a fields object. Optional.
   * @param fieldsIfMessage - if `msgOrFields` is a string, these
   *   additional fields merge with `{message}`. Ignored otherwise.
   *
   * @example
   * ```ts
   * tn.log("schema.migrated", { from: "v1", to: "v2" });
   * tn.log("ceremony.opened");                          // no fields
   * tn.log("audit.event", "compliance marker", { id: 42 }); // string + fields
   * ```
   *
   * @see {@link Tn.info} - filtered by level; use for routine events.
   * @see {@link Tn.warning} {@link Tn.error} - level-tagged variants.
   * @see {@link Tn.read} - read entries back.
   *
   * @remarks
   * Auto-injects the process's `run_id` and any active scope-stack
   * fields via the shared `_mergeForEmit` path.
   *
   * @public
   */
  log(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    this._rt.log(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  /**
   * DEBUG-level attested event. Suppressed when the process-wide
   * level threshold is above DEBUG (10).
   *
   * Mirrors Python `tn.debug(event_type, **fields)`.
   *
   * @param eventType - dotted event identifier.
   * @param msgOrFields - string message OR fields object.
   * @param fieldsIfMessage - additional fields when `msgOrFields` is a string.
   *
   * @example
   * ```ts
   * tn.debug("cache.lookup", { key: "u:123", hit: false });
   * tn.debug("trace.entered", "fn=processOrder", { order_id: "o_456" });
   * ```
   *
   * @see {@link Tn.setLevel} - control which levels emit.
   * @public
   */
  debug(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (10 < _tnLogLevelThreshold) return;
    this._rt.debug(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  /**
   * INFO-level attested event. The most common emit verb — use for
   * routine business events that should be visible in DevTools and
   * persisted to the chain.
   *
   * Suppressed when the process-wide level threshold is above INFO
   * (20). Mirrors Python `tn.info(event_type, **fields)`.
   *
   * @param eventType - dotted event identifier.
   * @param msgOrFields - string message OR fields object.
   * @param fieldsIfMessage - additional fields when `msgOrFields` is a string.
   *
   * @example
   * ```ts
   * tn.info("user.signed_in", { user_id: "u_123" });
   * tn.info("checkout.completed", "order placed", { order_id: "o_456" });
   * tn.info("startup");
   * ```
   *
   * @see {@link Tn.log} - severity-less variant for facts.
   * @see {@link Tn.warning} - for events worth highlighting.
   * @see {@link Tn.read} - read entries back.
   *
   * @remarks
   * The DevTools console handler routes this to `console.info` so the
   * built-in level filter works.
   *
   * @public
   */
  info(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (20 < _tnLogLevelThreshold) return;
    this._rt.info(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  /**
   * WARNING-level attested event. Use for recoverable anomalies —
   * rate limits approaching, degraded paths, retries.
   *
   * Suppressed when the process-wide level threshold is above WARNING
   * (30). Mirrors Python `tn.warning(event_type, **fields)`.
   *
   * @param eventType - dotted event identifier.
   * @param msgOrFields - string message OR fields object.
   * @param fieldsIfMessage - additional fields when `msgOrFields` is a string.
   *
   * @example
   * ```ts
   * tn.warning("rate_limit.approaching", { remaining: 5 });
   * tn.warning("retry.attempted", "third try", { attempt: 3 });
   * ```
   *
   * @see {@link Tn.error} - for unrecoverable failures.
   * @public
   */
  warning(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (30 < _tnLogLevelThreshold) return;
    this._rt.warning(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  /**
   * ERROR-level attested event. Use for unrecoverable failures —
   * caught exceptions, terminal protocol errors, integrity check
   * failures.
   *
   * Suppressed when the process-wide level threshold is above ERROR
   * (40). Mirrors Python `tn.error(event_type, **fields)`.
   *
   * @param eventType - dotted event identifier.
   * @param msgOrFields - string message OR fields object.
   * @param fieldsIfMessage - additional fields when `msgOrFields` is a string.
   *
   * @example
   * ```ts
   * tn.error("payment.failed", { code: "card_declined", order_id: "o_456" });
   * tn.error("integrity.broken", "row_hash mismatch", { sequence: 42 });
   * ```
   *
   * @see {@link Tn.warning} - for recoverable anomalies.
   * @public
   */
  error(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (40 < _tnLogLevelThreshold) return;
    this._rt.error(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  // -------------------------------------------------------------------------
  // Read verbs
  // -------------------------------------------------------------------------

  /**
   * Read every entry from the main log as flat JS objects.
   *
   * Each entry carries the six envelope basics (`timestamp`,
   * `event_type`, `level`, `did`, `sequence`, `event_id`) plus every
   * readable group's decrypted fields hoisted to the top level — the
   * same flat shape Python's `tn.read()` returns by default.
   *
   * @returns Array of flat-shaped entries. Materialised eagerly from
   *   wasm; ordered by emit-time (oldest first).
   *
   * @example
   * ```ts
   * for (const e of tn.read()) {
   *   console.log(e.sequence, e.event_type, e.user_id);
   * }
   * ```
   *
   * @see {@link Tn.readRaw} - audit-grade variant with full envelope +
   *   per-group plaintext map.
   *
   * @public
   */
  read(): Array<Record<string, unknown>> {
    return this._rt.read();
  }

  /**
   * Audit-grade read returning `{envelope, plaintext}` per entry. Use
   * when you need the full on-disk envelope (signatures, hashes,
   * group ciphertext metadata) alongside the decrypted fields.
   *
   * @returns Array of `{envelope, plaintext}` records.
   *
   * @example
   * ```ts
   * for (const row of tn.readRaw()) {
   *   verifySignature(row.envelope.signature, row.envelope.row_hash);
   *   const decrypted = row.plaintext.default;   // per-group plaintext map
   * }
   * ```
   *
   * @see {@link Tn.read} - flat-shaped convenience variant.
   * @public
   */
  readRaw(): Array<Record<string, unknown>> {
    return this._rt.readRaw();
  }

  /**
   * Seal fields into a portable attested object (standalone envelope)
   * using this ceremony's groups and key material. The receipt row (on
   * by default) chains through the live wasm write path. Mirrors the
   * Node `tn.seal(objectType, fields)` / Python `tn.seal(object_type,
   * **fields)`.
   *
   * @example
   * ```ts
   * const sealed = await tn.seal("obj.invoice.v1", { amount: 42 });
   * sendSomewhere(sealed.rawJson);   // verbatim wire string
   * ```
   */
  async seal(
    objectType: string,
    fields: Record<string, unknown> = {},
    opts: SealOptions = {},
  ): Promise<SealedObject> {
    return sealWithBrowserRuntime(this._rt, objectType, fields, opts);
  }

  /**
   * Verify a sealed object and open every group block a held key fits,
   * walking this ceremony's keystore. With `asRecipient` (a
   * {filename -> bytes} key bag — the browser analog of a recipient
   * keystore directory) only the named `group` is opened and the
   * ceremony is not consulted. Mirrors Node/Python `tn.unseal`.
   */
  async unseal(
    source: UnsealSource,
    opts: BrowserUnsealOptions = {},
  ): Promise<Entry | SealedTriple> {
    return unsealWithBrowserRuntime(this._rt, source, opts);
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /**
   * Flush the HTTP delivery queue without closing the runtime. Use before
   * navigating away if you want every queued envelope to land — the
   * `pagehide` listener does this automatically when
   * `http.flushOnUnload !== false`, but explicit `await tn.flush()`
   * is useful in handlers where you need to know the ship completed.
   *
   * Mirror of Python `tn.flush()`.
   *
   * @returns A Promise that resolves once every queued POST has
   *   settled (success / 4xx-drop / 5xx-requeue). The requeued ones
   *   wait for the next flush — caller can re-`await flush()` to chase
   *   them.
   *
   * @example
   * ```ts
   * // Make sure analytics events ship before showing a confirmation modal.
   * tn.info("checkout.completed", { order_id });
   * await tn.flush();
   * showConfirmation();
   * ```
   *
   * @see {@link Tn.close} - flush + close in one step.
   * @public
   */
  async flush(): Promise<void> {
    await this._rt.flush();
  }

  /**
   * Flush pending handlers, then close the wasm runtime.
   *
   * Idempotent at the JS level; safe to call multiple times. Awaits
   * the HTTP queue (if any) before tearing down the wasm, so emits
   * issued right before `await tn.close()` land on the wire.
   *
   * @returns A Promise that resolves when flush + close are both
   *   complete.
   *
   * @example
   * ```ts
   * window.addEventListener("beforeunload", () => {
   *   tn.close();   // fire-and-forget; the http handler uses keepalive
   * });
   *
   * // Or, in a controlled shutdown:
   * await tn.close();
   * ```
   *
   * @see {@link Tn.flush} - drain without closing.
   * @public
   */
  async close(): Promise<void> {
    await this._rt.close();
  }
}
