// @tnproto/sdk — browser-native Tn class.
//
// Same verb surface as the Node `Tn` class (src/tn.ts), same names,
// same call shapes. Only the runtime differs: this version wraps a
// browser-local `BrowserRuntime` (which in turn wraps the wasm
// `WasmRuntime`) using a localStorage-backed storage adapter by default.
//
// Python verb parity is the hard contract:
//
//   const tn = await Tn.init();
//   tn.info("hello.world", { who: "alice" });
//   for (const e of tn.read()) console.log(e);
//   await tn.close();
//
// reads identically in Python, Node, and the browser.
//
// Surface NOT yet wired (placeholders throw `NotYetWiredForBrowserError`
// so the shape stays intact and the error is unambiguous):
//
//   * `tn.admin.*`, `tn.pkg.*`, `tn.vault.*`, `tn.agents.*`, `tn.handlers.*`
//     — namespace ports follow once the underlying modules go browser-pure.
//   * `tn.watch(...)` — async iter; needs a localStorage-aware tail walker.
//   * `Tn.use(name, opts)` / `Tn.listCeremonies()` — multi-ceremony.
//   * `Tn.absorb(source)` — needs a browser-pure tnpkg reader.
//   * `Tn.ephemeral(opts)` — Node-only (tempdir lifetime).
//
// All of those throw at call time, not at module load, so the
// surface inspection (`typeof tn.admin === "object"`,
// `typeof Tn.init === "function"`) stays honest.

import { BrowserRuntime, type BrowserRuntimeOptions } from "./runtime.js";
import { normalizeLogFields } from "../_log_fields.js";

// ---------------------------------------------------------------------------
// Module-level state — mirrors src/tn.ts (`_tnLogLevelThreshold`, run_id).
// ---------------------------------------------------------------------------

const _LOG_LEVELS = {
  debug: 10,
  info: 20,
  warning: 30,
  error: 40,
} as const;

/** Standard log-level numeric values. Mirrors stdlib Python `logging`. */
export const LOG_LEVELS: typeof _LOG_LEVELS = _LOG_LEVELS;

export type LogLevel = keyof typeof _LOG_LEVELS;

/** Process-wide level threshold. Default: debug (10). */
let _tnLogLevelThreshold: number = _LOG_LEVELS.debug;

/** Module-level strict mode. Currently unused on browser but kept so
 *  the static `Tn.setStrict` verb has somewhere to land. */
let _strictMode = false;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/**
 * Thrown when a Python/Node-side `Tn` verb hasn't yet been wired up in
 * the browser. The shape is preserved (the property exists, the method
 * is callable) but the implementation is pending.
 */
export class NotYetWiredForBrowserError extends Error {
  readonly verb: string;
  constructor(verb: string) {
    super(
      `Tn.${verb} is not yet wired up for the browser. ` +
        `The Python/Node surface is the reference — see src/tn.ts. ` +
        `Track progress in the @tnproto/sdk browser-surface plan.`,
    );
    this.name = "NotYetWiredForBrowserError";
    this.verb = verb;
  }
}

function _stubFn(verb: string): (...args: unknown[]) => never {
  return () => {
    throw new NotYetWiredForBrowserError(verb);
  };
}

/** Build a namespace object whose every property is a stub. */
function _stubNamespace<T extends Record<string, unknown>>(name: string, keys: readonly string[]): T {
  const out: Record<string, unknown> = {};
  for (const k of keys) out[k] = _stubFn(`${name}.${k}`);
  return out as T;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options forwarded to `Tn.init`. Wraps `BrowserRuntimeOptions`. */
export interface TnInitOptions extends BrowserRuntimeOptions {}

// ---------------------------------------------------------------------------
// Tn class
// ---------------------------------------------------------------------------

/**
 * Browser-side TN client. Construct via the static factory `Tn.init`.
 */
export class Tn {
  private readonly _rt: BrowserRuntime;
  private readonly _runId: string;
  private _contextStack: Array<Record<string, unknown>> = [{}];

  /**
   * Admin namespace (`tn.admin.addRecipient` etc.). Placeholder — every
   * method throws `NotYetWiredForBrowserError` until the admin module
   * goes browser-pure. The property exists so `typeof tn.admin` matches
   * Node.
   */
  readonly admin = _stubNamespace<{
    addRecipient: (group: string, recipientDid: string) => never;
    revokeRecipient: (group: string, leafIndex: number) => never;
    ensureGroup: (group: string) => never;
    cachedAdminState: () => never;
    state: (group?: string | null) => never;
  }>("admin", ["addRecipient", "revokeRecipient", "ensureGroup", "cachedAdminState", "state"]);

  /**
   * Package namespace (`tn.pkg.absorb` / `tn.pkg.export`). Placeholder.
   */
  readonly pkg = _stubNamespace<{
    absorb: (source: string) => never;
    export: (opts: unknown) => never;
  }>("pkg", ["absorb", "export"]);

  /**
   * Vault namespace (`tn.vault.link` / `tn.vault.unlink`). Placeholder.
   */
  readonly vault = _stubNamespace<{
    link: (vaultDid: string, projectId: string) => never;
    unlink: (vaultDid: string, projectId: string, reason?: string) => never;
  }>("vault", ["link", "unlink"]);

  /**
   * Agents namespace (`tn.agents.loadPolicy` etc.). Placeholder.
   */
  readonly agents = _stubNamespace<{
    loadPolicy: () => never;
  }>("agents", ["loadPolicy"]);

  /**
   * Handlers namespace (`tn.handlers.add` / `tn.handlers.remove`).
   * Placeholder.
   */
  readonly handlers = _stubNamespace<{
    add: (h: unknown) => never;
    remove: (name: string) => never;
  }>("handlers", ["add", "remove"]);

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
   * On first call in a given origin (or after `localStorage.clear()`),
   * a fresh ceremony is minted: device key, btn publisher + self-kit,
   * index master, full `tn.yaml`. Every subsequent call loads the
   * existing material.
   *
   * Construction is async to mirror Node `Tn.init`; in the browser the
   * underlying work is synchronous, so the returned promise resolves on
   * the next microtask.
   */
  static async init(opts?: TnInitOptions): Promise<Tn> {
    const rt = BrowserRuntime.init(opts ?? {});
    return new Tn(rt);
  }

  /**
   * `Tn.use(name, opts)` — multi-ceremony. Not yet wired for browser;
   * default `Tn.init()` covers single-ceremony usage. Mirrors
   * Python `tn.use`.
   */
  static async use(_name: string, _opts?: unknown): Promise<Tn> {
    throw new NotYetWiredForBrowserError("use");
  }

  /**
   * `Tn.absorb(source)` — install a `.tnpkg`. Not yet wired for browser:
   * needs a browser-pure tnpkg reader (the Node side uses fs to read
   * the file). Track in the browser-surface plan.
   */
  static async absorb(_source: string): Promise<Tn> {
    throw new NotYetWiredForBrowserError("absorb");
  }

  /**
   * `Tn.ephemeral(opts)` — Node-only (lifetime tied to a tempdir).
   * The browser equivalent is "use a different `keyPrefix` on the
   * storage adapter," which is `Tn.init({ storage: ... })`.
   */
  static async ephemeral(_opts?: unknown): Promise<Tn> {
    throw new NotYetWiredForBrowserError("ephemeral");
  }

  /** List ceremony names on disk. Multi-ceremony placeholder. */
  static listCeremonies(): string[] {
    throw new NotYetWiredForBrowserError("listCeremonies");
  }

  /** Toggle strict mode (no fresh-mint on missing yaml). */
  static setStrict(enabled: boolean): void {
    _strictMode = enabled;
  }

  /** Whether strict mode is on. */
  static isStrict(): boolean {
    return _strictMode;
  }

  /** Set the process-wide level threshold by name. */
  static setLevel(level: LogLevel | string): void {
    BrowserRuntime.setLevel(String(level));
    if (level in _LOG_LEVELS) {
      _tnLogLevelThreshold = _LOG_LEVELS[level as LogLevel];
    }
  }

  /** The active level threshold as a name. */
  static getLevel(): string {
    return BrowserRuntime.getLevel();
  }

  /** True iff `level` would currently emit. Mirrors Python `tn.is_enabled_for`. */
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

  /** Severity-less attested event. Always emits regardless of `setLevel`. */
  log(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    this._rt.log(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  debug(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (10 < _tnLogLevelThreshold) return;
    this._rt.debug(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  info(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (20 < _tnLogLevelThreshold) return;
    this._rt.info(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  warning(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (30 < _tnLogLevelThreshold) return;
    this._rt.warning(eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

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
   * Read every entry from the main log as flat JS objects. Sync —
   * matches Python's `tn.read()` shape (six envelope basics + every
   * readable group's decrypted fields hoisted to the top level).
   *
   * Currently returns an array (materialised eagerly from wasm). Once
   * the wasm side gains an iterator surface, this'll match Python's
   * `_ReadIterator` more closely.
   */
  read(): Array<Record<string, unknown>> {
    return this._rt.read();
  }

  /** Audit-grade read returning `{envelope, plaintext}` per entry. */
  readRaw(): Array<Record<string, unknown>> {
    return this._rt.readRaw();
  }

  /** Tail the log live. Not yet wired for browser. */
  watch(_opts?: unknown): AsyncIterable<Record<string, unknown>> {
    throw new NotYetWiredForBrowserError("watch");
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /** Flush and close. Idempotent at the JS level. */
  async close(): Promise<void> {
    this._rt.close();
  }
}
