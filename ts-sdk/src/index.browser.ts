// Public entry point for the @tnproto/sdk browser bundle.
//
// Mirrors the Python module-level call surface so the simplest browser
// usage reads exactly like Python:
//
//   import * as tn from "@tnproto/sdk/browser";  // or via the prebuilt browser.mjs
//   await tn.init();
//   tn.info("hello.world", { who: "alice" });
//   for (const e of tn.read()) console.log(e);
//   await tn.close();
//
// Power users who want explicit instance management still use the `Tn`
// class directly — `import { Tn } from "@tnproto/sdk/browser"`.
//
// This file lives next to `src/index.ts` (the Node entry) and re-exports
// only the surface that's currently wired for the browser. Other Tn
// verbs (admin / pkg / vault / agents / watch / use / absorb / ephemeral)
// exist as throwing placeholders on the `Tn` class so the API shape
// stays intact; they'll light up as the underlying modules go
// browser-pure.

// ---------------------------------------------------------------------------
// Class + types
// ---------------------------------------------------------------------------

export {
  Tn,
  LOG_LEVELS,
  NotYetWiredForBrowserError,
  type LogLevel,
  type TnInitOptions,
  type TnInitFromSeedOptions,
} from "./browser/tn.js";

export {
  BrowserRuntime,
  type BrowserRuntimeOptions,
} from "./browser/runtime.js";

export {
  createFreshCeremony,
  type CreateFreshOptions,
  type CreateFreshResult,
} from "./browser/create_fresh.js";

export {
  createFromSeed,
  type CreateFromSeedOptions,
  type CreateFromSeedResult,
} from "./browser/create_from_seed.js";

export {
  consoleHandler,
  type ConsoleHandler,
} from "./browser/console_handler.js";

export {
  httpHandler,
  type HttpHandlerOptions,
  type WasmHandlerCallbacks,
} from "./browser/http_handler.js";

export {
  localStorageStorageAdapter,
  LocalStorageQuotaError,
  type LocalStorageAdapter,
  type LocalStorageAdapterOptions,
} from "./runtime/storage_localstorage.js";

export {
  memoryStorageAdapter,
  type MemoryStorageAdapter,
} from "./runtime/storage_memory.js";

export type { JsStorageCallbacks } from "./runtime/storage_node.js";

// Raw wasm primitives, for callers who want them.
export * from "./raw.js";

// Canonical bytes + row hash are routinely useful outside the runtime
// (e.g. building envelopes manually for a federated witness check).
export {
  canonicalBytes,
  canonicalJson,
  computeRowHash,
  zeroHash,
  buildEnvelope,
} from "./raw.js";

// ---------------------------------------------------------------------------
// Module-level singleton surface — mirrors Python `tn.init / tn.info /
// tn.read / tn.close` etc. Same shape as src/index.ts's singleton block.
// ---------------------------------------------------------------------------

import {
  Tn as _Tn,
  type TnInitOptions as _TnInitOptions,
  type TnInitFromSeedOptions as _TnInitFromSeedOptions,
} from "./browser/tn.js";

let _defaultTn: _Tn | null = null;

function _requireDefault(verb: string): _Tn {
  if (_defaultTn === null) {
    throw new Error(
      `tn.${verb}() called before tn.init(). Call \`await tn.init()\` first, ` +
        `or use the \`Tn\` class directly if you want to manage multiple ceremonies.`,
    );
  }
  return _defaultTn;
}

/** Initialize the default ceremony. Mirrors Python `tn.init()`. */
export async function init(opts?: _TnInitOptions): Promise<_Tn> {
  if (_defaultTn !== null) {
    try {
      await _defaultTn.close();
    } catch {
      // Best-effort close; never let a stale singleton block re-init.
    }
    _defaultTn = null;
  }
  _defaultTn = await _Tn.init(opts);
  return _defaultTn;
}

/**
 * Initialize the default ceremony from caller-supplied seed material
 * (witness-style: the server has already minted the device key + btn
 * publisher state and ships them per session). Closes any existing
 * default first.
 */
export async function initFromSeed(opts: _TnInitFromSeedOptions): Promise<_Tn> {
  if (_defaultTn !== null) {
    try {
      await _defaultTn.close();
    } catch {
      // Best-effort close; never let a stale singleton block re-init.
    }
    _defaultTn = null;
  }
  _defaultTn = await _Tn.initFromSeed(opts);
  return _defaultTn;
}

/** Severity-less attested event. Mirrors Python `tn.log(...)`. */
export function log(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): void {
  _requireDefault("log").log(eventType, msgOrFields, fieldsIfMessage);
}

export function debug(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): void {
  _requireDefault("debug").debug(eventType, msgOrFields, fieldsIfMessage);
}

export function info(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): void {
  _requireDefault("info").info(eventType, msgOrFields, fieldsIfMessage);
}

export function warning(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): void {
  _requireDefault("warning").warning(eventType, msgOrFields, fieldsIfMessage);
}

export function error(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): void {
  _requireDefault("error").error(eventType, msgOrFields, fieldsIfMessage);
}

/** Read attested entries from the default ceremony's log. */
export function read(): Array<Record<string, unknown>> {
  return _requireDefault("read").read();
}

/** Audit-grade read returning `{envelope, plaintext}` per entry. */
export function readRaw(): Array<Record<string, unknown>> {
  return _requireDefault("readRaw").readRaw();
}

/**
 * Drain any pending out-of-process handlers (HTTP queue, future
 * fan-out targets) without releasing the runtime. Mirror of Python's
 * `tn.flush()`.
 */
export async function flush(): Promise<void> {
  if (_defaultTn === null) return;
  await _defaultTn.flush();
}

/** Flush and release the default ceremony. Mirrors Python `tn.flush_and_close()`. */
export async function close(): Promise<void> {
  if (_defaultTn === null) return;
  const t = _defaultTn;
  _defaultTn = null;
  await t.close();
}

/** Snake_case alias for Python parity. */
export const flush_and_close = close;

/** This client's publisher DID. */
export function did(): string {
  return _requireDefault("did").did();
}

/** Always true on the browser path — the wasm runtime is the only backend. */
export function usingRust(): boolean {
  return true;
}

// Context fns — same shape as src/index.ts (safe on null default).
export function setContext(fields: Record<string, unknown>): void {
  if (_defaultTn === null) return;
  _defaultTn.setContext(fields);
}

export function updateContext(fields: Record<string, unknown>): void {
  if (_defaultTn === null) return;
  _defaultTn.updateContext(fields);
}

export function clearContext(): void {
  if (_defaultTn === null) return;
  _defaultTn.clearContext();
}

export function getContext(): Record<string, unknown> {
  return _defaultTn === null ? {} : _defaultTn.getContext();
}

export function scope<T>(fields: Record<string, unknown>, body: () => T): T {
  return _requireDefault("scope").scope(fields, body);
}

// Process-wide level toggles. Bound to the class so callers can do
// `tn.setLevel("info")` without grabbing the class.
export const setLevel: typeof _Tn.setLevel = _Tn.setLevel.bind(_Tn);
export const getLevel: typeof _Tn.getLevel = _Tn.getLevel.bind(_Tn);
export const isEnabledFor: typeof _Tn.isEnabledFor = _Tn.isEnabledFor.bind(_Tn);
export const setStrict: typeof _Tn.setStrict = _Tn.setStrict.bind(_Tn);
