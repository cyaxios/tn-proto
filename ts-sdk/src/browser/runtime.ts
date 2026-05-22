// Browser-side runtime.
//
// Thin JS wrapper around wasm `WasmRuntime`. Mirrors the slice of
// `NodeRuntime` that the `Tn` class actually calls — emit verbs, read,
// did, close, level mgmt — without any of the Node-specific
// infrastructure (handler registry, log rotation, agent-policy load,
// admin BtnPublisher cache). Those land in later PRs as the
// corresponding namespaces are ported.
//
// All disk I/O routes through a `JsStorageCallbacks` adapter — the
// localStorage one by default. The wasm runtime calls those callbacks
// for every read/write/append; this class never touches storage
// directly.

import { WasmRuntime } from "tn-wasm";
import { createFreshCeremony, type CreateFreshOptions } from "./create_fresh.js";
import { localStorageStorageAdapter } from "../runtime/storage_localstorage.js";
import type { JsStorageCallbacks } from "../runtime/storage_node.js";

/** Options for `BrowserRuntime.init`. */
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
}

/**
 * Wraps a single `WasmRuntime` handle. Construct via the static `init`
 * factory; never `new BrowserRuntime` directly.
 */
export class BrowserRuntime {
  /** The wasm runtime handle this instance owns. */
  private readonly _wasm: WasmRuntime;
  /** The storage adapter we handed to the wasm runtime. Kept so admin /
   *  pkg verbs can call back into it without re-resolving. */
  readonly storage: JsStorageCallbacks;
  /** Resolved yaml path the wasm runtime loaded from. */
  readonly yamlPath: string;

  private constructor(wasm: WasmRuntime, storage: JsStorageCallbacks, yamlPath: string) {
    this._wasm = wasm;
    this.storage = storage;
    this.yamlPath = yamlPath;
  }

  /**
   * Load a ceremony from `storage`, creating a fresh one on first call.
   *
   * Mirrors `NodeRuntime.init`: if the yaml doesn't exist at
   * `opts.yamlPath`, call `createFreshCeremony` first; then hand the
   * yaml + storage to `WasmRuntime.initWith` and cache the handle.
   */
  static init(opts: BrowserRuntimeOptions = {}): BrowserRuntime {
    const storage = opts.storage ?? localStorageStorageAdapter();
    const yamlPath = opts.yamlPath ?? "/v/tn.yaml";

    if (!storage.exists(yamlPath)) {
      createFreshCeremony(storage, opts.createFresh ?? {});
    }

    // `initWith` is the variant that takes an opts object; we pass an
    // empty bag for now. `skipCeremonyInitEmit` is a NodeRuntime concern
    // (it attaches wasm lazily after the TS side has already taken
    // responsibility for the init event) and doesn't apply here — the
    // browser runtime IS the wasm runtime, no lazy attach.
    const wasm = WasmRuntime.initWith(yamlPath, storage, {});
    return new BrowserRuntime(wasm, storage, yamlPath);
  }

  /** The publisher DID this runtime emits as. `did:key:z…`. */
  did(): string {
    return this._wasm.did();
  }

  /** Severity-less attested event. See `WasmRuntime.log`. */
  log(eventType: string, fields: Record<string, unknown>): void {
    this._wasm.log(eventType, fields);
  }

  /** DEBUG-level attested event. */
  debug(eventType: string, fields: Record<string, unknown>): void {
    this._wasm.debug(eventType, fields);
  }

  /** INFO-level attested event. */
  info(eventType: string, fields: Record<string, unknown>): void {
    this._wasm.info(eventType, fields);
  }

  /** WARNING-level attested event. */
  warning(eventType: string, fields: Record<string, unknown>): void {
    this._wasm.warning(eventType, fields);
  }

  /** ERROR-level attested event. */
  error(eventType: string, fields: Record<string, unknown>): void {
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

  /** Explicit flush + close. Idempotent at the JS level. */
  close(): void {
    this._wasm.close();
  }
}
