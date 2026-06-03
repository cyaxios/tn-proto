// Public entry point for @tnproto/sdk. All crypto is delegated to tn-wasm,
// which is compiled from the tn-core Rust crate. If you need a primitive
// not re-exported here, pull from `@tnproto/sdk/raw`.

// Wasm init note: wasm-pack's `--target nodejs` glue auto-instantiates
// the .wasm at module load time (see the bottom of pkg/tn_wasm.js —
// `let wasm = new WebAssembly.Instance(...).exports; wasm.__wbindgen_start();`).
// So a plain `import "tn-wasm"` is sufficient on Node — no explicit
// `initSync` is required, and `initSync` is NOT exported by the
// nodejs-target glue (only by the web/bundler targets).
// The browser entry (src/index.browser.ts) doesn't import this — its
// bundle script handles wasm init via the inlined-bytes path against
// the pkg-web build.
import "tn-wasm";

export * from "./core/types.js";
export * from "./core/canonical.js";
export * from "./core/chain.js";
export * from "./core/envelope.js";
export * from "./core/indexing.js";
export * from "./core/signing.js";
// The static admin-event catalog (reduce / catalogKinds / validateEmit).
// Exported as `adminCatalog` so the module-level `admin` name is free for
// the RUNTIME admin namespace (tn.admin.addRecipient(...)) further down,
// matching Python's `import tn; tn.admin.*`.
export * as adminCatalog from "./core/admin/catalog.js";
export * as primitives from "./core/primitives.js";
export { NodeRuntime } from "./runtime/node_runtime.js";
export type { ReadEntry } from "./runtime/node_runtime.js";
export type {
  EmitReceipt,
  AbsorbReceipt,
  AddRecipientResult,
  RevokeRecipientResult,
  RotateGroupResult,
  EnsureGroupResult,
  BundleResult,
  OfferReceipt,
} from "./core/results.js";
export {
  VerificationError,
  ChainConflictError,
  RotationConflictError,
  LeafReuseError,
  SameCoordinateForkError,
} from "./core/errors.js";

// Polymorphic recipient helpers for tn.admin.{addRecipient,revokeRecipient}.
// Matches the Python `recipient=` resolver in tn.admin.
export { did, leafIndex, publicKeyBytes, resolveRecipient } from "./admin/recipient.js";
export type {
  Did,
  LeafIndex,
  PublicKeyBytes,
  RecipientInput,
  RecipientLike,
  ResolvedRecipient,
} from "./admin/recipient.js";

// 0.3.0 surface — Tn is the public class. Bare-function exports of the
// process-global toggles let callers do `import { setLevel } from
// "@tnproto/sdk"` without needing the class.
export { Tn } from "./tn.js";
export type {
  TnInitOptions,
  ReadOptions,
  WatchOptions,
  VerifyMode,
} from "./tn.js";
export type { WatchSince } from "./watch.js";
export { Entry, VerifyError } from "./Entry.js";
export { LOG_LEVELS } from "./tn.js";
export type {
  AddRuntimeOptions,
  AddRuntimeOptions as AdminAddAgentRuntimeOptions,
} from "./agents/index.js";
export type {
  ExportOptions as PkgExportOptions,
} from "./pkg/index.js";
export type {
  ChainConflict,
  LeafReuseAttempt,
} from "./core/admin/state.js";

import { Tn as _Tn } from "./tn.js";
export const setLevel: typeof _Tn.setLevel = _Tn.setLevel.bind(_Tn);
export const getLevel: typeof _Tn.getLevel = _Tn.getLevel.bind(_Tn);
export const isEnabledFor: typeof _Tn.isEnabledFor = _Tn.isEnabledFor.bind(_Tn);
export const setSigning: typeof _Tn.setSigning = _Tn.setSigning.bind(_Tn);
export const setStrict: typeof _Tn.setStrict = _Tn.setStrict.bind(_Tn);
export {
  loadPolicyFile,
  parsePolicyText,
  policyPathFor,
  POLICY_RELATIVE_PATH,
  REQUIRED_FIELDS,
  type PolicyDocument,
  type PolicyTemplate,
} from "./agents_policy.js";
export {
  AdminStateCache,
  LKV_VERSION,
  type RotationConflict,
  type SameCoordinateFork,
} from "./admin/cache.js";
export { AdminStateReducer, emptyState } from "./core/admin/state.js";
export {
  KNOWN_KINDS,
  MANIFEST_VERSION,
  clockDominates,
  clockMerge,
  isManifestSignatureValid,
  manifestSigningBytes,
  newManifest,
  nowIsoMillis,
  signManifest,
  verifyManifest,
  type Manifest,
  type ManifestKind,
  type VectorClock,
  type BodyContents,
} from "./core/tnpkg.js";
export {
  readTnpkg,
  writeTnpkg,
  packTnpkg,
  parseTnpkg,
  type ZipEntry,
  type ParsedZipEntry,
} from "./tnpkg_io.js";
export {
  DEFAULT_ADMIN_LOG_LOCATION,
  appendAdminEnvelopes,
  existingRowHashes,
  isAdminEventType,
  resolveAdminLogPath,
} from "./admin/log.js";
export { loadConfig } from "./runtime/config.js";
export { loadKeystore } from "./runtime/keystore.js";
export {
  absorbBootstrap,
  absorbSealedBootstrap,
  isBootstrapKind,
} from "./runtime/absorb_bootstrap.js";
export {
  encryptBodyBlob,
  decryptBodyBlob,
  packBodyPlaintextZip,
  BODY_CIPHER_SUITE,
  BODY_FRAME,
} from "./core/body_encryption.js";
export {
  buildRecipientWraps,
  manifestAadForWrap,
  sealBekForRecipient,
  unsealBekFromWrap,
  UnsealError,
  WRAP_FRAME,
  type RecipientWrap,
} from "./core/recipient_seal.js";
export { fromWireDict, toWireDict } from "./core/tnpkg.js";
export {
  DEFAULT_VAULT_URL,
  ENV_VAULT_URL,
  ENV_VAULT_DEFAULT_BASE,
  ENV_NO_LINK,
  resolveVaultUrl,
  resolveDidEndpoint,
  isAutoLinkDisabled,
} from "./vault/url.js";
export {
  bootstrapFromApiKey,
  challengeVerify,
  parseBearer,
  UnsealNotWiredError,
  type ApiKeyFetchResult,
  type ParsedBearer,
} from "./runtime/bootstrap_api_key.js";
// readAsRecipient is no longer exported from the public surface;
// use `Tn.read({asRecipient})` for foreign-publisher reads.
export {
  iterLogFiles,
  scanAttestedEvents,
  scanAttestedEventRecords,
  scanAttestedGroups,
  yamlRecipientDids,
} from "./runtime/reconcile.js";
export * from "./handlers/index.js";
export {
  initUpload,
  type InitUploadOptions,
  type InitUploadResult,
} from "./handlers/init_upload.js";
export { Identity, defaultIdentityPath, defaultIdentityDir } from "./identity.js";
export {
  compileKitBundle,
  compileKitBundleToFile,
  type CompileKitBundleOptions,
  type CompiledKitMeta,
  type CompiledPackage,
} from "./compile.js";
export {
  STATE_FILE,
  SYNC_DIR,
  getInboxCursor,
  getLastPushedAdminHead,
  loadSyncState,
  saveSyncState,
  setInboxCursor,
  setLastPushedAdminHead,
  statePath,
  updateSyncState,
  type SyncState,
} from "./sync_state.js";

// ---------------------------------------------------------------------------
// Module-level singleton surface — mirrors Python's `tn.info(...)`,
// `tn.init(...)`, etc. so the simplest TS usage is the same shape as
// Python:
//
//     import * as tn from "@tnproto/sdk";
//     await tn.init(yamlPath);
//     tn.info("event.type", { a: 1 });
//     for (const entry of tn.read()) { ... }
//     await tn.close();
//
// Under the hood, this is a lazy-initialized default `Tn` instance.
// Power users who want to manage instances explicitly still use the
// `Tn` class directly — that surface is unchanged.
//
// Why this exists (api-critique log 2026-05-14): before this, TS had
// NO bare module-level logging verbs. Every consumer had to instantiate
// `Tn` and thread the instance through their code. That broke
// cross-SDK parity with Python and added friction for the simplest
// usage pattern. ~50 LOC of wrappers fixes the asymmetry without
// changing the `Tn` class.
// ---------------------------------------------------------------------------

import type {
  EmitReceipt,
  Entry as _Entry,
  ReadOptions,
  TnInitOptions,
  WatchOptions,
} from "./tn.js";

let _defaultTn: _Tn | null = null;

/** Internal — for the regression suite and any future test that needs
 *  to detect "did `tn.init()` succeed yet" without touching the class. */
function _requireDefault(verb: string): _Tn {
  if (_defaultTn === null) {
    throw new Error(
      `tn.${verb}() called before tn.init(). Call \`await tn.init(yamlPath)\` first, ` +
        `or use the \`Tn\` class directly if you want to manage multiple ceremonies.`,
    );
  }
  return _defaultTn;
}

/**
 * Initialize a default ceremony. Mirrors Python `tn.init(yaml_path)`.
 * Calling `init()` again closes the previous default first.
 *
 * @returns the underlying `Tn` instance so callers who want it can keep
 *          it; not required for the bare-export usage.
 */
export async function init(yamlPath?: string, opts?: TnInitOptions): Promise<_Tn> {
  if (_defaultTn !== null) {
    try {
      await _defaultTn.close();
    } catch {
      // Best-effort close; never let a stale singleton block re-init.
    }
    _defaultTn = null;
  }
  _defaultTn = await _Tn.init(yamlPath, opts);
  return _defaultTn;
}

/** Severity-less attested event. Mirrors Python `tn.log(...)`. */
export function log(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _requireDefault("log").log(eventType, msgOrFields, fieldsIfMessage);
}

export function debug(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _requireDefault("debug").debug(eventType, msgOrFields, fieldsIfMessage);
}

export function info(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _requireDefault("info").info(eventType, msgOrFields, fieldsIfMessage);
}

export function warning(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _requireDefault("warning").warning(eventType, msgOrFields, fieldsIfMessage);
}

export function error(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _requireDefault("error").error(eventType, msgOrFields, fieldsIfMessage);
}

/** Read attested entries from the default ceremony's log. Mirrors
 *  Python `tn.read()`. Returns an iterator like the class method;
 *  yields `Entry` by default, `Record<string, unknown>` when
 *  `opts.raw === true`. */
export function read(opts?: ReadOptions): IterableIterator<_Entry | Record<string, unknown>> {
  return _requireDefault("read").read(opts);
}

/** Tail the default ceremony's log live. Mirrors Python `tn.watch()`.
 *  Async generator; yields `Entry` by default, `Record<string, unknown>`
 *  when `opts.raw === true`. Throws if called before `tn.init()`. */
export function watch(
  opts?: WatchOptions,
): AsyncIterableIterator<_Entry | Record<string, unknown>> {
  return _requireDefault("watch").watch(opts);
}

/** Block-scoped context overlay on the default ceremony. Mirrors Python
 *  `with tn.scope(**fields):`. Runs `body` with `fields` layered on top
 *  of the current context, restoring the prior context on return (even
 *  if `body` throws). Throws if called before `tn.init()`. */
export function scope<T>(fields: Record<string, unknown>, body: () => T): T {
  return _requireDefault("scope").scope(fields, body);
}

/** Flush handlers and release the default ceremony. Mirrors Python
 *  `tn.flush_and_close()`. Safe to call multiple times. */
export async function close(): Promise<void> {
  if (_defaultTn === null) return;
  const t = _defaultTn;
  _defaultTn = null;
  await t.close();
}

/** Flush handlers and release the default ceremony. Snake_case alias
 *  for Python parity (`tn.flush_and_close()`). */
export const flush_and_close = close;

/** True iff the default ceremony's emit path is currently serviced by
 *  the attached Rust/WASM core. False before the first emit (wasm
 *  attaches lazily) and after an admin-driven runtime reset. Throws if
 *  called before `tn.init()`. Mirrors Python's `tn.using_rust`. */
export function usingRust(): boolean {
  return _requireDefault("usingRust").usingRust();
}

/** Return the default ceremony's resolved config. Mirrors Python
 *  `tn.current_config()`. */
export function config(): ReturnType<_Tn["config"]> {
  return _requireDefault("config").config();
}

/** Snake_case alias of {@link config} for Python parity
 *  (`tn.current_config()`). */
export const current_config = config;

/** Default-ceremony context functions — mirror Python `tn.set_context`,
 *  etc. All no-op if init hasn't been called yet (rather than throwing)
 *  so they're safe to use in early boot before the runtime is up. */
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

// ---------------------------------------------------------------------------
// Static-backed module verbs — these don't touch the default singleton;
// they forward straight to the `Tn` static factories. `tn.use(...)` and
// `tn.session(...)` mint *additional* ceremonies (the caller owns the
// returned handle); only `tn.absorb(...)` rebinds the module default,
// matching its role as a bootstrap entry point.
// ---------------------------------------------------------------------------

/** Get-or-create a named stream. Mirrors Python `tn.use(name)`. Returns
 *  a fresh `Tn` handle (interned per project+name like the class method);
 *  does NOT rebind the module-level default. */
export function use(
  name: string,
  opts?: TnInitOptions & { projectDir?: string; profile?: string; project?: string },
): Promise<_Tn> {
  return _Tn.use(name, opts);
}

/** List ceremony names found on disk under `.tn/` for `projectDir`
 *  (default: cwd). Mirrors Python `tn.list_ceremonies()`. */
export function listCeremonies(projectDir?: string): string[] {
  return _Tn.listCeremonies(projectDir);
}

/** Snake_case alias of {@link listCeremonies} for Python parity
 *  (`tn.list_ceremonies()`). */
export const list_ceremonies = listCeremonies;

/** Build a throwaway ceremony in a private tempdir, removed on its
 *  `close()`. Mirrors Python `tn.session()`. Returns a fresh `Tn`
 *  handle; does NOT rebind the module-level default. */
export function session(opts?: TnInitOptions): Promise<_Tn> {
  return _Tn.ephemeral(opts);
}

/** Absorb a self-contained bootstrap bundle and rebind the module-level
 *  default to the freshly-absorbed ceremony. Mirrors Python `tn.absorb()`
 *  followed by the module default tracking that ceremony. Any prior
 *  default is closed first (best-effort), matching {@link init}. */
export async function absorb(
  source: string | Uint8Array,
  opts?: { cwd?: string } & TnInitOptions,
): Promise<_Tn> {
  const tn = await _Tn.absorb(source, opts ?? {});
  if (_defaultTn !== null && _defaultTn !== tn) {
    try {
      await _defaultTn.close();
    } catch {
      // Best-effort close; never let a stale singleton block the rebind.
    }
  }
  _defaultTn = tn;
  return tn;
}

// ---------------------------------------------------------------------------
// Runtime namespaces at module level — so `tn.admin.addRecipient(...)`,
// `tn.pkg.*`, `tn.vault.*` (and `tn.agents.*`, `tn.handlers.*`) work and
// resolve to the live default ceremony's RUNTIME namespaces, NOT the
// static `adminCatalog` re-export above. Each is a lazy proxy: property
// access forwards to the namespace on the current default instance, so
// the binding always tracks the latest `tn.init()` / `tn.absorb()`.
// Accessing any member before init throws via `_requireDefault`.
// ---------------------------------------------------------------------------

function _makeNamespaceProxy<K extends "admin" | "pkg" | "vault" | "agents" | "handlers">(
  verb: K,
): _Tn[K] {
  // The target is an inert object; every read is intercepted and routed
  // to the live namespace. Cast to the namespace instance type so callers
  // get full member typings (e.g. `tn.admin.addRecipient`).
  return new Proxy({} as _Tn[K], {
    get(_target, prop, receiver) {
      const ns = _requireDefault(verb)[verb] as object;
      const value = Reflect.get(ns, prop, receiver) as unknown;
      // Re-bind `this` for methods so they execute against the namespace
      // instance rather than the proxy.
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(ns) : value;
    },
    has(_target, prop) {
      const ns = _requireDefault(verb)[verb] as object;
      return Reflect.has(ns, prop);
    },
  });
}

/** Runtime ceremony-admin namespace on the default instance. Mirrors
 *  Python `tn.admin.*` (e.g. `tn.admin.addRecipient(...)`). This is the
 *  RUNTIME namespace, not the static `adminCatalog` event catalog. */
export const admin: _Tn["admin"] = _makeNamespaceProxy("admin");

/** Runtime package (tnpkg) namespace on the default instance. Mirrors
 *  Python `tn.pkg.*`. */
export const pkg: _Tn["pkg"] = _makeNamespaceProxy("pkg");

/** Runtime vault namespace on the default instance. Mirrors Python
 *  `tn.vault.*`. */
export const vault: _Tn["vault"] = _makeNamespaceProxy("vault");

/** Runtime agents-policy namespace on the default instance. Mirrors
 *  Python `tn.agents.*`. */
export const agents: _Tn["agents"] = _makeNamespaceProxy("agents");

/** Runtime handlers namespace on the default instance. Mirrors Python
 *  `tn.handlers.*`. */
export const handlers: _Tn["handlers"] = _makeNamespaceProxy("handlers");
