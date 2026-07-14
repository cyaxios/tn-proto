// Public entry point for tn-proto. All crypto is delegated to tn-wasm,
// which is compiled from the tn-core Rust crate. If you need a primitive
// not re-exported here, pull from `tn-proto/raw`.

// Wasm init note: tn-wasm is loaded LAZILY by the node runtime (see
// runtime/node_runtime.ts `loadWasm()`), not via a static side-effect import
// here. wasm-pack's `--target nodejs` glue auto-instantiates the .wasm on
// require, which can throw (missing .wasm after a serverless bundle, no `fs`
// on edge). Eagerly importing it at this entry would let that throw crash any
// program that merely imports tn-proto; deferring + guarding the require keeps
// the SDK from crashing user space. The browser entry (src/index.browser.ts)
// has its own inlined-bytes init against the pkg-web build.

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
export * as btn from "./btn.js";
export * as jwe from "./jwe.js";
export * from "./primitive_errors.js";
// Named aggregate so `import { tn } from "tn-proto"` works (see _namespace.ts).
export { tn } from "./_namespace.js";
export { NodeRuntime } from "./runtime/node_runtime.js";
export type { ReadEntry } from "./runtime/node_runtime.js";
export type {
  EmitReceipt,
  AbsorbReceipt,
  AbsorbResult,
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
// "tn-proto"` without needing the class.
export { Tn } from "./tn.js";
export type { TnInitOptions, ReadOptions, WatchOptions, VerifyMode } from "./tn.js";
export type { WatchSince } from "./watch.js";
export { Entry, VerifyError } from "./Entry.js";
// Portable sealed objects (tn.seal / tn.unseal). `SealedObjectError` is
// the malformed-source error (Python's tn.UnsealError under a
// non-colliding name — `UnsealError` below is recipient_seal's BEK
// unwrap failure, a different animal).
export { SealedObject, SealedObjectError } from "./seal.js";
export type { SealOptions, SealedTriple, UnsealOptions, UnsealSource } from "./seal.js";
export { LOG_LEVELS } from "./tn.js";
export type {
  AddRuntimeOptions,
  AddRuntimeOptions as AdminAddAgentRuntimeOptions,
} from "./agents/index.js";
export type { ExportOptions as PkgExportOptions } from "./pkg/index.js";
export type { ChainConflict, LeafReuseAttempt } from "./core/admin/state.js";

import { Tn as _Tn } from "./tn.js";
// Local bindings for the auto-link helper (the same symbols are re-exported
// below from ./vault/url.js; a re-export does not bind them into local scope).
import { resolveVaultUrl, isAutoLinkDisabled } from "./vault/url.js";
import { USER_AGENT } from "./version.js";
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
  computeBodySha256,
  isManifestSignatureValid,
  manifestSigningBytes,
  newManifest,
  nowIsoMillis,
  prepareManifestBodyIndex,
  signManifest,
  signManifestWithBody,
  verifyManifestBodyIndex,
  verifyManifest,
  type Manifest,
  type ManifestKind,
  type VectorClock,
  type BodyContents,
} from "./core/tnpkg.js";
export {
  readTnpkg,
  readTnpkgVerified,
  writeTnpkg,
  packTnpkgBytes,
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
export { awkPickupAad, drainPendingAwk, redeemAwkPickup } from "./vault/awk_pickup.js";
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

// Wallet module surface. `wallet` is the public `tn.wallet` namespace
// (mirrors Python's `tn.wallet` module); the underlying impls remain
// individually importable for callers that want them directly.
export { wallet, type WalletStatus, type WalletNamespaceSurface } from "./wallet/namespace.js";

// Auth module surface. `auth` is the public `tn.auth` namespace (account /
// session / device enrollment); mirrors Python's `tn.auth`. Library-first -
// bin/tn-js.mjs is a thin printer over these verbs.
export {
  auth,
  AuthError,
  AuthState,
  VERDICT_MESSAGE,
  computeVerdict,
  type Verdict,
  type AuthNamespace,
  type StatusOptions as AuthStatusOptions,
  type LoginOptions as AuthLoginOptions,
  type ConnectOptions as AuthConnectOptions,
} from "./auth/index.js";
export { WalletNamespace, readSyncQueue, readLinkState, type LinkResult } from "./wallet/index.js";
export {
  restoreWithBek,
  restoreViaPassphrase,
  restoreViaLoopback,
  restoreViaMnemonic,
  restoreCeremony,
  decryptBlobWithBek,
  tryUnpackExportFrame,
  RestoreError,
  type RestoreOptions,
  type RestoreResult,
  type RestoreViaLoopbackOptions,
} from "./wallet/restore.js";
export { walletSyncCmd, type WalletSyncCmdOptions } from "./cli/wallet_sync.js";
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
//     import { tn } from "tn-proto";
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
import {
  unsealWithRuntime as _unsealWithRuntime,
  type SealOptions as _SealOptions,
  type SealedObject as _SealedObject,
  type SealedTriple as _SealedTriple,
  type UnsealOptions as _UnsealOptions,
  type UnsealSource as _UnsealSource,
} from "./seal.js";

let _defaultTn: _Tn | null = null;

/** Internal — for the verbs that legitimately require an already-bound
 *  default (`usingRust`, `config`). Throws if `tn.init()` hasn't run.
 *  The emit and read/watch verbs use the auto-init helpers below instead. */
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
 * Auto-init for the EMIT verbs (log/debug/info/warning/error). If no
 * default ceremony is bound yet, discover-or-MINT one synchronously
 * (`Tn.initSync()` walks the discovery chain and creates a fresh
 * project-root ceremony when none is found). Mirrors Python's
 * `_autoinit.maybe_autoinit`. The `verb` arg is kept for parity with
 * `_requireDefault` / future diagnostics.
 */
function _ensureDefault(_verb: string): _Tn {
  if (_defaultTn === null) {
    _defaultTn = _Tn.initSync();
  }
  return _defaultTn;
}

/**
 * Auto-init for the READ-ONLY verbs (read/watch). If no default ceremony
 * is bound yet, discover an EXISTING ceremony but never mint one — throw
 * a friendly "no ceremony found" error instead. Mirrors Python's
 * `_autoinit.maybe_autoinit_load_only`. The no-mint behavior comes from
 * `Tn.initSync(undefined, { mint: false })`.
 */
function _ensureDefaultLoadOnly(_verb: string): _Tn {
  if (_defaultTn === null) {
    _defaultTn = _Tn.initSync(undefined, { mint: false });
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
export async function init(
  yamlPath?: string,
  opts?: TnInitOptions & { projectDir?: string; profile?: string },
): Promise<_Tn> {
  if (_defaultTn !== null) {
    try {
      await _defaultTn.close();
    } catch {
      // Best-effort close; never let a stale singleton block re-init.
    }
    _defaultTn = null;
  }
  _defaultTn = await _Tn.init(yamlPath, opts);
  // One anonymous usage ping per process — "an SDK session started".
  // Contained: a broken config or dead vault must never affect init.
  _sessionPing(_defaultTn);
  // SDK auto-link — parity with Python's `_auto_link_after_init`. Surfaces a
  // claim URL by default in serverless deploys (Vercel/Lambda/etc.) so a coded
  // `tn.init()` gives you a link to claim the project, for both an unnamed and a
  // generated-name ceremony. Contained: never fails init.
  await _maybeAutoLinkAfterInit(_defaultTn, opts);
  return _defaultTn;
}

// Latch for the session usage ping — one per process, ever.
let _sessionPingDone = false;

/**
 * Fire ONE anonymous `GET /api/v1/ping` at the ceremony's vault per process —
 * the "this SDK session exists" usage signal. Mirrors Python
 * `tn/__init__.py::_session_ping`.
 *
 * Gates: the ceremony's vault block must allow contact (enabled + url;
 * `TN_NO_LINK=1` wins), same as every other vault touch. Fire-and-forget
 * with a short timeout; every failure is swallowed — a dead vault must
 * never slow down or break `tn.init()`.
 */
function _sessionPing(tn: _Tn, fetchImpl?: typeof fetch): void {
  if (_sessionPingDone) return;
  if (isAutoLinkDisabled()) return; // TN_NO_LINK=1 hard opt-out.
  let vault: { enabled?: boolean; url?: string } | undefined;
  try {
    vault = (tn.config() as { vault?: { enabled?: boolean; url?: string } }).vault;
  } catch {
    return;
  }
  if (!vault?.enabled || !vault.url) return;
  _sessionPingDone = true;
  const base = vault.url.replace(/\/+$/, "");
  const f = fetchImpl ?? fetch;
  void f(`${base}/api/v1/ping`, {
    headers: { "User-Agent": USER_AGENT },
    signal: AbortSignal.timeout(3000),
  }).catch(() => {});
}

/** Test hook: reset the once-per-process ping latch and fire with an
 * injected fetch. Not part of the public API surface. */
export const _sessionPingInternals = {
  fire: _sessionPing,
  reset(): void {
    _sessionPingDone = false;
  },
};

// Module-level latch so re-entrant `tn.init()` calls in the same process (e.g. a
// warm serverless container reused across invocations) don't re-mint a pending
// claim on every call. Mirrors Python's `_link_done_this_process`.
let _linkDoneThisProcess = false;

/**
 * True iff running in a serverless / FaaS context. Used to decide the default
 * (link === undefined) auto-link behaviour, analogous to Python's
 * `_in_ipython()` notebook gate. Detects Vercel, AWS Lambda, Netlify,
 * Cloud Run / Knative (K_SERVICE), and Azure Functions.
 */
function _inServerless(): boolean {
  const e = process.env;
  return Boolean(
    e["VERCEL"] ||
    e["VERCEL_ENV"] ||
    e["AWS_LAMBDA_FUNCTION_NAME"] ||
    e["LAMBDA_TASK_ROOT"] ||
    e["NETLIFY"] ||
    e["K_SERVICE"] ||
    e["FUNCTIONS_WORKER_RUNTIME"],
  );
}

/**
 * Best-effort vault upload + claim-URL surfacing after a module-level
 * `tn.init()`. Mirrors Python `tn/__init__.py::_auto_link_after_init`:
 *
 *   - `opts.link === true`  → always run.
 *   - `opts.link === false` → never (the CLI passes this; it runs its own flow).
 *   - `opts.link` undefined → run iff `_inServerless()`.
 *   - `TN_NO_LINK=1`        → hard opt-out in every mode.
 *
 * On success the claim URL is printed to stdout (so it lands in serverless logs)
 * AND stored on the returned `Tn` instance (`tn.claimUrl` / `tn.claim`) for
 * programmatic use. Any failure is swallowed — the on-disk ceremony stays valid.
 */
async function _maybeAutoLinkAfterInit(
  tn: _Tn,
  opts?: TnInitOptions & { projectDir?: string; profile?: string },
): Promise<void> {
  const link = opts?.link;
  if (link === false) return;
  if (link !== true && !_inServerless()) return;
  if (isAutoLinkDisabled()) return; // TN_NO_LINK=1 hard opt-out.
  if (_linkDoneThisProcess) return;

  try {
    const vaultBase = resolveVaultUrl(opts?.vaultUrl ?? null);
    const result = await tn.initUpload({ vaultBase });
    tn.claimUrl = result.claimUrl;
    tn.claim = {
      vaultId: result.vaultId,
      expiresAt: result.expiresAt,
      claimUrl: result.claimUrl,
    };
    _linkDoneThisProcess = true;
    // Plain stdout (no IPython/HTML on a serverless runtime); lands in logs.
    process.stdout.write(
      `\n[tn.init] Backed up to ${vaultBase}\n` +
        `[tn.init]   vault_id: ${result.vaultId}\n` +
        `[tn.init]   expires:  ${result.expiresAt}\n\n` +
        `[tn.init] CLAIM URL - open this in your browser to attach the project to your account:\n` +
        `  ${result.claimUrl}\n\n`,
    );
  } catch (e) {
    // Auto-link is best-effort; the ceremony is valid locally regardless.
    if (process.env["TN_DEBUG"]) {
      try {
        process.stderr.write(
          `[tn:debug] tn.init auto-link failed: ${e instanceof Error ? e.message : String(e)}\n`,
        );
      } catch {
        /* ignore broken stderr */
      }
    }
  }
}

/** Severity-less attested event. Mirrors Python `tn.log(...)`. */
export function log(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _ensureDefault("log").log(eventType, msgOrFields, fieldsIfMessage);
}

export function debug(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _ensureDefault("debug").debug(eventType, msgOrFields, fieldsIfMessage);
}

export function info(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _ensureDefault("info").info(eventType, msgOrFields, fieldsIfMessage);
}

export function warning(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _ensureDefault("warning").warning(eventType, msgOrFields, fieldsIfMessage);
}

export function error(
  eventType: string,
  msgOrFields?: string | Record<string, unknown>,
  fieldsIfMessage?: Record<string, unknown>,
): EmitReceipt {
  return _ensureDefault("error").error(eventType, msgOrFields, fieldsIfMessage);
}

/** Read attested entries from the default ceremony's log. Mirrors
 *  Python `tn.read()`. Returns an iterator like the class method;
 *  yields `Entry` by default, `Record<string, unknown>` when
 *  `opts.raw === true`.
 *
 *  Auto-inits LOAD-ONLY: if no `tn.init()` has run, it discovers an
 *  existing ceremony but never mints one — throwing a friendly "no
 *  ceremony found" error instead (mirrors Python `maybe_autoinit_load_only`).
 *  Use an emit verb (e.g. `tn.info(...)`) to auto-create a ceremony. */
export function read(opts?: ReadOptions): IterableIterator<_Entry | Record<string, unknown>> {
  return _ensureDefaultLoadOnly("read").read(opts);
}

/** Tail the default ceremony's log live. Mirrors Python `tn.watch()`.
 *  Async generator; yields `Entry` by default, `Record<string, unknown>`
 *  when `opts.raw === true`.
 *
 *  Auto-inits LOAD-ONLY (same discover-or-throw semantics as `read`):
 *  never mints a fresh ceremony. */
export function watch(
  opts?: WatchOptions,
): AsyncIterableIterator<_Entry | Record<string, unknown>> {
  return _ensureDefaultLoadOnly("watch").watch(opts);
}

/** Seal fields into a portable attested object (standalone envelope).
 *  Mirrors Python `tn.seal(object_type, **fields)`.
 *
 *  Auto-inits like the write verbs (a seal needs a bound publisher to
 *  encrypt its groups and sign): if no default ceremony is bound yet,
 *  discover-or-mint one. */
export async function seal(
  objectType: string,
  fields: Record<string, unknown> = {},
  opts: _SealOptions = {},
): Promise<_SealedObject> {
  return _ensureDefault("seal").seal(objectType, fields, opts);
}

/** Verify a sealed object and open every group block a held key fits.
 *  Mirrors Python `tn.unseal(source)`.
 *
 *  Auto-inits LOAD-ONLY (like `read`): an existing ceremony is
 *  discovered but never minted. Unlike `read`, finding no ceremony is
 *  not an error here — verification needs no ceremony at all, and the
 *  `asRecipient` override brings its own keys — so the walk simply
 *  runs key-less and returns the verified public frame (mirrors
 *  Python, whose unseal never auto-inits). */
export async function unseal(
  source: _UnsealSource,
  opts: _UnsealOptions = {},
): Promise<_Entry | _SealedTriple> {
  let handle: _Tn | null = _defaultTn;
  if (handle === null) {
    try {
      handle = _ensureDefaultLoadOnly("unseal");
    } catch {
      handle = null;
    }
  }
  if (handle !== null) return handle.unseal(source, opts);
  return _unsealWithRuntime(null, source, opts);
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
export async function close(opts: { timeoutMs?: number } = {}): Promise<void> {
  if (_defaultTn === null) return;
  const t = _defaultTn;
  _defaultTn = null;
  await t.close(opts);
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
export const using_rust = usingRust;

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
export const set_context = setContext;

export function updateContext(fields: Record<string, unknown>): void {
  if (_defaultTn === null) return;
  _defaultTn.updateContext(fields);
}
export const update_context = updateContext;

export function clearContext(): void {
  if (_defaultTn === null) return;
  _defaultTn.clearContext();
}
export const clear_context = clearContext;

export function getContext(): Record<string, unknown> {
  return _defaultTn === null ? {} : _defaultTn.getContext();
}
export const get_context = getContext;

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
  name?: string,
  opts?: TnInitOptions & { projectDir?: string; profile?: string; project?: string },
): Promise<_Tn> {
  // `name` omitted resolves the `default` ceremony (parity with Python `tn.use()`).
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
