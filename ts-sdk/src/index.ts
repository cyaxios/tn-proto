// Public entry point for @tn/sdk. All crypto is delegated to tn-wasm,
// which is compiled from the tn-core Rust crate. If you need a primitive
// not re-exported here, pull from `@tn/sdk/raw`.

export * from "./core/types.js";
export * from "./core/canonical.js";
export * from "./core/chain.js";
export * from "./core/envelope.js";
export * from "./core/indexing.js";
export * from "./core/signing.js";
export * as admin from "./core/admin/catalog.js";
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
  LOG_LEVELS,
  TNClient,
  type AdminAddAgentRuntimeOptions,
  type ChainConflict,
  type ExportOptions,
  type Instructions,
  type LeafReuseAttempt,
  type LogLevel,
  type SecureEntry,
  type SecureReadOptions,
} from "./client.js";
export {
  VerificationError,
  ChainConflictError,
  RotationConflictError,
  LeafReuseError,
  SameCoordinateForkError,
} from "./core/errors.js";

// 0.3.0 surface — the new shape replacing TNClient. TNClient stays alive
// alongside Tn until Task 2.12 deletes it. Bare-function exports of the
// process-global toggles let callers do `import { setLevel } from
// "@tnproto/sdk"` without needing the class.
export { Tn } from "./tn.js";
export type {
  TnInitOptions,
  ReadOptions,
  ReadAsRecipientOptions as TnReadAsRecipientOptions,
  SecureReadOptions as TnSecureReadOptions,
} from "./tn.js";

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
  readAsRecipient,
  type ForeignReadEntry,
  type ReadAsRecipientOptions,
} from "./read_as_recipient.js";
export {
  iterLogFiles,
  scanAttestedEvents,
  scanAttestedEventRecords,
  scanAttestedGroups,
  yamlRecipientDids,
} from "./runtime/reconcile.js";
export * from "./handlers/index.js";
export {
  compileKitBundle,
  compileKitBundleToFile,
  type CompileKitBundleOptions,
  type CompiledManifest,
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
