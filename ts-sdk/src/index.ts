// Public entry point for @tn/sdk. All crypto is delegated to tn-wasm,
// which is compiled from the tn-core Rust crate. If you need a primitive
// not re-exported here, pull from `@tn/sdk/raw`.

export * from "./core/types.js";
export * from "./core/canonical.js";
export * from "./core/chain.js";
export * from "./core/envelope.js";
export * from "./core/indexing.js";
export * from "./core/signing.js";
export * as admin from "./admin.js";
export * as primitives from "./core/primitives.js";
export { NodeRuntime } from "./runtime/node_runtime.js";
export type { ReadEntry, EmitReceipt } from "./runtime/node_runtime.js";
export {
  LOG_LEVELS,
  TNClient,
  type AbsorbReceipt,
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
} from "./admin_cache.js";
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
} from "./admin_log.js";
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
