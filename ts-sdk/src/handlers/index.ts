export { BaseTNHandler, compileFilter } from "./base.js";
export type { FilterSpec, TNHandler } from "./base.js";
export { FileHandler } from "./file.js";
export type { FileHandlerOptions } from "./file.js";
export { OpenTelemetryHandler } from "./otel.js";
export type { OtelLogRecord, OtelLogger, OpenTelemetryHandlerOptions } from "./otel.js";
export { StdoutHandler } from "./stdout.js";

// Admin-log push/pull handlers (plan 2026-04-24 §5.2; commit 78f5617).
export {
  FsDropHandler,
  DEFAULT_FS_DROP_FILENAME_TEMPLATE,
  formatFilename,
  makePackageSnapshotBuilder,
} from "./fs_drop.js";
export type { FsDropHandlerOptions, FsDropSpec, SnapshotBuilder } from "./fs_drop.js";
export { FsScanHandler, makePackageAbsorber } from "./fs_scan.js";
export type {
  FsScanHandlerOptions,
  FsScanSpec,
  FsScanOnProcessed,
  FsScanAbsorber,
  FsScanAbsorbReceipt,
} from "./fs_scan.js";
export {
  VaultPushHandler,
  NullVaultPostClient,
  makeFetchVaultPostClient,
} from "./vault_push.js";
export type {
  VaultPushHandlerOptions,
  VaultPushSpec,
  VaultPushTrigger,
  VaultPostClient,
  QueryParams,
} from "./vault_push.js";
export {
  VaultPullHandler,
  makeFetchVaultInboxClient,
} from "./vault_pull.js";
export type {
  VaultPullHandlerOptions,
  VaultPullSpec,
  VaultInboxClient,
  VaultInboxItem,
  VaultInboxListing,
  VaultPullAbsorber,
  VaultPullAbsorbReceipt,
  OnAbsorbError,
} from "./vault_pull.js";
export { buildHandlers, parseDurationMs } from "./registry.js";
export type { HandlerAdapters, HandlerSpec } from "./registry.js";
