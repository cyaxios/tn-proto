// Handler registry — mirrors `python/tn/handlers/registry.py`.
//
// Wires YAML `handlers:` blocks to TS handler classes. Currently
// recognized kinds:
//
//   stdout              StdoutHandler
//   vault.push          VaultPushHandler
//   vault.pull          VaultPullHandler
//   fs.drop             FsDropHandler
//   fs.scan             FsScanHandler
//   file.rotating       FileHandler (size-based rotation; max_bytes + backup_count)
//   otel                OpenTelemetryHandler (host injects OtelLogger via adapters)
//
// Not yet ported from Python: file.timed_rotating, kafka, delta, s3.
// Tracked as follow-up work; use the corresponding Python handler in
// the meantime, or add via `tn.handlers.add(new FileHandler(...))`
// programmatically.

import { resolve as pathResolve, isAbsolute as pathIsAbsolute, join } from "node:path";

import type { TNHandler, FilterSpec } from "./base.js";
import { FileHandler } from "./file.js";
import { FsDropHandler, type SnapshotBuilder } from "./fs_drop.js";
import { FsScanHandler, type FsScanAbsorber } from "./fs_scan.js";
import { OpenTelemetryHandler, type OtelLogger } from "./otel.js";
import { StdoutHandler } from "./stdout.js";
import {
  VaultPullHandler,
  type VaultInboxClient,
  type VaultPullAbsorber,
} from "./vault_pull.js";
import { VaultPushHandler, type VaultPostClient } from "./vault_push.js";

/** Adapters injected by the host so handlers can build / absorb / POST without
 * a hard dependency on TNClient (avoids a cyclic import). */
export interface HandlerAdapters {
  /** `fs.drop` and `vault.push` snapshot builders. */
  snapshotBuilder: SnapshotBuilder;
  /** `fs.scan` absorber adapter. */
  fsAbsorber: FsScanAbsorber;
  /** `vault.pull` absorber adapter. */
  vaultAbsorber: VaultPullAbsorber;
  /** `vault.push` HTTP client factory (called per handler). */
  makeVaultPostClient?: (endpoint: string) => VaultPostClient;
  /** `vault.pull` HTTP client factory (called per handler). */
  makeVaultInboxClient?: (endpoint: string) => VaultInboxClient;
  /** Acting DID (for vault.pull `list_incoming`). */
  did: string;
  /** OTel logger injected by the host. Required when yaml declares
   * `kind: otel`. Pass via `addHandler(new OpenTelemetryHandler(...))`
   * directly if you don't want yaml-driven config. */
  otelLogger?: OtelLogger;
}

/** Parse a duration as ms. Accepts numbers (assumed seconds) or strings
 * like `"60s"`, `"5m"`, `"1h"`, `"500ms"` — same shape as Python
 * `_parse_duration`. */
export function parseDurationMs(value: unknown, defaultSec: number): number {
  if (value === null || value === undefined) return defaultSec * 1000;
  if (typeof value === "number") return value * 1000;
  if (typeof value === "string") {
    const s = value.trim().toLowerCase();
    let mult = 1.0;
    let num: string;
    if (s.endsWith("ms")) {
      num = s.slice(0, -2);
      mult = 0.001;
    } else if (s.endsWith("s")) {
      num = s.slice(0, -1);
      mult = 1.0;
    } else if (s.endsWith("m")) {
      num = s.slice(0, -1);
      mult = 60.0;
    } else if (s.endsWith("h")) {
      num = s.slice(0, -1);
      mult = 3600.0;
    } else {
      num = s;
    }
    const n = Number(num);
    if (!Number.isFinite(n)) {
      throw new Error(`tn.yaml: invalid duration ${JSON.stringify(value)}`);
    }
    return n * mult * 1000;
  }
  throw new Error(`tn.yaml: invalid duration value ${JSON.stringify(value)}`);
}

function resolvePath(p: string, yamlDir: string): string {
  return pathIsAbsolute(p) ? p : pathResolve(yamlDir, p);
}

/** Spec entry as produced by `yaml.parse`. */
export type HandlerSpec = Record<string, unknown>;

/**
 * Translate a raw yaml `filter:` block to a `FilterSpec`.
 *
 * Supports both the Python yaml shape (nested `event_type.starts_with`)
 * and the flat TS-native `FilterSpec` property names so that either form
 * works in tn.yaml:
 *
 *   filter:
 *     event_type:
 *       starts_with: "auth."   # → eventTypePrefix
 *
 *   filter:
 *     eventTypePrefix: "auth." # TS-native flat form
 */
function parseFilter(raw: unknown): FilterSpec | undefined {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  const spec: FilterSpec = {};
  let hasAny = false;

  // Python yaml nested shape: event_type.starts_with
  const eventTypeBlock = r["event_type"];
  if (eventTypeBlock != null && typeof eventTypeBlock === "object" && !Array.isArray(eventTypeBlock)) {
    const etb = eventTypeBlock as Record<string, unknown>;
    if (typeof etb["starts_with"] === "string") {
      spec.eventTypePrefix = etb["starts_with"];
      hasAny = true;
    }
    if (typeof etb["exact"] === "string") {
      spec.eventType = etb["exact"];
      hasAny = true;
    }
    if (typeof etb["not_starts_with"] === "string") {
      spec.notEventTypePrefix = etb["not_starts_with"];
      hasAny = true;
    }
  }

  // Flat TS-native property names (pass-through).
  if (typeof r["eventType"] === "string") { spec.eventType = r["eventType"]; hasAny = true; }
  if (typeof r["eventTypePrefix"] === "string") { spec.eventTypePrefix = r["eventTypePrefix"]; hasAny = true; }
  if (typeof r["notEventTypePrefix"] === "string") { spec.notEventTypePrefix = r["notEventTypePrefix"]; hasAny = true; }
  if (Array.isArray(r["eventTypeIn"])) { spec.eventTypeIn = r["eventTypeIn"] as string[]; hasAny = true; }
  if (typeof r["level"] === "string") { spec.level = r["level"]; hasAny = true; }
  if (Array.isArray(r["levelIn"])) { spec.levelIn = r["levelIn"] as string[]; hasAny = true; }

  return hasAny ? spec : undefined;
}

/** Build handler instances from the YAML `handlers:` block.
 *
 * `adapters` may be a partial object when only handler kinds that don't
 * need host adapters are declared (e.g. `file.rotating`, `stdout`). The
 * individual handler branches throw a descriptive error if a required
 * adapter field is absent. */
export function buildHandlers(
  specs: readonly HandlerSpec[],
  adapters: Partial<HandlerAdapters>,
  yamlDir: string,
): TNHandler[] {
  const out: TNHandler[] = [];
  for (const raw of specs) {
    const kind = String(raw["kind"] ?? "").toLowerCase();
    const name = (raw["name"] as string | undefined) ?? kind ?? "handler";
    const filterSpec = raw["filter"] as Record<string, unknown> | undefined;
    if (kind === "vault.push") {
      const endpoint = requireStr(raw, "endpoint", "vault.push");
      const projectId = requireStr(raw, "project_id", "vault.push");
      const trigger = (raw["trigger"] as "on_emit" | "on_schedule" | undefined) ?? "on_schedule";
      if (trigger !== "on_emit" && trigger !== "on_schedule") {
        throw new Error(
          `vault.push: trigger must be 'on_emit' or 'on_schedule', got ${JSON.stringify(trigger)}`,
        );
      }
      const pollIntervalMs = parseDurationMs(raw["poll_interval"], 60);
      const scope = (raw["scope"] as string | undefined) ?? "admin";
      if (!adapters.snapshotBuilder) {
        throw new Error(
          `tn.yaml: handler ${JSON.stringify(name)} of kind "vault.push" requires adapters.snapshotBuilder.`,
        );
      }
      const client = adapters.makeVaultPostClient?.(endpoint);
      out.push(
        new VaultPushHandler(name, {
          endpoint,
          projectId,
          builder: adapters.snapshotBuilder,
          client,
          trigger,
          pollIntervalMs,
          scope,
          filter: filterSpec,
        } as ConstructorParameters<typeof VaultPushHandler>[1]),
      );
      continue;
    }
    if (kind === "vault.pull") {
      const endpoint = requireStr(raw, "endpoint", "vault.pull");
      const projectId = requireStr(raw, "project_id", "vault.pull");
      const pollIntervalMs = parseDurationMs(raw["poll_interval"], 60);
      const onAbsorbError =
        (raw["on_absorb_error"] as "log" | "raise" | undefined) ?? "log";
      if (onAbsorbError !== "log" && onAbsorbError !== "raise") {
        throw new Error(
          `vault.pull: on_absorb_error must be 'log' or 'raise', got ${JSON.stringify(onAbsorbError)}`,
        );
      }
      if (adapters.makeVaultInboxClient === undefined) {
        throw new Error(
          "vault.pull: HandlerAdapters.makeVaultInboxClient is required (no built-in default).",
        );
      }
      if (!adapters.vaultAbsorber) {
        throw new Error(
          `tn.yaml: handler ${JSON.stringify(name)} of kind "vault.pull" requires adapters.vaultAbsorber.`,
        );
      }
      const client = adapters.makeVaultInboxClient(endpoint);
      const cursorDir = join(yamlDir, ".tn", "admin");
      out.push(
        new VaultPullHandler(name, {
          endpoint,
          projectId,
          did: adapters.did ?? "",
          client,
          absorber: adapters.vaultAbsorber,
          cursorDir,
          pollIntervalMs,
          onAbsorbError,
          filter: filterSpec,
        } as ConstructorParameters<typeof VaultPullHandler>[1]),
      );
      continue;
    }
    if (kind === "fs.drop") {
      const trigger = (raw["trigger"] as string | undefined) ?? "on_emit";
      if (trigger !== "on_emit") {
        throw new Error(
          `fs.drop: trigger=${JSON.stringify(trigger)} not supported yet; only 'on_emit' is implemented.`,
        );
      }
      const outDir = resolvePath((raw["out_dir"] as string | undefined) ?? "./.tn/outbox", yamlDir);
      const scope = (raw["scope"] as string | undefined) ?? "admin";
      const filenameTemplate = raw["filename_template"] as string | undefined;
      const on = (raw["on"] as readonly string[] | undefined) ?? undefined;
      if (!adapters.snapshotBuilder) {
        throw new Error(
          `tn.yaml: handler ${JSON.stringify(name)} of kind "fs.drop" requires adapters.snapshotBuilder.`,
        );
      }
      out.push(
        new FsDropHandler(name, {
          outDir,
          builder: adapters.snapshotBuilder,
          on,
          scope,
          filenameTemplate,
          filter: filterSpec,
        } as ConstructorParameters<typeof FsDropHandler>[1]),
      );
      continue;
    }
    if (kind === "stdout") {
      const opts: { name: string; filter?: FilterSpec } = { name };
      if (filterSpec !== undefined) opts.filter = filterSpec as FilterSpec;
      out.push(new StdoutHandler(opts));
      continue;
    }
    if (kind === "fs.scan") {
      const inDir = resolvePath(requireStr(raw, "in_dir", "fs.scan"), yamlDir);
      const pollIntervalMs = parseDurationMs(raw["poll_interval"], 30);
      const onProcessed = (raw["on_processed"] as "archive" | "delete" | undefined) ?? "archive";
      if (onProcessed !== "archive" && onProcessed !== "delete") {
        throw new Error(
          `fs.scan: on_processed must be 'archive' or 'delete', got ${JSON.stringify(onProcessed)}`,
        );
      }
      const archiveDir =
        raw["archive_dir"] !== undefined
          ? resolvePath(raw["archive_dir"] as string, yamlDir)
          : undefined;
      const rejectedDir =
        raw["rejected_dir"] !== undefined
          ? resolvePath(raw["rejected_dir"] as string, yamlDir)
          : undefined;
      if (!adapters.fsAbsorber) {
        throw new Error(
          `tn.yaml: handler ${JSON.stringify(name)} of kind "fs.scan" requires adapters.fsAbsorber.`,
        );
      }
      out.push(
        new FsScanHandler(name, {
          inDir,
          absorber: adapters.fsAbsorber,
          pollIntervalMs,
          onProcessed,
          archiveDir,
          rejectedDir,
          filter: filterSpec,
        } as ConstructorParameters<typeof FsScanHandler>[1]),
      );
      continue;
    }
    if (kind === "file.rotating") {
      const path = String(raw["path"] ?? "");
      if (!path) {
        throw new Error(
          `tn.yaml: handler ${JSON.stringify(name)} of kind ${JSON.stringify(kind)} is missing required field "path"`,
        );
      }
      const resolved = pathIsAbsolute(path) ? path : pathResolve(yamlDir, path);
      const fileOpts: import("./file.js").FileHandlerOptions = {};
      if (typeof raw["max_bytes"] === "number") fileOpts.maxBytes = raw["max_bytes"];
      if (typeof raw["backup_count"] === "number") fileOpts.backupCount = raw["backup_count"];
      const fileFilter = parseFilter(raw["filter"]);
      if (fileFilter !== undefined) fileOpts.filter = fileFilter;
      out.push(new FileHandler(name, resolved, fileOpts));
      continue;
    }
    if (kind === "otel") {
      if (!adapters.otelLogger) {
        throw new Error(
          `tn.yaml: handler ${JSON.stringify(name)} of kind "otel" requires an OtelLogger adapter — pass adapters.otelLogger when calling buildHandlers().`,
        );
      }
      const otelOpts: import("./otel.js").OpenTelemetryHandlerOptions = {};
      const otelFilter = parseFilter(raw["filter"]);
      if (otelFilter !== undefined) otelOpts.filter = otelFilter;
      out.push(new OpenTelemetryHandler(name, adapters.otelLogger, otelOpts));
      continue;
    }
    throw new Error(`tn.yaml: unknown handler kind ${JSON.stringify(kind)} on handler ${JSON.stringify(name)}`);
  }
  return out;
}

function requireStr(raw: HandlerSpec, key: string, ctx: string): string {
  const v = raw[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`${ctx}: missing required string field ${JSON.stringify(key)}`);
  }
  return v;
}
