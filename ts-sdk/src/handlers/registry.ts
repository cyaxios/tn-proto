// Handler registry — mirrors `python/tn/handlers/registry.py`.
//
// Consumes the YAML `handlers:` block and instantiates the matching
// handler classes. The four kinds wired here (`vault.push`,
// `vault.pull`, `fs.drop`, `fs.scan`) match the Python four byte-for-
// byte in field names + defaults; the `file.*` / `kafka` / `delta` /
// `s3` / `otel` kinds remain Python-only for now (out of scope for the
// admin-log push/pull set landed in commit 78f5617).

import { resolve as pathResolve, isAbsolute as pathIsAbsolute, join } from "node:path";

import type { TNHandler, FilterSpec } from "./base.js";
import { FsDropHandler, type SnapshotBuilder } from "./fs_drop.js";
import { FsScanHandler, type FsScanAbsorber } from "./fs_scan.js";
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

/** Build handler instances from the YAML `handlers:` block. */
export function buildHandlers(
  specs: readonly HandlerSpec[],
  adapters: HandlerAdapters,
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
      const client = adapters.makeVaultInboxClient(endpoint);
      const cursorDir = join(yamlDir, ".tn", "admin");
      out.push(
        new VaultPullHandler(name, {
          endpoint,
          projectId,
          did: adapters.did,
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
