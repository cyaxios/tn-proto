// `fs.drop` handler — write `.tnpkg` admin snapshots to a watched directory.
//
// Mirrors `python/tn/handlers/fs_drop.py` byte-for-byte where it matters:
// the same default filename template, the same idempotency guard
// (skip-when-head-unchanged), and the same on-emit semantics.
//
// Design notes:
// * `_buildSnapshot` is a callback rather than a hard reference to
//   `TNClient` so this module can sit underneath the TNClient/NodeRuntime
//   layer without a circular import. The host (TNClient or a test)
//   provides a builder that calls `client.export({kind:"admin_log_snapshot",...})`
//   and returns the resulting bytes plus the parsed manifest.
// * Filesystem writes are sync — these handlers don't try to overlap I/O
//   with each other; the runtime calls `emit` from a single thread.

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { BaseTNHandler, type FilterSpec } from "./base.js";
import { type Manifest } from "../core/tnpkg.js";
import { readTnpkg } from "../tnpkg_io.js";

/** Default filename template — must match `python/tn/handlers/fs_drop.py`. */
export const DEFAULT_FS_DROP_FILENAME_TEMPLATE =
  "snapshot_{ceremony_id}_{date}_{head_row_hash:short}.tnpkg";

/** Builder shape — the host wires this to `client.export(...)`. */
export interface SnapshotBuilder {
  /**
   * Build an admin-log snapshot at `outPath`, returning the manifest
   * bytes (file is written as a side effect) and the parsed manifest.
   */
  buildSnapshot(outPath: string, scope: string): { bytes: Uint8Array; manifest: Manifest };
}

export interface FsDropHandlerOptions {
  /** Destination directory. Created on demand. */
  outDir: string;
  /** Snapshot builder (typically a TNClient adapter). */
  builder: SnapshotBuilder;
  /** Allowlist of event types to drop on; null/undefined = every `tn.*` event. */
  on?: readonly string[];
  /** Snapshot scope — passed to export. Default `"admin"`. */
  scope?: string;
  /** Filename template; see `DEFAULT_FS_DROP_FILENAME_TEMPLATE`. */
  filenameTemplate?: string;
  filter?: FilterSpec;
}

/** Drop `.tnpkg` admin snapshots into a local watched directory. */
export class FsDropHandler extends BaseTNHandler {
  private readonly outDir: string;
  private readonly onTypes: ReadonlySet<string> | null;
  private readonly scope: string;
  private readonly filenameTemplate: string;
  private readonly builder: SnapshotBuilder;
  private lastShippedHead: string | null = null;

  constructor(name: string, opts: FsDropHandlerOptions) {
    super(name, opts.filter);
    this.outDir = opts.outDir;
    this.builder = opts.builder;
    this.onTypes = opts.on ? new Set(opts.on) : null;
    this.scope = opts.scope ?? "admin";
    this.filenameTemplate = opts.filenameTemplate ?? DEFAULT_FS_DROP_FILENAME_TEMPLATE;
  }

  override accepts(envelope: Record<string, unknown>): boolean {
    if (!super.accepts(envelope)) return false;
    const et = String(envelope["event_type"] ?? "");
    if (!et.startsWith("tn.")) return false;
    if (this.onTypes !== null && !this.onTypes.has(et)) return false;
    return true;
  }

  emit(_envelope: Record<string, unknown>, _rawLine: string): void {
    try {
      this.dropSnapshot();
    } catch (e) {
      console.warn(`[${this.name}] fs.drop emit failed:`, e);
    }
  }

  /** Public test seam — synchronously build + write one snapshot. */
  dropSnapshot(): string | null {
    if (!existsSync(this.outDir)) mkdirSync(this.outDir, { recursive: true });
    const tmpStamp = nowStampMicro();
    const tmpPath = join(this.outDir, `snapshot_inflight_${tmpStamp}.tnpkg`);

    let manifest: Manifest;
    try {
      const built = this.builder.buildSnapshot(tmpPath, this.scope);
      manifest = built.manifest;
    } catch (e) {
      try {
        unlinkSync(tmpPath);
      } catch {
        // best-effort
      }
      throw e;
    }

    const head = manifest.headRowHash ?? null;
    if (head !== null && this.lastShippedHead === head) {
      try {
        unlinkSync(tmpPath);
      } catch {
        // best-effort
      }
      return null;
    }

    const finalName = formatFilename(
      this.filenameTemplate,
      manifest.ceremonyId,
      head,
      manifest.fromDid,
    );
    let finalPath = join(this.outDir, finalName);
    if (existsSync(finalPath)) {
      const suffix = nowStampMicro();
      const dot = finalName.lastIndexOf(".");
      const stem = dot >= 0 ? finalName.slice(0, dot) : finalName;
      const ext = dot >= 0 ? finalName.slice(dot) : "";
      finalPath = join(this.outDir, `${stem}__${suffix}${ext}`);
    }
    renameSync(tmpPath, finalPath);
    this.lastShippedHead = head;
    return finalPath;
  }
}

/** Helper used by tests/hosts to build a snapshot via TNClient. */
export function makePackageSnapshotBuilder(client: {
  export: (opts: { kind: string; scope?: string }, outPath: string) => string;
}): SnapshotBuilder {
  return {
    buildSnapshot(outPath: string, scope: string) {
      client.export({ kind: "admin_log_snapshot", scope }, outPath);
      const bytes = readFileSync(outPath);
      const { manifest } = readTnpkg(bytes);
      return { bytes, manifest };
    },
  };
}

const DISALLOWED = /[<>:"/\\|?*]/g;

function sanitizeFilename(name: string): string {
  return name.replace(DISALLOWED, "_");
}

function shortHash(rh: string | null): string {
  if (rh === null || rh === "") return "noop";
  const stripped = rh.startsWith("sha256:") ? rh.slice("sha256:".length) : rh;
  return stripped.slice(0, 12);
}

function nowStampMicro(): string {
  // Python uses %Y%m%dT%H%M%S%f (microseconds). JS Date only has ms; pad
  // with three zeros for parity in shape, not in precision.
  const d = new Date();
  const pad = (n: number, w: number) => String(n).padStart(w, "0");
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1, 2)}${pad(d.getUTCDate(), 2)}` +
    `T${pad(d.getUTCHours(), 2)}${pad(d.getUTCMinutes(), 2)}${pad(d.getUTCSeconds(), 2)}` +
    `${pad(d.getUTCMilliseconds(), 3)}000`
  );
}

function nowStampSeconds(): string {
  const d = new Date();
  const pad = (n: number, w: number) => String(n).padStart(w, "0");
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1, 2)}${pad(d.getUTCDate(), 2)}` +
    `T${pad(d.getUTCHours(), 2)}${pad(d.getUTCMinutes(), 2)}${pad(d.getUTCSeconds(), 2)}Z`
  );
}

/** Substitute placeholders in a fs.drop filename template. */
export function formatFilename(
  template: string,
  ceremonyId: string,
  headRowHash: string | null,
  fromDid: string,
): string {
  const head = headRowHash ?? "";
  const headShort = shortHash(headRowHash);
  const date = nowStampSeconds();
  // Order matters: replace the longer placeholder first so it doesn't get
  // partially eaten by the shorter one.
  let out = template;
  out = out.replace("{head_row_hash:short}", headShort);
  out = out.replace("{head_row_hash}", head);
  out = out.replace("{ceremony_id}", ceremonyId);
  out = out.replace("{date}", date);
  out = out.replace("{from_did}", fromDid);
  return sanitizeFilename(out);
}

/** Used by `loadHandlers` to instantiate from yaml. */
export interface FsDropSpec {
  kind: "fs.drop";
  name?: string;
  out_dir?: string;
  on?: readonly string[];
  scope?: string;
  trigger?: string;
  filename_template?: string;
  filter?: FilterSpec;
}

void writeFileSync;
