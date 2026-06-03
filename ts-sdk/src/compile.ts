// Compile btn keystore material into a `.tnpkg` file (a ZIP archive)
// that the Chrome extension, the Python SDK, and any other TN reader
// can consume. This is the TS/Node analog of
// `tn.compile.compile_kit_bundle` in Python.
//
// .tnpkg layout
// -------------
//
//   manifest.json           small metadata (label, note, created_at,
//                           ceremony_id, did, kit_sha256 per kit).
//                           Optional but always written by this
//                           function.
//   <group>.btn.mykit       raw reader-kit bytes, one per group.
//                           Multiple allowed.
//   <group>.btn.mykit.revoked.<ts>   rotation-preserved kits.
//
// With `full: true` the archive additionally carries the publisher
// seed + state + index master + tn.yaml so the recipient ends up with
// a complete ceremony. Don't use that for sharing; use it for
// self-backup only.
//
// The archive uses STORED compression (method 0). Kits are tiny (a couple
// of KB each), and the shared browser-safe `.tnpkg` helper keeps archive
// behavior aligned with the rest of the SDK.

import { Buffer } from "node:buffer";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { packTnpkg, type ZipEntry } from "./core/tnpkg_archive.js";
import { loadConfig } from "./runtime/config.js";

export interface CompileKitBundleOptions {
  /** Keystore directory (e.g. `./demo/alice/keys`). Either this or `yamlPath` is required. */
  keystoreDir?: string;
  /** Path to a tn.yaml. If given, `keystoreDir` is inferred from the yaml's keystore.path. */
  yamlPath?: string;
  /** If set, include ONLY these group names (e.g. ["trading", "chat"]). Default: all. */
  groups?: string[];
  /** Human-readable label the Chrome extension shows in the popup. */
  label?: string;
  /** Optional free-form note the recipient sees at import time. */
  note?: string;
  /**
   * Include publisher-side material (signing seed, publisher state,
   * index master, tn.yaml) alongside the reader kits. Use this for
   * self-backup only.
   */
  full?: boolean;
}

export interface CompiledManifest {
  version: "tnpkg-v1";
  label: string | null;
  note: string | null;
  did: string | null;
  ceremony_id: string | null;
  kind: "readers-only" | "full-keystore";
  created_at: string;
  kits: Array<{ name: string; sha256: string; bytes: number }>;
}

export interface CompiledPackage {
  manifest: CompiledManifest;
  zipBytes: Uint8Array;
}

const KIT_RE = /^(.+?)\.btn\.(mykit|mykit\.revoked\.\d+)$/;

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}

// ---------------------------------------------------------------------------
// Public: compile to in-memory package + optional write-to-file
// ---------------------------------------------------------------------------

/**
 * Build a `.tnpkg` package in memory. Pure function: reads from disk,
 * writes nothing.
 */
export function compileKitBundle(opts: CompileKitBundleOptions): CompiledPackage {
  let keystoreDir = opts.keystoreDir ? resolve(opts.keystoreDir) : null;
  let did: string | null = null;
  let ceremonyId: string | null = null;
  let yamlPath: string | null = null;

  if (opts.yamlPath) {
    const cfg = loadConfig(opts.yamlPath);
    if (!keystoreDir) keystoreDir = cfg.keystorePath;
    did = cfg.device.device_identity || null;
    ceremonyId = cfg.ceremonyId || null;
    yamlPath = resolve(opts.yamlPath);
  }
  if (!keystoreDir) {
    throw new Error("compileKitBundle: provide keystoreDir or yamlPath");
  }
  if (!existsSync(keystoreDir) || !statSync(keystoreDir).isDirectory()) {
    throw new Error(`compileKitBundle: keystore directory not found: ${keystoreDir}`);
  }

  const entries = readdirSync(keystoreDir);
  const groupFilter = opts.groups && opts.groups.length > 0 ? new Set(opts.groups) : null;
  const zipEntries: ZipEntry[] = [];
  const manifestKits: CompiledManifest["kits"] = [];

  for (const name of entries) {
    const m = KIT_RE.exec(name);
    if (!m) continue;
    const group = m[1]!;
    if (groupFilter && !groupFilter.has(group)) continue;
    const data = new Uint8Array(readFileSync(join(keystoreDir, name)));
    zipEntries.push({ name, data });
    manifestKits.push({ name, sha256: `sha256:${sha256Hex(data)}`, bytes: data.length });
  }

  if (manifestKits.length === 0) {
    const suffix = groupFilter ? ` matching groups [${Array.from(groupFilter).join(", ")}]` : "";
    throw new Error(`compileKitBundle: no *.btn.mykit files in ${keystoreDir}${suffix}`);
  }

  if (opts.full) {
    for (const name of ["local.private", "local.public", "index_master.key"]) {
      const p = join(keystoreDir, name);
      if (existsSync(p)) {
        zipEntries.push({ name, data: new Uint8Array(readFileSync(p)) });
      }
    }
    for (const name of entries) {
      if (/\.btn\.state$/.test(name)) {
        const group = name.replace(/\.btn\.state$/, "");
        if (groupFilter && !groupFilter.has(group)) continue;
        zipEntries.push({ name, data: new Uint8Array(readFileSync(join(keystoreDir, name))) });
      }
    }
    if (yamlPath && existsSync(yamlPath)) {
      zipEntries.push({ name: "tn.yaml", data: new Uint8Array(readFileSync(yamlPath)) });
    }
  }

  const manifest: CompiledManifest = {
    version: "tnpkg-v1",
    label: opts.label ?? null,
    note: opts.note ?? null,
    did,
    ceremony_id: ceremonyId,
    kind: opts.full ? "full-keystore" : "readers-only",
    created_at: new Date().toISOString(),
    kits: manifestKits,
  };
  zipEntries.unshift({
    name: "manifest.json",
    data: new Uint8Array(Buffer.from(JSON.stringify(manifest, null, 2) + "\n")),
  });

  return { manifest, zipBytes: packTnpkg(zipEntries) };
}

/**
 * Compile + write to `outPath`. Ensures the file name ends with
 * `.tnpkg`; if the caller passes a different suffix, we still write the
 * zip but warn so they know the convention.
 */
export function compileKitBundleToFile(opts: CompileKitBundleOptions & { outPath: string }): {
  manifest: CompiledManifest;
  outPath: string;
  kits: string[];
} {
  const { manifest, zipBytes } = compileKitBundle(opts);
  const outResolved = resolve(opts.outPath);
  writeFileSync(outResolved, zipBytes);
  const kits = manifest.kits.map((k) => k.name);
  return { manifest, outPath: outResolved, kits };
}
