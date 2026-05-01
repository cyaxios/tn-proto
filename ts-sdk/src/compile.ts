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
// The archive uses STORED compression (method 0). Kits are tiny (a
// couple of KB each), and STORED keeps the encoder trivial (no extra
// deps, no DecompressionStream on the read side).

import { Buffer } from "node:buffer";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
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
// Minimal STORED zip encoder. No deps; ~80 lines. Enough for a handful
// of small files.
// ---------------------------------------------------------------------------

interface ZipEntryInput {
  name: string;
  data: Uint8Array;
}

function crc32(buf: Uint8Array): number {
  // Table-free CRC32 (IEEE polynomial 0xEDB88320). Small + fast enough.
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i]!;
    for (let k = 0; k < 8; k += 1) {
      c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(d: Date): { time: number; date: number } {
  const time =
    ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((d.getSeconds() / 2) & 0x1f);
  const date =
    (((d.getFullYear() - 1980) & 0x7f) << 9) |
    (((d.getMonth() + 1) & 0xf) << 5) |
    (d.getDate() & 0x1f);
  return { time, date };
}

function encodeStoredZip(entries: ZipEntryInput[]): Uint8Array {
  const { time, date } = dosDateTime(new Date());
  const localChunks: Uint8Array[] = [];
  const cdChunks: Uint8Array[] = [];
  let offset = 0;

  for (const e of entries) {
    const nameBytes = new TextEncoder().encode(e.name);
    const crc = crc32(e.data);
    const size = e.data.length;

    // Local file header (30 bytes + name + extra[0])
    const lh = new Uint8Array(30 + nameBytes.length);
    const lhView = new DataView(lh.buffer);
    lhView.setUint32(0, 0x04034b50, true);
    lhView.setUint16(4, 20, true); // version needed
    lhView.setUint16(6, 0, true); // general purpose bit flag
    lhView.setUint16(8, 0, true); // method: 0 = STORED
    lhView.setUint16(10, time, true);
    lhView.setUint16(12, date, true);
    lhView.setUint32(14, crc, true);
    lhView.setUint32(18, size, true); // compressed size
    lhView.setUint32(22, size, true); // uncompressed size
    lhView.setUint16(26, nameBytes.length, true);
    lhView.setUint16(28, 0, true); // extra length
    lh.set(nameBytes, 30);
    localChunks.push(lh, e.data);

    // Central directory entry (46 bytes + name)
    const cd = new Uint8Array(46 + nameBytes.length);
    const cdView = new DataView(cd.buffer);
    cdView.setUint32(0, 0x02014b50, true);
    cdView.setUint16(4, 20, true); // version made by
    cdView.setUint16(6, 20, true); // version needed
    cdView.setUint16(8, 0, true); // flags
    cdView.setUint16(10, 0, true); // method
    cdView.setUint16(12, time, true);
    cdView.setUint16(14, date, true);
    cdView.setUint32(16, crc, true);
    cdView.setUint32(20, size, true);
    cdView.setUint32(24, size, true);
    cdView.setUint16(28, nameBytes.length, true);
    cdView.setUint16(30, 0, true); // extra length
    cdView.setUint16(32, 0, true); // comment length
    cdView.setUint16(34, 0, true); // disk number
    cdView.setUint16(36, 0, true); // internal attrs
    cdView.setUint32(38, 0, true); // external attrs
    cdView.setUint32(42, offset, true);
    cd.set(nameBytes, 46);
    cdChunks.push(cd);

    offset += lh.length + e.data.length;
  }

  const cdStart = offset;
  const cdBytes = concat(cdChunks);
  const cdSize = cdBytes.length;

  // End of central directory (22 bytes)
  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(4, 0, true); // disk number
  eocdView.setUint16(6, 0, true); // cd start disk
  eocdView.setUint16(8, entries.length, true);
  eocdView.setUint16(10, entries.length, true);
  eocdView.setUint32(12, cdSize, true);
  eocdView.setUint32(16, cdStart, true);
  eocdView.setUint16(20, 0, true); // comment length

  return concat([...localChunks, cdBytes, eocd]);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
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
    did = cfg.me.did || null;
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
  const zipEntries: ZipEntryInput[] = [];
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

  return { manifest, zipBytes: encodeStoredZip(zipEntries) };
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
