// Browser-safe `.tnpkg` zip pack / parse layer.
//
// Operates on `Uint8Array` only — no Node APIs. ZIP writing and reading use
// `fflate` (pure-JS, no native deps) so this module runs in both Node and
// browser / MV3 extension contexts.
//
// Public surface:
//   packTnpkg(entries)  → Uint8Array   (write a zip from in-memory entries)
//   parseTnpkg(bytes)   → ParsedZipEntry[]  (read a zip from in-memory bytes)

import { Unzip, UnzipInflate, UnzipPassThrough, Zip, ZipPassThrough } from "fflate";

// -----------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------

export interface ZipEntry {
  name: string;
  data: Uint8Array;
}

export interface ParsedZipEntry {
  name: string;
  data: Uint8Array;
}

export interface PackTnpkgOptions {
  mtime?: Date;
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

/** Pack a list of entries into a STORED zip archive. Returns the raw bytes. */
export function packTnpkg(entries: ZipEntry[], opts: PackTnpkgOptions = {}): Uint8Array {
  const chunks: Uint8Array[] = [];
  const zip = new Zip((err, chunk) => {
    if (err) throw err;
    if (chunk) chunks.push(chunk);
  });
  for (const e of entries) {
    const file = new ZipPassThrough(e.name);
    file.mtime = opts.mtime ?? new Date();
    zip.add(file);
    file.push(e.data, true);
  }
  zip.end();
  return concat(chunks);
}

// -----------------------------------------------------------------------
// Zip reader. Handles the small subset of zip features used for `.tnpkg`
// archives: STORED + DEFLATE, no encryption, no zip64.
// -----------------------------------------------------------------------

/** Parse a zip archive from raw bytes. Returns all entries. Does NOT
 * verify the manifest signature — call `verifyManifest` separately. */
export function parseTnpkg(bytes: Uint8Array): ParsedZipEntry[] {
  const entries: ParsedZipEntry[] = [];
  const unzip = new Unzip((file) => {
    const chunks: Uint8Array[] = [];
    file.ondata = (err, chunk, final) => {
      if (err) throw err;
      if (chunk) chunks.push(chunk);
      if (final) entries.push({ name: file.name, data: concat(chunks) });
    };
    try {
      file.start();
    } catch (err) {
      throw new Error(`parseTnpkg: unsupported compression method ${file.compression}`, {
        cause: err,
      });
    }
  });
  unzip.register(UnzipPassThrough);
  unzip.register(UnzipInflate);
  try {
    unzip.push(bytes, true);
  } catch (err) {
    throw new Error(`parseTnpkg: invalid zip archive: ${(err as Error).message}`, { cause: err });
  }
  return entries;
}
