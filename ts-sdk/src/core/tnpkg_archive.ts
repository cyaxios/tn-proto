// Browser-safe `.tnpkg` zip pack / parse layer.
//
// Operates on `Uint8Array` only — no Node APIs. DEFLATE decompression
// uses `fflate` (pure-JS, ~8KB, no native deps) so this module runs in
// both Node and browser / MV3 extension contexts.
//
// Public surface:
//   packTnpkg(entries)  → Uint8Array   (write a zip from in-memory entries)
//   parseTnpkg(bytes)   → ParsedZipEntry[]  (read a zip from in-memory bytes)

import { inflateSync } from "fflate";

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

// -----------------------------------------------------------------------
// Zip writer (STORED-only)
// -----------------------------------------------------------------------

function crc32(buf: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i]!;
    for (let k = 0; k < 8; k += 1) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(d: Date): { time: number; date: number } {
  const time =
    ((d.getHours() & 0x1f) << 11) |
    ((d.getMinutes() & 0x3f) << 5) |
    ((d.getSeconds() / 2) & 0x1f);
  const date =
    (((d.getFullYear() - 1980) & 0x7f) << 9) |
    (((d.getMonth() + 1) & 0xf) << 5) |
    (d.getDate() & 0x1f);
  return { time, date };
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
export function packTnpkg(entries: ZipEntry[]): Uint8Array {
  const { time, date } = dosDateTime(new Date());
  const localChunks: Uint8Array[] = [];
  const cdChunks: Uint8Array[] = [];
  let offset = 0;

  for (const e of entries) {
    const nameBytes = new TextEncoder().encode(e.name);
    const crc = crc32(e.data);
    const size = e.data.length;

    const lh = new Uint8Array(30 + nameBytes.length);
    const lhView = new DataView(lh.buffer);
    lhView.setUint32(0, 0x04034b50, true);
    lhView.setUint16(4, 20, true);
    lhView.setUint16(6, 0, true);
    lhView.setUint16(8, 0, true);
    lhView.setUint16(10, time, true);
    lhView.setUint16(12, date, true);
    lhView.setUint32(14, crc, true);
    lhView.setUint32(18, size, true);
    lhView.setUint32(22, size, true);
    lhView.setUint16(26, nameBytes.length, true);
    lhView.setUint16(28, 0, true);
    lh.set(nameBytes, 30);
    localChunks.push(lh, e.data);

    const cd = new Uint8Array(46 + nameBytes.length);
    const cdView = new DataView(cd.buffer);
    cdView.setUint32(0, 0x02014b50, true);
    cdView.setUint16(4, 20, true);
    cdView.setUint16(6, 20, true);
    cdView.setUint16(8, 0, true);
    cdView.setUint16(10, 0, true);
    cdView.setUint16(12, time, true);
    cdView.setUint16(14, date, true);
    cdView.setUint32(16, crc, true);
    cdView.setUint32(20, size, true);
    cdView.setUint32(24, size, true);
    cdView.setUint16(28, nameBytes.length, true);
    cdView.setUint16(30, 0, true);
    cdView.setUint16(32, 0, true);
    cdView.setUint16(34, 0, true);
    cdView.setUint16(36, 0, true);
    cdView.setUint32(38, 0, true);
    cdView.setUint32(42, offset, true);
    cd.set(nameBytes, 46);
    cdChunks.push(cd);

    offset += lh.length + e.data.length;
  }

  const cdStart = offset;
  const cdBytes = concat(cdChunks);
  const cdSize = cdBytes.length;

  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(4, 0, true);
  eocdView.setUint16(6, 0, true);
  eocdView.setUint16(8, entries.length, true);
  eocdView.setUint16(10, entries.length, true);
  eocdView.setUint32(12, cdSize, true);
  eocdView.setUint32(16, cdStart, true);
  eocdView.setUint16(20, 0, true);

  return concat([...localChunks, cdBytes, eocd]);
}

// -----------------------------------------------------------------------
// Zip reader. Handles the small subset of zip features Python's
// `zipfile.ZipFile` produces for `.tnpkg` archives: STORED + DEFLATE,
// no encryption, no zip64. DEFLATE is decompressed via fflate's
// inflateSync (raw deflate, same as zip method 8) because Python defaults
// to STORED but a future producer may switch to DEFLATE — we accept both.
// -----------------------------------------------------------------------

/** Parse a zip archive from raw bytes. Returns all entries. Does NOT
 * verify the manifest signature — call `verifyManifest` separately. */
export function parseTnpkg(bytes: Uint8Array): ParsedZipEntry[] {
  // Find EOCD by scanning backwards for signature 0x06054b50.
  const sig = 0x06054b50;
  let eocdOffset = -1;
  // EOCD is at most 22 + 0xffff bytes from the end.
  const minStart = Math.max(0, bytes.length - (22 + 0xffff));
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = bytes.length - 22; i >= minStart; i -= 1) {
    if (dv.getUint32(i, true) === sig) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error("parseTnpkg: end-of-central-directory record not found (not a zip?)");
  }
  const cdEntries = dv.getUint16(eocdOffset + 10, true);
  const cdSize = dv.getUint32(eocdOffset + 12, true);
  const cdOffset = dv.getUint32(eocdOffset + 16, true);
  if (cdOffset + cdSize > bytes.length) {
    throw new Error("parseTnpkg: central directory extends past archive end");
  }

  const entries: ParsedZipEntry[] = [];
  let cur = cdOffset;
  for (let i = 0; i < cdEntries; i += 1) {
    if (dv.getUint32(cur, true) !== 0x02014b50) {
      throw new Error(`parseTnpkg: invalid central-directory entry signature at offset ${cur}`);
    }
    const method = dv.getUint16(cur + 10, true);
    const compSize = dv.getUint32(cur + 20, true);
    const uncompSize = dv.getUint32(cur + 24, true);
    const nameLen = dv.getUint16(cur + 28, true);
    const extraLen = dv.getUint16(cur + 30, true);
    const commentLen = dv.getUint16(cur + 32, true);
    const localHeaderOffset = dv.getUint32(cur + 42, true);
    const name = new TextDecoder("utf-8").decode(bytes.subarray(cur + 46, cur + 46 + nameLen));
    cur += 46 + nameLen + extraLen + commentLen;

    if (dv.getUint32(localHeaderOffset, true) !== 0x04034b50) {
      throw new Error(
        `parseTnpkg: invalid local-file-header signature at offset ${localHeaderOffset}`,
      );
    }
    const lhNameLen = dv.getUint16(localHeaderOffset + 26, true);
    const lhExtraLen = dv.getUint16(localHeaderOffset + 28, true);
    const dataStart = localHeaderOffset + 30 + lhNameLen + lhExtraLen;
    const compBytes = bytes.subarray(dataStart, dataStart + compSize);

    let data: Uint8Array;
    if (method === 0) {
      data = compBytes.slice();
    } else if (method === 8) {
      // fflate inflateSync decodes raw deflate (zip method 8).
      data = inflateSync(compBytes);
      if (uncompSize && data.length !== uncompSize) {
        throw new Error(
          `parseTnpkg: deflate produced ${data.length} bytes but central dir says ${uncompSize}`,
        );
      }
    } else {
      throw new Error(`parseTnpkg: unsupported compression method ${method} for entry ${name}`);
    }
    entries.push({ name, data });
  }
  return entries;
}
