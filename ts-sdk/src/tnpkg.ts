// Universal `.tnpkg` wrapper — signed manifest + kind-specific body.
//
// Mirrors `tn-protocol/python/tn/tnpkg.py` byte-for-byte on the wire.
// Every `.tnpkg` is a zip archive:
//
//     foo.tnpkg/
//       manifest.json    ← signed JSON; the index
//       body/...         ← kind-specific contents
//
// The manifest is signed with Ed25519 by `from_did`'s device key, over
// the canonical bytes of the manifest minus the signature field. The
// internal TS object uses camelCase (`fromDid`, `toDid`, ...) but the
// wire form is snake_case so Python and Rust readers see byte-identical
// JSON — see `_toWireDict` below.
//
// Body shape varies by `kind`. Producer / consumer dispatch lives in the
// TNClient `export` / `absorb` methods.

import { Buffer } from "node:buffer";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";

import { canonicalize } from "./core/canonical.js";
import type { DeviceKey } from "./core/signing.js";
import { signatureB64, signatureFromB64, verify as verifySig } from "./core/signing.js";
import { asDid, asSignatureB64 } from "./types.js";

/** Manifest schema version. Bump if required fields change incompatibly. */
export const MANIFEST_VERSION = 1;

/** v1 dispatch discriminators. */
export type ManifestKind =
  | "admin_log_snapshot"
  | "offer"
  | "enrolment"
  | "recipient_invite"
  | "kit_bundle"
  | "full_keystore"
  // Session 8 (plan 2026-04-29-contact-update-tnpkg.md, spec §4.6 / D-11):
  // vault-emitted notification that a counterparty claimed a share-link
  // or backup-link. Mirror only — TS absorb is not implemented yet.
  | "contact_update";

export const KNOWN_KINDS: ReadonlySet<ManifestKind> = new Set<ManifestKind>([
  "admin_log_snapshot",
  "offer",
  "enrolment",
  "recipient_invite",
  "kit_bundle",
  "full_keystore",
  "contact_update",
]);

/** Vector clock keyed by `did → {event_type → max_seq}`. */
export type VectorClock = Record<string, Record<string, number>>;

/** Decoded `.tnpkg` manifest. Mirrors the JSON on the wire (snake_case
 * field names) but uses camelCase here for TS conventions. */
export interface Manifest {
  kind: ManifestKind | string;
  version: number;
  fromDid: string;
  toDid?: string;
  ceremonyId: string;
  asOf: string;
  scope: string;
  clock: VectorClock;
  eventCount: number;
  headRowHash?: string;
  state?: Record<string, unknown> | null;
  manifestSignatureB64?: string;
}

export type BodyContents = Record<string, Uint8Array>;

// -----------------------------------------------------------------------
// Snake-case wire format
// -----------------------------------------------------------------------

/** Build the snake-case wire dict from a TS Manifest. Optional fields are
 * omitted when null/undefined so the canonical form stays stable. */
function toWireDict(m: Manifest, includeSignature: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {
    kind: m.kind,
    version: m.version,
    from_did: m.fromDid,
    ceremony_id: m.ceremonyId,
    as_of: m.asOf,
    scope: m.scope,
    clock: m.clock,
    event_count: m.eventCount,
  };
  if (m.toDid !== undefined && m.toDid !== null) out["to_did"] = m.toDid;
  if (m.headRowHash !== undefined && m.headRowHash !== null) {
    out["head_row_hash"] = m.headRowHash;
  }
  if (m.state !== undefined && m.state !== null) out["state"] = m.state;
  if (includeSignature && m.manifestSignatureB64) {
    out["manifest_signature_b64"] = m.manifestSignatureB64;
  }
  return out;
}

/** Parse a snake-case JSON dict into a TS Manifest. Throws on missing
 * required fields. */
function fromWireDict(doc: unknown): Manifest {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error(`manifest must be a JSON object; got ${typeof doc}`);
  }
  const d = doc as Record<string, unknown>;
  const required = ["kind", "version", "from_did", "ceremony_id", "as_of"];
  const missing = required.filter((k) => !(k in d));
  if (missing.length > 0) {
    throw new Error(`manifest missing required keys: ${JSON.stringify(missing)}`);
  }
  const clock: VectorClock = {};
  const rawClock = d["clock"];
  if (rawClock && typeof rawClock === "object" && !Array.isArray(rawClock)) {
    for (const [did, etMap] of Object.entries(rawClock as Record<string, unknown>)) {
      if (!etMap || typeof etMap !== "object" || Array.isArray(etMap)) continue;
      const slot: Record<string, number> = {};
      for (const [et, seq] of Object.entries(etMap as Record<string, unknown>)) {
        const n = typeof seq === "number" ? seq : Number(seq);
        if (Number.isFinite(n)) slot[et] = Math.trunc(n);
      }
      clock[did] = slot;
    }
  }

  const m: Manifest = {
    kind: String(d["kind"]),
    version: Math.trunc(Number(d["version"])),
    fromDid: String(d["from_did"]),
    ceremonyId: String(d["ceremony_id"]),
    asOf: String(d["as_of"]),
    scope: typeof d["scope"] === "string" ? (d["scope"] as string) : "admin",
    clock,
    eventCount:
      typeof d["event_count"] === "number"
        ? (d["event_count"] as number)
        : Number(d["event_count"] ?? 0) || 0,
  };
  if (typeof d["to_did"] === "string") m.toDid = d["to_did"] as string;
  if (typeof d["head_row_hash"] === "string") m.headRowHash = d["head_row_hash"] as string;
  if (d["state"] !== undefined && d["state"] !== null) {
    m.state = d["state"] as Record<string, unknown>;
  }
  if (typeof d["manifest_signature_b64"] === "string") {
    m.manifestSignatureB64 = d["manifest_signature_b64"] as string;
  }
  return m;
}

// -----------------------------------------------------------------------
// Sign / verify
// -----------------------------------------------------------------------

/** Canonical bytes of the manifest with `manifest_signature_b64`
 * excluded — the exact domain over which the producer signs. Matches
 * Python `TnpkgManifest.signing_bytes`. */
export function manifestSigningBytes(m: Manifest): Uint8Array {
  return canonicalize(toWireDict(m, false));
}

/** Sign a manifest in place. Returns the same object with
 * `manifestSignatureB64` populated. */
export function signManifest(m: Manifest, deviceKey: DeviceKey): Manifest {
  const sig = deviceKey.sign(manifestSigningBytes(m));
  m.manifestSignatureB64 = Buffer.from(sig).toString("base64");
  return m;
}

/** Verify a manifest's signature against `from_did`. Throws on failure;
 * returns silently on success. */
export function verifyManifest(m: Manifest): void {
  if (!m.manifestSignatureB64) {
    throw new Error("verifyManifest: manifest is unsigned (manifest_signature_b64 missing)");
  }
  let sigBytes: Uint8Array;
  try {
    // Python uses standard base64; our internal helper expects URL-safe
    // no-padding. We accept both by normalizing through Node Buffer.
    sigBytes = new Uint8Array(Buffer.from(m.manifestSignatureB64, "base64"));
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`verifyManifest: signature is not valid base64: ${msg}`, { cause: e });
  }
  const ok = verifySig(asDid(m.fromDid), manifestSigningBytes(m), sigBytes);
  if (!ok) {
    throw new Error(
      `verifyManifest: signature does not verify against from_did ${JSON.stringify(m.fromDid)}`,
    );
  }
}

/** True iff the signature verifies; never throws. */
export function isManifestSignatureValid(m: Manifest): boolean {
  try {
    verifyManifest(m);
    return true;
  } catch {
    return false;
  }
}

// -----------------------------------------------------------------------
// Vector-clock helpers
// -----------------------------------------------------------------------

/** True iff vector clock `a` >= `b` on every (did, event_type) coord. */
export function clockDominates(a: VectorClock, b: VectorClock): boolean {
  for (const [did, etMap] of Object.entries(b)) {
    const aMap = a[did] ?? {};
    for (const [et, seq] of Object.entries(etMap)) {
      if ((aMap[et] ?? 0) < seq) return false;
    }
  }
  return true;
}

/** Pointwise max of two vector clocks. Pure. */
export function clockMerge(a: VectorClock, b: VectorClock): VectorClock {
  const out: VectorClock = {};
  for (const src of [a, b]) {
    for (const [did, etMap] of Object.entries(src)) {
      const slot = out[did] ?? {};
      for (const [et, seq] of Object.entries(etMap)) {
        const cur = slot[et] ?? 0;
        if (seq > cur) slot[et] = seq;
      }
      out[did] = slot;
    }
  }
  return out;
}

// -----------------------------------------------------------------------
// Zip writer / reader (STORED-only; reuses the encoder from compile.ts
// philosophy but kept local so this module is self-contained).
// -----------------------------------------------------------------------

interface ZipEntry {
  name: string;
  data: Uint8Array;
}

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

function encodeStoredZip(entries: ZipEntry[]): Uint8Array {
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
// no encryption, no zip64. DEFLATE is decompressed via Node's
// zlib.inflateRawSync because Python defaults to STORED but a future
// producer may switch to DEFLATE — we accept both.
// -----------------------------------------------------------------------

import { inflateRawSync } from "node:zlib";

interface ParsedZipEntry {
  name: string;
  data: Uint8Array;
}

function parseZip(bytes: Uint8Array): ParsedZipEntry[] {
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
    throw new Error("parseZip: end-of-central-directory record not found (not a zip?)");
  }
  const cdEntries = dv.getUint16(eocdOffset + 10, true);
  const cdSize = dv.getUint32(eocdOffset + 12, true);
  const cdOffset = dv.getUint32(eocdOffset + 16, true);
  if (cdOffset + cdSize > bytes.length) {
    throw new Error("parseZip: central directory extends past archive end");
  }

  const entries: ParsedZipEntry[] = [];
  let cur = cdOffset;
  for (let i = 0; i < cdEntries; i += 1) {
    if (dv.getUint32(cur, true) !== 0x02014b50) {
      throw new Error(`parseZip: invalid central-directory entry signature at offset ${cur}`);
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
        `parseZip: invalid local-file-header signature at offset ${localHeaderOffset}`,
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
      data = new Uint8Array(inflateRawSync(Buffer.from(compBytes)));
      if (uncompSize && data.length !== uncompSize) {
        throw new Error(
          `parseZip: deflate produced ${data.length} bytes but central dir says ${uncompSize}`,
        );
      }
    } else {
      throw new Error(`parseZip: unsupported compression method ${method} for entry ${name}`);
    }
    entries.push({ name, data });
  }
  return entries;
}

// -----------------------------------------------------------------------
// Public writer / reader
// -----------------------------------------------------------------------

/** Write a `.tnpkg` zip to `outPath`. The manifest must already be
 * signed (see `signManifest`). `body` keys are logical paths inside the
 * zip — typically `body/...` per the format. */
export function writeTnpkg(outPath: string, manifest: Manifest, body: BodyContents): string {
  if (!manifest.manifestSignatureB64) {
    throw new Error(
      "writeTnpkg: manifest is unsigned. Call signManifest(...) before writing — " +
        "the wire format requires manifest_signature_b64 to be present.",
    );
  }
  const resolved = pathResolve(outPath);
  const dir = dirname(resolved);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const wireDoc = toWireDict(manifest, true);
  const manifestJson = JSON.stringify(wireDoc, sortedReplacer(wireDoc), 2) + "\n";
  const entries: ZipEntry[] = [
    { name: "manifest.json", data: new TextEncoder().encode(manifestJson) },
  ];
  // Stable order: keys sorted lexicographically. Matches Python's
  // `zf.writestr` ordering driven by dict insertion, which is
  // unspecified — the receiver doesn't care, but a stable order keeps
  // diffs / fixtures readable.
  for (const name of Object.keys(body).sort()) {
    entries.push({ name, data: body[name]! });
  }
  writeFileSync(resolved, Buffer.from(encodeStoredZip(entries)));
  return resolved;
}

/** Sort-keys replacer for JSON.stringify so the manifest JSON in the
 * archive matches Python's `json.dumps(..., sort_keys=True, indent=2)`. */
function sortedReplacer(_root: unknown): (this: unknown, key: string, value: unknown) => unknown {
  return function replacer(_key, value) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  };
}

/** Open a `.tnpkg` from a file path or in-memory bytes. Returns the
 * parsed manifest plus a body map (every non-manifest entry). Does NOT
 * verify the signature — call `verifyManifest` separately. */
export function readTnpkg(source: string | Uint8Array): {
  manifest: Manifest;
  body: Map<string, Uint8Array>;
} {
  let bytes: Uint8Array;
  if (typeof source === "string") {
    if (!existsSync(source)) {
      throw new Error(`readTnpkg: source path does not exist: ${source}`);
    }
    bytes = new Uint8Array(readFileSync(source));
  } else {
    bytes = source;
  }
  let entries: ParsedZipEntry[];
  try {
    entries = parseZip(bytes);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`readTnpkg: input is not a valid \`.tnpkg\` zip: ${msg}`, { cause: e });
  }
  const manifestEntry = entries.find((e) => e.name === "manifest.json");
  if (!manifestEntry) {
    throw new Error(
      "readTnpkg: zip is missing `manifest.json`. The `.tnpkg` format requires a " +
        "top-level signed manifest; this archive does not have one.",
    );
  }
  const manifestDoc = JSON.parse(new TextDecoder("utf-8").decode(manifestEntry.data));
  const manifest = fromWireDict(manifestDoc);
  const body = new Map<string, Uint8Array>();
  for (const e of entries) {
    if (e.name === "manifest.json") continue;
    body.set(e.name, e.data);
  }
  return { manifest, body };
}

/** Build a zero-clock empty manifest with the required fields populated.
 * Convenience for callers that build kits / offer / enrolment exports. */
export function newManifest(args: {
  kind: ManifestKind | string;
  fromDid: string;
  ceremonyId: string;
  scope?: string;
  toDid?: string;
}): Manifest {
  const m: Manifest = {
    kind: args.kind,
    version: MANIFEST_VERSION,
    fromDid: args.fromDid,
    ceremonyId: args.ceremonyId,
    asOf: nowIsoMillis(),
    scope: args.scope ?? "admin",
    clock: {},
    eventCount: 0,
  };
  if (args.toDid !== undefined) m.toDid = args.toDid;
  return m;
}

/** RFC 3339 / ISO 8601 UTC timestamp with milliseconds. Matches Python's
 * `datetime.now(tz=utc).isoformat(timespec='milliseconds')`. */
export function nowIsoMillis(): string {
  // Node's Date.toISOString already yields ms precision. Convert the
  // trailing "Z" to "+00:00" to match Python's isoformat output.
  return new Date().toISOString().replace(/Z$/, "+00:00");
}

// keep a hint for the linter that signature codecs are referenced
void asSignatureB64;
void signatureB64;
void signatureFromB64;
