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

import { canonicalize } from "./canonical.js";
import { bytesToB64, b64ToBytes } from "./encoding.js";
import type { DeviceKey } from "./signing.js";
import { verify as verifySig } from "./signing.js";
import { asDid } from "./types.js";

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
  m.manifestSignatureB64 = bytesToB64(sig);
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
    // Python uses standard base64; our internal helper accepts both
    // standard and URL-safe by normalizing through b64ToBytes.
    sigBytes = b64ToBytes(m.manifestSignatureB64);
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

// Internal helpers re-exported for the tnpkg_io layer (Layer 2).
// Not part of the public browser-safe API, but needed for manifest ↔ JSON
// serialization in the Node I/O wrapper.
export { fromWireDict, toWireDict };
