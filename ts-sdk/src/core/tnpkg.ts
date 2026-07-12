// Universal `.tnpkg` wrapper — signed manifest + kind-specific body.
//
// Mirrors `tn_proto/python/tn/tnpkg.py` byte-for-byte on the wire.
// Every `.tnpkg` is a zip archive:
//
//     foo.tnpkg/
//       manifest.json    ← signed JSON; the index
//       body/...         ← kind-specific contents
//
// The manifest is signed with Ed25519 by `publisher_identity`'s device key, over
// the canonical bytes of the manifest minus the signature field. The
// internal TS object uses camelCase (`fromDid`, `toDid`, ...) but the
// wire form is snake_case so Python and Rust readers see byte-identical
// JSON — see `toWireDict` below.
//
// Body shape varies by `kind`. Producer / consumer dispatch lives in the
// TNClient `export` / `absorb` methods.

import {
  manifestClockDominates as rawClockDominates,
  manifestClockMerge as rawClockMerge,
} from "../raw.js";
import { canonicalize } from "./canonical.js";
import { sha256HexBytes } from "./chain.js";
import { b64ToBytes, bytesToB64 } from "./encoding.js";
import { type DeviceKey, verify as verifySignature } from "./signing.js";
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
  // Vault-emitted notification that a counterparty claimed a share-link
  // or backup-link. Mirror only - TS absorb is not implemented yet.
  | "contact_update"
  // Two-device group sync (DAY-1): carries a ceremony's group KEY material
  // (`<group>.btn.state` + `<group>.btn.mykit`) PLUS each group's yaml
  // `groups.<name>` block, scoped to the OWN account so a second device that
  // pulls + absorbs ends up with the group INSTALLED (keystore) and ROUTABLE
  // (registered in its yaml). Unlike `full_keystore` it carries NO device
  // secret (`local.private`), and unlike `kit_bundle` it carries the
  // publisher `.btn.state` needed to ENCRYPT. Content-addressed + union-merge
  // on absorb (idempotent; two devices adding different groups → clean union).
  | "group_keys"
  | "identity_seed"
  | "project_seed";

// Enumerated to match the `ManifestKind` union above and built as a plain TS
// constant — NOT via the wasm `manifestKnownKinds()`. A module-level wasm call
// runs at import, before the web-target wasm is initialized, which throws and
// breaks every browser consumer (vendored OR npm). The drift test
// `known_kinds_parity` asserts this set equals the Rust core's
// manifestKnownKinds() so the two can never diverge.
export const KNOWN_KINDS: ReadonlySet<ManifestKind> = new Set<ManifestKind>([
  "admin_log_snapshot",
  "offer",
  "enrolment",
  "recipient_invite",
  "kit_bundle",
  "full_keystore",
  "contact_update",
  "group_keys",
  "identity_seed",
  "project_seed",
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
  /** Exact final archive member name to lowercase tagged SHA-256 digest. */
  bodySha256?: Record<string, string>;
  manifestSignatureB64?: string;
}

export type BodyContents = Record<string, Uint8Array>;

// -----------------------------------------------------------------------
// Snake-case wire format
// -----------------------------------------------------------------------

/** Build the snake-case wire dict from a TS Manifest. Optional fields are
 * omitted when null/undefined so the canonical form stays stable. */
function manifestToCandidateWireDict(
  m: Manifest,
  includeSignature: boolean,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    kind: m.kind,
    version: m.version,
    publisher_identity: m.fromDid,
    ceremony_id: m.ceremonyId,
    as_of: m.asOf,
    scope: m.scope,
    clock: m.clock,
    event_count: m.eventCount,
  };
  if (m.toDid !== undefined && m.toDid !== null) out["recipient_identity"] = m.toDid;
  if (m.headRowHash !== undefined && m.headRowHash !== null) {
    out["head_row_hash"] = m.headRowHash;
  }
  if (m.state !== undefined && m.state !== null) out["state"] = m.state;
  if (m.bodySha256 !== undefined) out["body_sha256"] = { ...m.bodySha256 };
  if (includeSignature && m.manifestSignatureB64) {
    out["manifest_signature_b64"] = m.manifestSignatureB64;
  }
  return out;
}

function toWireDict(m: Manifest, includeSignature: boolean): Record<string, unknown> {
  return manifestToCandidateWireDict(m, includeSignature);
}

/** Parse a snake-case JSON dict into a TS Manifest. Throws on missing
 * required fields. */
function fromWireDict(doc: unknown): Manifest {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error(`manifest must be a JSON object; got ${typeof doc}`);
  }
  const d = doc as Record<string, unknown>;
  const required = ["kind", "version", "publisher_identity", "ceremony_id", "as_of"];
  const missing = required.filter((k) => !(k in d));
  if (missing.length > 0) {
    throw new Error(`manifest missing required keys: ${JSON.stringify(missing)}`);
  }
  if (typeof d["kind"] !== "string") {
    throw new Error("manifest kind must be a string");
  }
  const kind = d["kind"];
  if (!KNOWN_KINDS.has(kind as ManifestKind)) {
    throw new Error(`manifest unknown kind: ${JSON.stringify(kind)}`);
  }
  const requiredString = (key: "publisher_identity" | "ceremony_id" | "as_of"): string => {
    const value = d[key];
    if (typeof value !== "string") {
      throw new Error(`manifest ${key} must be a string`);
    }
    return value;
  };
  const publisherIdentity = requiredString("publisher_identity");
  const ceremonyId = requiredString("ceremony_id");
  const asOf = requiredString("as_of");
  const version = Number(d["version"]);
  if (!Number.isSafeInteger(version)) {
    throw new Error("manifest version must be an integer");
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
    kind,
    version,
    fromDid: publisherIdentity,
    ceremonyId,
    asOf,
    scope: typeof d["scope"] === "string" ? d["scope"] : "admin",
    clock,
    eventCount:
      typeof d["event_count"] === "number" ? d["event_count"] : Number(d["event_count"] ?? 0) || 0,
  };
  if (typeof d["recipient_identity"] === "string") {
    m.toDid = d["recipient_identity"];
  }
  if (typeof d["head_row_hash"] === "string") {
    m.headRowHash = d["head_row_hash"];
  }
  if (d["state"] !== undefined && d["state"] !== null) {
    m.state = d["state"] as Record<string, unknown>;
  }
  if (d["body_sha256"] !== undefined) {
    const rawBodyIndex = d["body_sha256"];
    if (!rawBodyIndex || typeof rawBodyIndex !== "object" || Array.isArray(rawBodyIndex)) {
      throw new Error("manifest body_sha256 must be a JSON object");
    }
    const bodySha256: Record<string, string> = {};
    for (const [name, digest] of Object.entries(rawBodyIndex as Record<string, unknown>)) {
      if (typeof digest !== "string") {
        throw new Error("manifest body_sha256 keys and values must be strings");
      }
      bodySha256[name] = digest;
    }
    m.bodySha256 = bodySha256;
  }
  if (typeof d["manifest_signature_b64"] === "string") {
    m.manifestSignatureB64 = d["manifest_signature_b64"];
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
  return canonicalize(manifestToCandidateWireDict(m, false));
}

/** Validate an exact normalized non-manifest archive member path. */
export function validateTnpkgBodyName(name: string): void {
  if (!name.startsWith("body/") || name === "body/") {
    throw new Error(
      `tnpkg: invalid package member ${JSON.stringify(name)}; expected manifest.json or body/...`,
    );
  }
  if (name.startsWith("/") || name.includes("\\") || name.includes("\0")) {
    throw new Error(
      `tnpkg: invalid package member ${JSON.stringify(name)}; only POSIX relative paths are allowed`,
    );
  }
  if (name.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(
      `tnpkg: invalid package member ${JSON.stringify(name)}; path traversal is forbidden`,
    );
  }
}

/** Compute the canonical index over the exact final bytes stored in `body/...`. */
export function computeBodySha256(body: BodyContents): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of Object.keys(body).sort()) {
    validateTnpkgBodyName(name);
    const bytes = body[name];
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError(`tnpkg body member ${JSON.stringify(name)} must be a Uint8Array`);
    }
    out[name] = `sha256:${sha256HexBytes(bytes)}`;
  }
  return out;
}

/** Populate the body index and invalidate any signature over an older body. */
export function prepareManifestBodyIndex(m: Manifest, body: BodyContents): Manifest {
  m.bodySha256 = computeBodySha256(body);
  delete m.manifestSignatureB64;
  return m;
}

/** Index final stored body bytes, then sign the complete manifest domain. */
export function signManifestWithBody(
  m: Manifest,
  body: BodyContents,
  deviceKey: DeviceKey,
): Manifest {
  prepareManifestBodyIndex(m, body);
  return signManifest(m, deviceKey);
}

function bodyDigestMismatch(detail: string): Error {
  return new Error(`body_digest_mismatch: ${detail}`);
}

/** Verify exact member names and lowercase tagged digests against the manifest. */
export function verifyManifestBodyIndex(
  m: Manifest,
  body: BodyContents,
  requireIndex = true,
): void {
  if (m.bodySha256 === undefined) {
    if (requireIndex) throw bodyDigestMismatch("manifest body_sha256 index is missing");
    return;
  }
  if (!m.bodySha256 || typeof m.bodySha256 !== "object" || Array.isArray(m.bodySha256)) {
    throw bodyDigestMismatch("manifest body_sha256 index is malformed");
  }
  for (const [name, digest] of Object.entries(m.bodySha256)) {
    try {
      validateTnpkgBodyName(name);
    } catch {
      throw bodyDigestMismatch(`invalid indexed body member ${JSON.stringify(name)}`);
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(digest)) {
      throw bodyDigestMismatch(`malformed digest for body member ${JSON.stringify(name)}`);
    }
  }

  let actual: Record<string, string>;
  try {
    actual = computeBodySha256(body);
  } catch {
    throw bodyDigestMismatch("body member set contains an invalid path or value");
  }
  const expectedNames = Object.keys(m.bodySha256).sort();
  const actualNames = Object.keys(actual).sort();
  if (
    expectedNames.length !== actualNames.length ||
    expectedNames.some(
      (name, index) => name !== actualNames[index] || m.bodySha256![name] !== actual[name],
    )
  ) {
    throw bodyDigestMismatch("body index mismatch");
  }
}

/** Sign a manifest in place. Returns the same object with
 * `manifestSignatureB64` populated. */
export function signManifest(m: Manifest, deviceKey: DeviceKey): Manifest {
  const sig = deviceKey.sign(manifestSigningBytes(m));
  m.manifestSignatureB64 = bytesToB64(sig);
  return m;
}

/** Verify a manifest's signature against `publisher_identity`. Throws on failure;
 * returns silently on success. */
export function verifyManifest(m: Manifest): void {
  if (!m.manifestSignatureB64) {
    throw new Error("verifyManifest: manifest is unsigned (manifest_signature_b64 missing)");
  }
  let ok: boolean;
  try {
    const signature = b64ToBytes(m.manifestSignatureB64);
    ok =
      bytesToB64(signature) === m.manifestSignatureB64 &&
      signature.length === 64 &&
      verifySignature(asDid(m.fromDid), manifestSigningBytes(m), signature);
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new Error(
      `verifyManifest: signature does not verify against publisher_identity ${JSON.stringify(m.fromDid)}`,
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
  return rawClockDominates(a, b);
}

/**
 * Did the publisher of a snapshot already KNOW about a revoke?
 *
 * True iff the snapshot's vector clock covers the revoke event —
 * `manifestClock[revokedDid]['tn.recipient.revoked'] >= revokedSeq`. That
 * means the publisher had absorbed the revocation before shipping, so an
 * `added` for that leaf in the same snapshot is an informed equivocation,
 * not a concurrent race.
 *
 * Conservative: a missing did/event_type/seq coordinate counts as 0, and
 * an unknown `revokedSeq` returns false — we never accuse a publisher of
 * equivocation we can't prove. Mirrors Python `tn/absorb.py`
 * `_reuse_is_informed`.
 */
export function reuseIsInformed(
  revokedDid: string | null,
  revokedSeq: number | null,
  manifestClock: VectorClock | null | undefined,
): boolean {
  if (typeof revokedDid !== "string" || typeof revokedSeq !== "number") return false;
  if (!manifestClock) return false;
  const seen = manifestClock[revokedDid];
  if (!seen) return false;
  return (seen["tn.recipient.revoked"] ?? 0) >= revokedSeq;
}

/** Pointwise max of two vector clocks. Pure. */
export function clockMerge(a: VectorClock, b: VectorClock): VectorClock {
  return rawClockMerge(a, b) as VectorClock;
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
