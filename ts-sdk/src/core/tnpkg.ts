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
// JSON — see `_toWireDict` below.
//
// Body shape varies by `kind`. Producer / consumer dispatch lives in the
// TNClient `export` / `absorb` methods.

import {
  manifestClockDominates as rawClockDominates,
  manifestClockMerge as rawClockMerge,
  manifestKnownKinds,
  manifestSigningBytes as rawManifestSigningBytes,
  manifestToWireDict,
  manifestVerifySignature,
} from "../raw.js";
import { bytesToB64 } from "./encoding.js";
import type { DeviceKey } from "./signing.js";

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

export const KNOWN_KINDS: ReadonlySet<ManifestKind> = new Set<ManifestKind>(
  (manifestKnownKinds() as string[]) as ManifestKind[],
);

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
function manifestToCandidateWireDict(m: Manifest, includeSignature: boolean): Record<string, unknown> {
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
  if (includeSignature && m.manifestSignatureB64) {
    out["manifest_signature_b64"] = m.manifestSignatureB64;
  }
  return out;
}

function toWireDict(m: Manifest, includeSignature: boolean): Record<string, unknown> {
  return manifestToWireDict(manifestToCandidateWireDict(m, includeSignature)) as Record<
    string,
    unknown
  >;
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
  let normalized: Record<string, unknown>;
  try {
    normalized = manifestToWireDict(d) as Record<string, unknown>;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(msg, { cause: e });
  }

  const clock: VectorClock = {};
  const rawClock = normalized["clock"];
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
    kind: String(normalized["kind"]),
    version: Math.trunc(Number(normalized["version"])),
    fromDid: String(normalized["publisher_identity"]),
    ceremonyId: String(normalized["ceremony_id"]),
    asOf: String(normalized["as_of"]),
    scope: typeof normalized["scope"] === "string" ? (normalized["scope"] as string) : "admin",
    clock,
    eventCount:
      typeof normalized["event_count"] === "number"
        ? (normalized["event_count"] as number)
        : Number(normalized["event_count"] ?? 0) || 0,
  };
  if (typeof normalized["recipient_identity"] === "string") {
    m.toDid = normalized["recipient_identity"] as string;
  }
  if (typeof normalized["head_row_hash"] === "string") {
    m.headRowHash = normalized["head_row_hash"] as string;
  }
  if (normalized["state"] !== undefined && normalized["state"] !== null) {
    m.state = normalized["state"] as Record<string, unknown>;
  }
  if (typeof normalized["manifest_signature_b64"] === "string") {
    m.manifestSignatureB64 = normalized["manifest_signature_b64"] as string;
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
  return rawManifestSigningBytes(manifestToCandidateWireDict(m, false));
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
  const ok = manifestVerifySignature(toWireDict(m, true));
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
