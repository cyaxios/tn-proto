// Runtime-agnostic core of tn.seal / tn.unseal — portable sealed objects.
//
// Everything here is browser-safe: no node:* imports, no Buffer, no
// filesystem. The Node entry (src/seal.ts) and the browser entry
// (src/browser/seal.ts) each build a small context around this core —
// Node sources group material from the keystore directory on disk, the
// browser from its storage adapter — and both produce byte-identical
// wire artifacts (python/tn/seal.py stays the normative reference).
//
// Standalone conventions: `sequence` is 0, `prev_hash` is "", and the
// reserved public field `tn_sealed` is 1 (a number, so the row-hash
// preimage's str(value) renders identically across SDK
// implementations). Sealing never touches a ceremony's chain state.

import { buildEnvelope, canonicalBytes, computeRowHash } from "../raw.js";
import { aadBytesFor, decryptGroupAsync, type GroupKits } from "./decrypt.js";
import { deriveGroupKey, indexTokenFor } from "./indexing.js";
import { signatureFromB64, verify as verifySignature } from "./signing.js";
import { asDid } from "./types.js";
import { Entry, VerifyError } from "../Entry.js";

// The nine mandatory envelope scalars. Everything else in a sealed
// object is either a public field or a group block. Mirrors
// python/tn/seal.py's `_ENVELOPE_RESERVED`.
const _ENVELOPE_RESERVED = new Set([
  "device_identity",
  "timestamp",
  "event_id",
  "event_type",
  "level",
  "sequence",
  "prev_hash",
  "row_hash",
  "signature",
]);

// -- browser-and-node byte helpers (no Buffer) ------------------------------

function b64encode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Lax base64 decode matching Node's `Buffer.from(s, "base64")`:
 * non-alphabet characters are dropped and truncated tails tolerated, so
 * hand-tampered wire input degrades to garbage bytes (and a failed
 * row-hash check) instead of a decode throw. */
function b64decode(value: string): Uint8Array {
  const clean = value.replace(/[^A-Za-z0-9+/=]/g, "").replace(/=+$/, "");
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  let bin: string;
  try {
    bin = atob(padded);
  } catch {
    return new Uint8Array(0);
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Row hashes are hex ASCII, so UTF-8 encoding is byte-identical to the
 * Node side's `Buffer.from(s, "ascii")`. */
function asciiBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Event-type charset gate — same rule as the runtime's emit path
 * (node_runtime's module-local `validateEventType`) so a bad object
 * type fails before any crypto work. */
export function validateObjectType(objectType: string): void {
  if (!objectType) throw new Error("event_type must be non-empty");
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(objectType)) {
    throw new Error(`invalid event_type: ${objectType}`);
  }
}

/**
 * Signed standalone envelope returned by `tn.seal`.
 *
 * The source of truth is {@link SealedObject.rawJson} — the verbatim
 * wire string (compact envelope JSON, no trailing newline; the same
 * line format the log writes minus the newline). `toString()` returns
 * it, so the object can be written to a file, posted over HTTP, or
 * interpolated into a prompt without a serialization step. Transport
 * the wire string verbatim: a foreign JSON runtime that re-parses and
 * re-serializes it is exactly the round-trip the fragile-public guard
 * exists to protect against.
 */
export class SealedObject {
  /** The compact envelope JSON exactly as sealed (no trailing newline). */
  readonly rawJson: string;
  private _envelope: Record<string, unknown> | null = null;

  constructor(rawJson: string) {
    this.rawJson = rawJson;
  }

  /** The envelope as a parsed object (lazy; cached). A derived view —
   * `rawJson` stays the transport artifact. */
  get envelope(): Record<string, unknown> {
    if (this._envelope === null) {
      this._envelope = JSON.parse(this.rawJson) as Record<string, unknown>;
    }
    return this._envelope;
  }

  /** The object's `row_hash` — its content-derived identifier. */
  get rowHash(): string {
    return String(this.envelope["row_hash"] ?? "");
  }

  /** The object type this was sealed as (the envelope's `event_type`). */
  get eventType(): string {
    return String(this.envelope["event_type"] ?? "");
  }

  /** The sealing device's DID (the envelope's `device_identity`). */
  get deviceIdentity(): string {
    return String(this.envelope["device_identity"] ?? "");
  }

  /** The verbatim wire string (see {@link SealedObject.rawJson}). */
  toString(): string {
    return this.rawJson;
  }

  /** `JSON.stringify(sealed)` renders the envelope object. Convenience
   * only — for transport use `rawJson`, which is byte-verbatim. */
  toJSON(): Record<string, unknown> {
    return this.envelope;
  }
}

/**
 * Thrown when unseal input is not a sealed-object envelope at all.
 *
 * This is the TS equivalent of Python's `tn.UnsealError` under a
 * non-colliding name: `UnsealError` is already exported from
 * `core/recipient_seal.ts` for a different failure (a sealed-box BEK
 * that no recipient wrap opens). Having no key that fits is NOT this
 * error — that returns the public frame with the blocks left sealed.
 */
export class SealedObjectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SealedObjectError";
  }
}

/** Options for `tn.seal` (both entries). */
export interface SealOptions {
  /** Chain a `tn.object.sealed` receipt row through the runtime's
   * normal write path (default `true`). Receipt failures propagate —
   * the caller asked for a receipt, so a silently missing one would
   * break the guarantee. */
  receipt?: boolean;
  /** Additional-authenticated-data bound (authenticated, not
   * encrypted) to every group sealed on this object, merged OVER any
   * yaml per-group `aad` default and echoed into the public `tn_aad`
   * field. Omit (or empty) to bind nothing. */
  aad?: Record<string, unknown>;
}

/** The verify/raw half of the unseal options — shared by both entries.
 * Each entry adds its own `asRecipient` shape on top (a keystore
 * directory path on Node; a storage adapter or {filename -> bytes} bag
 * in the browser). */
export interface UnsealCoreOptions {
  /** Verify signature + row hash before decrypting (default `true`).
   * A failed check throws {@link VerifyError}; with `verify: false`
   * both `valid` flags report `false` and the walk proceeds. */
  verify?: boolean | undefined;
  /** Return the raw `{envelope, plaintext, valid}` triple instead of
   * an {@link Entry}. */
  raw?: boolean | undefined;
}

/** The raw `{envelope, plaintext, valid}` triple `unseal({raw: true})`
 * returns. Wire-faithful: the envelope keeps the `tn_sealed` marker.
 * Key names mirror Python's triple (`valid.row_hash`, snake_case). */
export interface SealedTriple {
  envelope: Record<string, unknown>;
  plaintext: Record<string, Record<string, unknown>>;
  valid: { signature: boolean; row_hash: boolean };
}

/** Any source shape `unseal` accepts. */
export type UnsealSource = SealedObject | string | Record<string, unknown>;

// ---------------------------------------------------------------------------
// seal
// ---------------------------------------------------------------------------

/**
 * Reject public field values that cannot survive a foreign JSON
 * round-trip. Mirrors `seal.py::_reject_fragile_public`.
 *
 * A sealed object is verified by re-hashing its PUBLIC fields as
 * `str(value)` (encrypted group fields are hashed as opaque
 * ciphertext, so they are safe for any value). A JSON runtime that
 * parses the object into native values and re-serializes it — a
 * browser, PowerShell/.NET, most LLM tool boundaries — reformats some
 * numbers: an integer past 2**53 loses precision and a non-integral
 * float has no canonical cross-runtime rendering. Either flips the
 * recomputed row hash far from the seal call, so we refuse those
 * values here, loudly and locally.
 *
 * One asymmetry vs Python is inherent to JS: `1.0` and `-0.0` collapse
 * to the integer `1` / `0` at the language level (there is no separate
 * float type), so where Python rejects an integral float, TS seals the
 * integer it already became — which is the safe wire form. Booleans
 * are exempt (they round-trip cleanly); arrays and objects are checked
 * recursively; error messages name the offending path (`pv[0]`,
 * `pv.amt`).
 */
function _rejectFragilePublic(publicOut: Record<string, unknown>): void {
  const check = (value: unknown, path: string): void => {
    if (typeof value === "boolean") return;
    if (typeof value === "number") {
      if (!Number.isInteger(value)) {
        throw new Error(
          `public field ${JSON.stringify(path)} is a float (${value}); floats do not ` +
            `have a canonical form across JSON runtimes (an integral float ` +
            `like 1.0 collapses to 1 when a browser or .NET reserializes ` +
            `the object), which would break row-hash verification. Put it ` +
            `in an encrypted group (any type is safe there), or pass it as ` +
            `a string.`,
        );
      }
      if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
        throw new Error(
          `public field ${JSON.stringify(path)} is an integer beyond +/-(2**53-1) ` +
            `(${value}); a JSON runtime that parses it into a float64 ` +
            `loses precision, which would break row-hash verification. ` +
            `Put it in an encrypted group (any type is safe there), or ` +
            `pass it as a string.`,
        );
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, i) => check(item, `${path}[${i}]`));
      return;
    }
    if (value !== null && typeof value === "object") {
      for (const [k, v] of Object.entries(value)) check(v, `${path}.${k}`);
    }
  };
  for (const [k, v] of Object.entries(publicOut)) check(v, k);
}

/** The slice of a group's config the seal pipeline needs. */
export interface SealGroupView {
  cipher: string;
  indexEpoch: number;
  aadDefault: Record<string, unknown>;
}

/**
 * Everything `sealObjectCore` needs from a ceremony, with the
 * runtime-specific parts (key material access and receipt write)
 * supplied as callbacks by the entry adapter.
 */
export interface SealContext {
  ceremonyId: string;
  deviceIdentity: string;
  publicFields: Set<string>;
  fieldToGroups: Map<string, string[]>;
  groups: Map<string, SealGroupView>;
  /** 32-byte index-master HMAC key (`index_master.key`). */
  indexMaster: Uint8Array;
  /** Sign `bytes` with the device key; return the signature base64. */
  signB64: (bytes: Uint8Array) => string;
  /** Seal one group's plaintext under its declared cipher. Throws when
   * this keystore holds no publisher-side material for the group. */
  sealGroup: (
    gname: string,
    cipher: string,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ) => Promise<Uint8Array>;
  /** Chain the `tn.object.sealed` receipt row through the runtime's
   * normal write path. Errors propagate to the seal caller. */
  emitReceipt: (fields: Record<string, unknown>) => void | Promise<void>;
}

/**
 * Seal `fields` into a portable attested object (standalone envelope).
 *
 * Same classification / index-token / aad-bind / encrypt pipeline as
 * the runtime's write path, then the standalone identity: `sequence`
 * 0, `prev_hash` "", `level` "", the reserved public marker
 * `tn_sealed: 1`, always signed. The ceremony's chain state is never
 * touched. Mirrors `python/tn/seal.py::seal`.
 */
export async function sealObjectCore(
  ctx: SealContext,
  objectType: string,
  fields: Record<string, unknown> = {},
  opts: SealOptions = {},
): Promise<SealedObject> {
  validateObjectType(objectType);
  if ("tn_sealed" in fields) {
    throw new Error("tn_sealed is a reserved sealed-object marker; rename the field");
  }

  // -- classify public vs group buckets (mirrors _emitViaTs step 1,
  //    minus the context merge / run_id injection) --
  const publicOut: Record<string, unknown> = {};
  const perGroup = new Map<string, Record<string, unknown>>();
  for (const [k, v] of Object.entries(fields)) {
    if (ctx.publicFields.has(k)) {
      if (v !== null && typeof v === "object" && !Array.isArray(v) && "ciphertext" in v) {
        // The wire is self-describing: unseal treats any object value
        // carrying a "ciphertext" key as an encrypted group block, so a
        // public field shaped like that could never round-trip.
        throw new Error(
          `public field ${JSON.stringify(k)} is a dict containing a 'ciphertext' ` +
            `key; unseal would misread it as an encrypted group block. ` +
            `Rename the inner key or route the field into a group.`,
        );
      }
      publicOut[k] = v;
      continue;
    }
    let gnames = ctx.fieldToGroups.get(k);
    if (!gnames || gnames.length === 0) {
      if (ctx.groups.has("default")) {
        gnames = ["default"];
      } else {
        throw new Error(
          `field ${JSON.stringify(k)} has no group route and is not in ` +
            `public_fields. Add it to \`groups[<g>].fields\` in tn.yaml, list ` +
            `it under public_fields, or define a \`default\` group to absorb unknowns.`,
        );
      }
    }
    for (const gname of gnames) {
      if (!ctx.groups.has(gname)) {
        throw new Error(
          `field ${JSON.stringify(k)} routed to unknown group ${JSON.stringify(gname)} ` +
            `(known groups: ${JSON.stringify([...ctx.groups.keys()].sort())})`,
        );
      }
      const bucket = perGroup.get(gname) ?? {};
      bucket[k] = v;
      perGroup.set(gname, bucket);
    }
  }

  // -- index tokens + aad + encrypt (the write path's token, aad-bind,
  //    and encrypt steps) --
  const aadEcho: Record<string, Record<string, unknown>> = {};
  const groupPayloads = new Map<string, { ct: Uint8Array; fieldHashes: Record<string, string> }>();
  for (const [gname, bucket] of perGroup) {
    const gcfg = ctx.groups.get(gname)!;
    // Sort up front so a sealed envelope's field_hashes ordering is
    // deterministic across builds; the row_hash is unaffected either way
    // because canonicalBytes sorts keys internally.
    const plainFields = Object.fromEntries(
      Object.entries(bucket).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
    const indexKey = deriveGroupKey(ctx.indexMaster, ctx.ceremonyId, gname, gcfg.indexEpoch);
    const fieldHashes: Record<string, string> = {};
    for (const [fname, fval] of Object.entries(plainFields)) {
      fieldHashes[fname] = indexTokenFor(indexKey, fname, fval);
    }
    const effectiveAad: Record<string, unknown> = {
      ...(gcfg.aadDefault ?? {}),
      ...(opts.aad ?? {}),
    };
    const hasAad = Object.keys(effectiveAad).length > 0;
    if (hasAad && gcfg.cipher === "btn") {
      // Same loud failure as the runtime's write path: the wasm
      // BtnPublisher.encrypt has no aad parameter, so binding would
      // silently drop the marker.
      throw new Error(
        "per-emit aad is not yet wired through the native (btn) runtime; " +
          "use a hibe/jwe ceremony, a group-level aad in config is likewise " +
          "native-limited, or bind at the group-cipher level.",
      );
    }
    const aadBytes = hasAad ? canonicalBytes(effectiveAad) : new Uint8Array(0);
    const plaintextBytes = canonicalBytes(plainFields);
    const ct = await ctx.sealGroup(gname, gcfg.cipher, plaintextBytes, aadBytes);
    groupPayloads.set(gname, { ct, fieldHashes });
    if (hasAad) aadEcho[gname] = effectiveAad;
  }

  // Authenticated aad echo: the canonical JSON STRING of the
  // {group: dict} map, so it hashes identically in every row_hash
  // implementation (str(s) == s). Absent when no group bound aad.
  if (Object.keys(aadEcho).length > 0) {
    publicOut["tn_aad"] = new TextDecoder().decode(canonicalBytes(aadEcho));
  }
  // Detachment marker — a number so str(value) in the row-hash
  // preimage renders identically in every SDK implementation.
  publicOut["tn_sealed"] = 1;

  // A sealed object is meant to travel through arbitrary intermediaries
  // (LLM tool boundaries, browsers), which reserialize JSON. Refuse
  // public values such a round-trip would silently mutate, so the
  // failure lands here at seal time instead of at a remote unseal.
  _rejectFragilePublic(publicOut);

  // -- standalone identity + hash + sign (mirrors the write path's
  //    hash/sign steps, with sequence=0 / prev_hash="" and NO chain
  //    advance) --
  const timestamp = new Date().toISOString().replace(/\.(\d{3})Z$/, ".$1000Z");
  const eventId = crypto.randomUUID();

  const groupsForHash: Record<string, { ciphertext_b64: string; field_hashes: Record<string, string> }> = {};
  const groupPayloadsWire: Record<string, { ciphertext: string; field_hashes: Record<string, string> }> = {};
  for (const [gname, g] of groupPayloads) {
    const b64 = b64encode(g.ct);
    groupsForHash[gname] = { ciphertext_b64: b64, field_hashes: g.fieldHashes };
    groupPayloadsWire[gname] = { ciphertext: b64, field_hashes: g.fieldHashes };
  }
  // Flat computeRowHash call (not core/chain.ts rowHash): the standalone
  // prev_hash is "", which the branded asRowHash guard rejects by design.
  const rowHash = computeRowHash({
    device_identity: ctx.deviceIdentity,
    timestamp,
    event_id: eventId,
    event_type: objectType,
    level: "",
    prev_hash: "",
    public_fields: publicOut,
    groups: groupsForHash,
  });
  const sigB64 = ctx.signB64(asciiBytes(rowHash));

  // buildEnvelope renders the log's ndjson line (trailing newline); the
  // sealed wire artifact carries none.
  let wire = buildEnvelope({
    device_identity: ctx.deviceIdentity,
    timestamp,
    event_id: eventId,
    event_type: objectType,
    level: "",
    sequence: 0,
    prev_hash: "",
    row_hash: rowHash,
    signature_b64: sigB64,
    public_fields: publicOut,
    group_payloads: groupPayloadsWire,
  });
  if (wire.endsWith("\n")) wire = wire.slice(0, -1);

  if (opts.receipt ?? true) {
    // Chain one ordinary log row attesting the seal act. Routed through
    // the runtime's normal write path; errors PROPAGATE — the caller
    // asked for a receipt, so a silently missing one would break the
    // guarantee.
    await ctx.emitReceipt({
      object_id: rowHash,
      object_type: objectType,
      groups: [...groupPayloads.keys()].sort(),
    });
  }

  return new SealedObject(wire);
}

// ---------------------------------------------------------------------------
// unseal
// ---------------------------------------------------------------------------

interface _GroupBlock {
  ciphertext: Uint8Array;
  fieldHashes: Record<string, string>;
}

/** Any accepted source shape -> one envelope object, or SealedObjectError. */
function _normalizeSource(source: UnsealSource): Record<string, unknown> {
  if (source instanceof SealedObject) {
    // The wire string is the source of truth — parse it fresh so the
    // result is wire-faithful and isolated from the cached view.
    return _parseEnvelopeText(source.rawJson);
  }
  if (typeof source === "string") {
    return _parseEnvelopeText(source);
  }
  if (source !== null && typeof source === "object" && !Array.isArray(source)) {
    return _requireEnvelopeShape({ ...source });
  }
  throw new SealedObjectError(
    `unsupported sealed object source type: ${source === null ? "null" : typeof source}`,
  );
}

function _parseEnvelopeText(text: string): Record<string, unknown> {
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    throw new SealedObjectError(
      `not a sealed object: invalid JSON (${e instanceof Error ? e.message : String(e)})`,
    );
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new SealedObjectError("not a sealed object: JSON is not an object");
  }
  return _requireEnvelopeShape(obj as Record<string, unknown>);
}

function _requireEnvelopeShape(env: Record<string, unknown>): Record<string, unknown> {
  // seal always writes all nine envelope scalars; require the ones the
  // rest of unseal dereferences unconditionally (Entry.fromRaw needs
  // timestamp/event_id/sequence even with verify=false) so malformed
  // input surfaces as SealedObjectError, never a bare lookup crash.
  const required = [
    "device_identity",
    "event_type",
    "row_hash",
    "signature",
    "timestamp",
    "event_id",
    "sequence",
  ];
  const missing = required.filter((k) => !(k in env));
  if (missing.length > 0) {
    throw new SealedObjectError(`not a sealed object: missing ${missing.join(", ")}`);
  }
  return env;
}

/** Lift every encrypted group block out of the envelope. The wire is
 * self-describing: any object value carrying a "ciphertext" key is a
 * group block. */
function _extractGroupBlocks(env: Record<string, unknown>): Map<string, _GroupBlock> {
  const blocks = new Map<string, _GroupBlock>();
  for (const [k, v] of Object.entries(env)) {
    if (v === null || typeof v !== "object" || Array.isArray(v)) continue;
    const obj = v as Record<string, unknown>;
    if (!("ciphertext" in obj)) continue;
    const ctB64 = obj["ciphertext"];
    if (typeof ctB64 !== "string") {
      throw new SealedObjectError(`group block ${JSON.stringify(k)} has undecodable ciphertext`);
    }
    const ciphertext = b64decode(ctB64);
    const fieldHashes =
      obj["field_hashes"] !== null &&
      typeof obj["field_hashes"] === "object" &&
      !Array.isArray(obj["field_hashes"])
        ? (obj["field_hashes"] as Record<string, string>)
        : {};
    blocks.set(k, { ciphertext, fieldHashes });
  }
  return blocks;
}

/** Envelope scalar as a string for the row-hash recompute; a non-string
 * (only possible on hand-tampered input) hashes as "" and simply fails
 * the check, keeping garbage on the VerifyError path. */
function _strOf(env: Record<string, unknown>, key: string): string {
  const v = env[key];
  return typeof v === "string" ? v : "";
}

/** Self-describing verify: recompute the row hash over every
 * non-reserved, non-group-block key as a public field (the log reader
 * filters through the local yaml's public_fields, which would make
 * foreign sealed objects unverifiable), then check the signature over
 * the row_hash bytes. */
function _verifySealed(
  env: Record<string, unknown>,
  blocks: Map<string, _GroupBlock>,
): { signature: boolean; row_hash: boolean } {
  const publicOut: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(env)) {
    if (_ENVELOPE_RESERVED.has(k) || blocks.has(k)) continue;
    publicOut[k] = v;
  }
  const groups: Record<string, { ciphertext_b64: string; field_hashes: Record<string, string> }> = {};
  for (const [gname, b] of blocks) {
    groups[gname] = {
      // Decode -> re-encode normalizes the wire base64 into the canonical
      // form the preimage commits to (same effect as Python hashing the
      // decoded bytes).
      ciphertext_b64: b64encode(b.ciphertext),
      field_hashes: b.fieldHashes,
    };
  }
  let rowHashOk = false;
  try {
    const expected = computeRowHash({
      device_identity: _strOf(env, "device_identity"),
      timestamp: _strOf(env, "timestamp"),
      event_id: _strOf(env, "event_id"),
      event_type: _strOf(env, "event_type"),
      level: _strOf(env, "level"),
      prev_hash: _strOf(env, "prev_hash"),
      public_fields: publicOut,
      groups,
    });
    rowHashOk = expected === env["row_hash"];
  } catch {
    /* an unhashable value means unverified — the flag stays false */
  }
  let signatureOk = false;
  try {
    signatureOk = verifySignature(
      asDid(_strOf(env, "device_identity")),
      asciiBytes(_strOf(env, "row_hash")),
      signatureFromB64(_strOf(env, "signature")),
    );
  } catch {
    /* any failure shape means unverified — the flag stays false */
  }
  // Insertion order matters downstream: failed_checks lists "signature"
  // before "row_hash" (Python's valid-dict insertion order).
  return { signature: signatureOk, row_hash: rowHashOk };
}

/** One group's decrypt-kit candidates: the ceremony's own declared
 * cipher for the group (pass 1 of the walk), plus every candidate the
 * key bag holds (pass 2). */
export interface UnsealKitCandidates {
  /** The group's cipher per the active ceremony's config, when the
   * ceremony declares the group at all. */
  ownCipher?: string | undefined;
  /** Every candidate kit set the keystore holds for the group, in the
   * fixed btn -> jwe -> hibe order. */
  candidates: GroupKits[];
}

/** Where unseal's decrypt walk sources keys from. Node backs this with
 * the keystore directory; the browser with its storage adapter or a
 * caller-supplied {filename -> bytes} bag. */
export interface UnsealKitSource {
  forGroup(group: string): UnsealKitCandidates;
}

/** Try every candidate key per group; first fit wins, failures skip.
 *
 * Both walks hold multi-cipher candidates: the asRecipient path loads
 * every cipher for the named group, and the default keystore walk maps
 * each group to a candidate list (btn, jwe, hibe) — so an absorbed
 * grant under a different cipher than the reader's own ceremony still
 * opens. Only successful opens land in the result; a group nothing
 * fits is simply absent (it surfaces as hidden, never an error). */
async function _decryptWalk(
  own: UnsealKitSource | null,
  asRecipient: UnsealKitSource | null,
  env: Record<string, unknown>,
  blocks: Map<string, _GroupBlock>,
  group: string,
): Promise<Record<string, Record<string, unknown>>> {
  const plaintext: Record<string, Record<string, unknown>> = {};

  const tryOpen = async (gname: string, kits: GroupKits): Promise<boolean> => {
    const block = blocks.get(gname)!;
    const result = await decryptGroupAsync(
      { ct: block.ciphertext, aad: aadBytesFor(env, gname) },
      kits,
    );
    if (
      "$no_read_key" in result ||
      "$decrypt_error" in result ||
      "$unsupported_cipher" in result
    ) {
      return false;
    }
    plaintext[gname] = result as Record<string, unknown>;
    return true;
  };

  if (asRecipient !== null) {
    // Single-kit override: load every cipher candidate for `group` from
    // the supplied bag and decrypt only `group`. Nothing to open means
    // nothing to load — return before touching the bag.
    if (!blocks.has(group)) return plaintext;
    for (const kits of asRecipient.forGroup(group).candidates) {
      if (await tryOpen(group, kits)) break;
    }
    return plaintext;
  }

  if (own === null) return plaintext;

  // Pass 1: own-ceremony group ciphers (publisher side) — the
  // config-declared cipher's candidate for each declared group.
  for (const gname of blocks.keys()) {
    const { ownCipher, candidates } = own.forGroup(gname);
    if (ownCipher === undefined) continue;
    const match = candidates.find((c) => c.cipher === ownCipher);
    if (match) await tryOpen(gname, match);
  }
  // Pass 2: keystore key-bag (own kits + everything absorbed).
  for (const gname of blocks.keys()) {
    // Own-property check, not `in`: a group named like an Object.prototype
    // member ("constructor", "toString") must not read as already open.
    if (Object.prototype.hasOwnProperty.call(plaintext, gname)) continue;
    for (const kits of own.forGroup(gname).candidates) {
      if (await tryOpen(gname, kits)) break;
    }
  }
  return plaintext;
}

/**
 * Verify a sealed object and open every group block a held key fits.
 *
 * No key fitting is not an error: you get the verified public frame
 * with the blocks left sealed (listed in `Entry.hidden_groups`).
 * {@link SealedObjectError} is malformed input only; {@link VerifyError}
 * is failed verification with `verify: true` (`failed_checks` drawn
 * from `"signature"` / `"row_hash"`). Mirrors `python/tn/seal.py::unseal`.
 *
 * `own` may be `null` (no active ceremony): verification still runs
 * and the `asRecipient` source still opens its group; the default
 * keystore walk is skipped.
 */
export async function unsealObjectCore(
  own: UnsealKitSource | null,
  asRecipient: UnsealKitSource | null,
  group: string,
  source: UnsealSource,
  opts: UnsealCoreOptions = {},
): Promise<Entry | SealedTriple> {
  const env = _normalizeSource(source);
  const blocks = _extractGroupBlocks(env);

  let valid: { signature: boolean; row_hash: boolean } = { signature: false, row_hash: false };
  if (opts.verify ?? true) {
    valid = _verifySealed(env, blocks);
    const failed = Object.entries(valid)
      .filter(([, ok]) => !ok)
      .map(([k]) => k);
    if (failed.length > 0) {
      const seqRaw = Number(env["sequence"]);
      throw new VerifyError(
        Number.isFinite(seqRaw) ? seqRaw : 0,
        _strOf(env, "event_type"),
        failed,
      );
    }
  }

  const plaintext = await _decryptWalk(own, asRecipient, env, blocks, group);

  const triple: SealedTriple = { envelope: env, plaintext, valid };
  if (opts.raw ?? false) {
    return triple;
  }
  // Entry.fromRaw copies non-reserved public extras into Entry.fields,
  // which would leak the tn_sealed marker into user fields — and make
  // tn.seal(entry.fields) trip the reserved-name guard. Drop it from
  // the Entry-bound copy only; the raw triple above stays wire-faithful.
  const entryEnv: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(env)) {
    if (k === "tn_sealed") continue;
    entryEnv[k] = v;
  }
  return Entry.fromRaw({ envelope: entryEnv, plaintext, valid });
}
