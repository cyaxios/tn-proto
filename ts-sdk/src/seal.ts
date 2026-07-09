// tn.seal / tn.unseal — portable sealed objects.
//
// A sealed object is a standalone envelope: the same on-wire schema the
// log writes, built and returned instead of appended to the log. `seal`
// routes fields into groups per the yaml and encrypts each group;
// `unseal` verifies the envelope and opens every group block the keys
// at hand can decrypt, walking own-ceremony ciphers first and then
// every kit in the keystore.
//
// Standalone conventions: `sequence` is 0, `prev_hash` is "", and the
// reserved public field `tn_sealed` is 1 (a number, so the row-hash
// preimage's str(value) renders identically across SDK
// implementations). Sealing never touches the ceremony's chain state.
//
// Mirrors python/tn/seal.py (the normative reference) — same
// classification, index-token, aad-bind, and encrypt pipeline as the
// TS emit path (NodeRuntime._emitViaTs), same standalone identity /
// hash / sign steps, and the same self-describing verify on unseal.
// Async-first: jwe seals and opens through panva/jose, which is
// async-only in TS, so both verbs return promises for every cipher.

import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  BtnPublisher,
  buildEnvelope,
  canonicalBytes,
  computeRowHash,
} from "./raw.js";
import { jweSeal } from "./core/jwe.js";
import { deriveGroupKey, indexTokenFor } from "./core/indexing.js";
import { signatureB64 } from "./core/signing.js";
import { hibeEncrypt } from "./runtime/hibe_group.js";
import type { NodeRuntime } from "./runtime/node_runtime.js";

/** Event-type charset gate — same rule as the runtime's emit path
 * (node_runtime's module-local `validateEventType`) so a bad object
 * type fails before any crypto work. */
function _validateObjectType(objectType: string): void {
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

/** Options for {@link sealWithRuntime} / `tn.seal`. */
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

/** Seal one group's plaintext under its declared cipher — the same
 * publisher material the runtime's write pipeline uses
 * (`_sealGroupTs` + the async jwe pre-seal), sourced from the loaded
 * keystore. Throws when this keystore holds no publisher-side
 * material for the group. */
async function _sealGroup(
  rt: NodeRuntime,
  gname: string,
  cipher: string,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (cipher === "hibe") {
    const mat = rt.keystore.groups.get(gname)?.hibe;
    if (!mat) {
      throw new Error("HIBE: no authority mpk / identity path in this keystore");
    }
    return hibeEncrypt(mat, plaintext, aad);
  }
  if (cipher === "btn") {
    const stateBytes = rt.keystore.groups.get(gname)?.stateBytes;
    if (!stateBytes) {
      throw new Error("btn: no state file in this keystore");
    }
    // Publisher state is static between rotations, so restoring from the
    // loaded bytes per seal is side-effect-free (encrypt mints a fresh
    // body key; it never advances persisted state).
    return BtnPublisher.fromBytes(stateBytes).encrypt(plaintext);
  }
  if (cipher === "jwe") {
    const path = join(rt.config.keystorePath, `${gname}.jwe.recipients`);
    if (!existsSync(path)) {
      throw new Error(`jwe: no recipients file for group ${JSON.stringify(gname)} at ${path}`);
    }
    const doc = JSON.parse(readFileSync(path, "utf8")) as { pub_b64: string }[];
    const pubs = doc.map((e) => new Uint8Array(Buffer.from(e.pub_b64, "base64")));
    return jweSeal(pubs, plaintext, aad.length > 0 ? aad : undefined);
  }
  throw new Error(`cipher ${JSON.stringify(cipher)} has no TS publisher path`);
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
export async function sealWithRuntime(
  rt: NodeRuntime,
  objectType: string,
  fields: Record<string, unknown> = {},
  opts: SealOptions = {},
): Promise<SealedObject> {
  _validateObjectType(objectType);
  if ("tn_sealed" in fields) {
    throw new Error("tn_sealed is a reserved sealed-object marker; rename the field");
  }
  const cfg = rt.config;

  // -- classify public vs group buckets (mirrors _emitViaTs step 1,
  //    minus the context merge / run_id injection) --
  const publicOut: Record<string, unknown> = {};
  const perGroup = new Map<string, Record<string, unknown>>();
  for (const [k, v] of Object.entries(fields)) {
    if (cfg.publicFields.has(k)) {
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
    let gnames = cfg.fieldToGroups.get(k);
    if (!gnames || gnames.length === 0) {
      if (cfg.groups.has("default")) {
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
      if (!cfg.groups.has(gname)) {
        throw new Error(
          `field ${JSON.stringify(k)} routed to unknown group ${JSON.stringify(gname)} ` +
            `(known groups: ${JSON.stringify([...cfg.groups.keys()].sort())})`,
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
    const gcfg = cfg.groups.get(gname)!;
    // Sort up front so a sealed envelope's field_hashes ordering is
    // deterministic across builds; the row_hash is unaffected either way
    // because canonicalBytes sorts keys internally.
    const plainFields = Object.fromEntries(
      Object.entries(bucket).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
    const indexKey = deriveGroupKey(
      rt.keystore.indexMaster,
      cfg.ceremonyId,
      gname,
      gcfg.indexEpoch,
    );
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
    let ct: Uint8Array;
    try {
      ct = await _sealGroup(rt, gname, gcfg.cipher, plaintextBytes, aadBytes);
    } catch (e) {
      // Not a publisher for this group — skip it, exactly like the
      // write path's NotAPublisherError branch (warn, drop the group,
      // keep the seal).
      process.emitWarning(
        `tn-proto: skipping group ${JSON.stringify(gname)} for ${objectType}: ` +
          `${e instanceof Error ? e.message : String(e)}`,
      );
      continue;
    }
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
  const eventId = randomUUID();

  const groupsForHash: Record<string, { ciphertext_b64: string; field_hashes: Record<string, string> }> = {};
  const groupPayloadsWire: Record<string, { ciphertext: string; field_hashes: Record<string, string> }> = {};
  for (const [gname, g] of groupPayloads) {
    const b64 = Buffer.from(g.ct).toString("base64");
    groupsForHash[gname] = { ciphertext_b64: b64, field_hashes: g.fieldHashes };
    groupPayloadsWire[gname] = { ciphertext: b64, field_hashes: g.fieldHashes };
  }
  // Flat computeRowHash call (not core/chain.ts rowHash): the standalone
  // prev_hash is "", which the branded asRowHash guard rejects by design.
  const rowHash = computeRowHash({
    device_identity: cfg.device.device_identity,
    timestamp,
    event_id: eventId,
    event_type: objectType,
    level: "",
    prev_hash: "",
    public_fields: publicOut,
    groups: groupsForHash,
  });
  const sig = rt.keystore.device.sign(new Uint8Array(Buffer.from(rowHash, "ascii")));

  // buildEnvelope renders the log's ndjson line (trailing newline); the
  // sealed wire artifact carries none.
  let wire = buildEnvelope({
    device_identity: cfg.device.device_identity,
    timestamp,
    event_id: eventId,
    event_type: objectType,
    level: "",
    sequence: 0,
    prev_hash: "",
    row_hash: rowHash,
    signature_b64: String(signatureB64(sig)),
    public_fields: publicOut,
    group_payloads: groupPayloadsWire,
  });
  if (wire.endsWith("\n")) wire = wire.slice(0, -1);

  if (opts.receipt ?? true) {
    // Chain one ordinary log row attesting the seal act. Routed through
    // the runtime's async write path (jwe groups seal asynchronously in
    // TS); errors PROPAGATE — the caller asked for a receipt, so a
    // silently missing one would break the guarantee.
    await rt.emitAsync("info", "tn.object.sealed", {
      object_id: rowHash,
      object_type: objectType,
      groups: [...groupPayloads.keys()].sort(),
    });
  }

  return new SealedObject(wire);
}
