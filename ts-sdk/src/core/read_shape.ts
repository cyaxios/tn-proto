// Layer 1 — pure read-shape projection.
//
// Projects a raw `{envelope, plaintext, valid}` ReadEntry into the flat dict
// shape that `tn.read()` / `tn.secureRead()` return to callers.
//
// All logic here is pure: no fs, no network, no global state.
// ESLint enforces that this file does NOT import from `node:*`.

import type { ReadEntry } from "./types.js";
export type { ReadEntry } from "./types.js";

/** Public envelope keys that always surface flat in the new shape (§1.1). */
export const FLAT_ENVELOPE_KEYS: readonly string[] = [
  "timestamp",
  "event_type",
  "level",
  "did",
  "sequence",
  "event_id",
];

/** Crypto-plumbing envelope keys that NEVER surface flat (only via raw=true). */
export const CRYPTO_ENVELOPE_KEYS: ReadonlySet<string> = new Set([
  "prev_hash",
  "row_hash",
  "signature",
]);

export const RESERVED_ENVELOPE_KEYS: ReadonlySet<string> = new Set([
  ...FLAT_ENVELOPE_KEYS,
  ...CRYPTO_ENVELOPE_KEYS,
]);

export function isGroupPayloadValue(v: unknown): boolean {
  return (
    typeof v === "object" &&
    v !== null &&
    !Array.isArray(v) &&
    "ciphertext" in (v as Record<string, unknown>)
  );
}

/** Project a raw `{envelope, plaintext, valid}` entry to the flat shape.
 *
 * Mirror of Python `tn.reader.flatten_raw_entry`. Snake-case throughout
 * (envelope basics + metadata) so the on-wire shape matches Python
 * byte-for-byte.
 */
export function flattenRawEntry(
  raw: ReadEntry,
  opts: { includeValid: boolean },
): Record<string, unknown> {
  const env = raw.envelope;
  const plaintext = raw.plaintext;
  const out: Record<string, unknown> = {};

  // 1. Envelope basics.
  for (const k of FLAT_ENVELOPE_KEYS) {
    if (k in env) out[k] = env[k];
  }

  // 2. Public fields beyond envelope basics: anything in env that isn't
  //    an envelope basic, isn't crypto plumbing, and isn't a group payload.
  for (const [k, v] of Object.entries(env)) {
    if (RESERVED_ENVELOPE_KEYS.has(k)) continue;
    if (isGroupPayloadValue(v)) continue;
    out[k] = v;
  }

  // 3. Decrypted group fields, merged in alphabetical group order so
  //    last-write-wins on collision is deterministic across runs.
  const decryptErrors: string[] = [];
  const groupNames = Object.keys(plaintext).sort();
  for (const gname of groupNames) {
    const body = plaintext[gname];
    if (!body || typeof body !== "object" || Array.isArray(body)) continue;
    if ((body as Record<string, unknown>)["$decrypt_error"] === true) {
      decryptErrors.push(gname);
      continue;
    }
    if ((body as Record<string, unknown>)["$no_read_key"] === true) {
      continue;
    }
    for (const [fk, fv] of Object.entries(body)) {
      out[fk] = fv;
    }
  }

  // 4. _hidden_groups: groups with ciphertext in env that we couldn't
  //    decrypt (plaintext absent, or marked $no_read_key).
  const hidden: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    if (RESERVED_ENVELOPE_KEYS.has(k)) continue;
    if (!isGroupPayloadValue(v)) continue;
    const body = plaintext[k];
    if (
      body === undefined ||
      (typeof body === "object" &&
        body !== null &&
        (body as Record<string, unknown>)["$no_read_key"] === true)
    ) {
      hidden.push(k);
    }
  }
  if (hidden.length > 0) {
    out["_hidden_groups"] = [...hidden].sort();
  }

  // 5. _decrypt_errors.
  if (decryptErrors.length > 0) {
    out["_decrypt_errors"] = [...decryptErrors].sort();
  }

  // 6. _valid block (verify=true path).
  if (opts.includeValid) {
    const v = raw.valid;
    out["_valid"] = {
      signature: Boolean(v.signature),
      row_hash: Boolean(v.rowHash),
      chain: Boolean(v.chain),
    };
  }

  return out;
}

/** Map the `valid` block to the public `invalid_reasons` shape. */
export function invalidReasonsFromValid(valid: ReadEntry["valid"]): string[] {
  const out: string[] = [];
  if (!valid.signature) out.push("signature");
  if (!valid.rowHash) out.push("row_hash");
  if (!valid.chain) out.push("chain");
  return out;
}

/** Public types for `secureRead`. */
export interface Instructions {
  instruction: string;
  use_for: string;
  do_not_use_for: string;
  consequences: string;
  on_violation_or_error: string;
  policy: string;
}

export interface SecureEntry extends Record<string, unknown> {
  _hidden_groups?: string[];
  _decrypt_errors?: string[];
  instructions?: Instructions;
  /** Forensic mode only: per-check booleans. */
  _valid?: { signature: boolean; row_hash: boolean; chain: boolean };
  /** Forensic mode only: list of failed checks. */
  _invalid_reasons?: string[];
}

/**
 * If the raw entry's plaintext carries a `tn.agents` block AND the caller
 * holds the kit (decrypt succeeded), surface those six fields as a
 * dedicated `instructions` block per spec §3.1. Removes the same six
 * field names from the top-level flat dict — instructions are a separate
 * concern.
 */
export function attachInstructions(flat: SecureEntry, raw: ReadEntry): void {
  const body = raw.plaintext["tn.agents"];
  if (!body || typeof body !== "object" || Array.isArray(body)) return;
  const b = body as Record<string, unknown>;
  if (b["$no_read_key"] === true || b["$decrypt_error"] === true) return;

  const instructions: Partial<Instructions> = {};
  for (const f of [
    "instruction",
    "use_for",
    "do_not_use_for",
    "consequences",
    "on_violation_or_error",
    "policy",
  ] as const) {
    if (f in b) {
      (instructions as Record<string, unknown>)[f] = b[f];
    }
    delete (flat as Record<string, unknown>)[f];
  }
  if (Object.keys(instructions).length > 0) {
    flat["instructions"] = instructions as Instructions;
  }
}
