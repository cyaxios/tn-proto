import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { computeRowHash, zeroHash as rawZeroHash } from "../raw.js";
import { asRowHash, type RowHash, type RowHashInput } from "./types.js";

let _zeroHash: RowHash | null = null;
/** Zero-initialized prev_hash for the first entry in any chain.
 *
 * Lazy-evaluated on first access so consumers that import this module
 * before tn-wasm has been initialized (notably browser bundles loaded
 * before their wasm-pack init) don't crash at module-load. */
export function ZERO_HASH(): RowHash {
  if (_zeroHash === null) _zeroHash = asRowHash(rawZeroHash());
  return _zeroHash;
}

/** Hex-encoded SHA-256 of the UTF-8 bytes of a string. Browser-safe via
 * @noble/hashes (audited, pure-JS). Used by core/agents_policy.ts to
 * compute policy contentHash without reaching for `node:crypto`. */
export function sha256Hex(text: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(text)));
}

/** Hex-encoded SHA-256 of a raw byte array. */
export function sha256HexBytes(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

/**
 * Compute the row_hash from the parts that transitively cover every
 * envelope field.
 *
 * This mirrors `tn.chain.compute_row_hash` in Python byte for byte.
 */
export function rowHash(input: RowHashInput): RowHash {
  const groups: Record<string, { ciphertext_b64: string; field_hashes: Record<string, string> }> =
    {};
  for (const [gname, g] of Object.entries(input.groups ?? {})) {
    groups[gname] = {
      ciphertext_b64: Buffer.from(g.ciphertext).toString("base64"),
      field_hashes: g.fieldHashes ?? {},
    };
  }
  const flat = {
    did: input.did,
    timestamp: input.timestamp,
    event_id: input.eventId,
    event_type: input.eventType,
    level: input.level,
    prev_hash: input.prevHash,
    public_fields: input.publicFields ?? {},
    groups,
  };
  return asRowHash(computeRowHash(flat));
}
