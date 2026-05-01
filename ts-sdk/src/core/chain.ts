import { computeRowHash, zeroHash as rawZeroHash } from "../raw.js";
import { asRowHash, type RowHash, type RowHashInput } from "../types.js";

/** Zero-initialized prev_hash for the first entry in any chain. */
export const ZERO_HASH: RowHash = asRowHash(rawZeroHash());

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
