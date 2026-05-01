import { deriveGroupIndexKey, indexToken } from "./raw.js";

/**
 * Derive the per-group HKDF-SHA256 index key. `master` must be 32 bytes.
 * Info string binds the key to (ceremony_id, group_name, epoch).
 */
export function deriveGroupKey(
  master: Uint8Array,
  ceremonyId: string,
  groupName: string,
  epoch: number | bigint,
): Uint8Array {
  if (master.length !== 32) {
    throw new Error(`master must be 32 bytes, got ${master.length}`);
  }
  const e = typeof epoch === "bigint" ? epoch : BigInt(epoch);
  return deriveGroupIndexKey(master, ceremonyId, groupName, e);
}

/** Keyed equality token: `hmac-sha256:v1:<hex>`. */
export function indexTokenFor(groupKey: Uint8Array, fieldName: string, value: unknown): string {
  return indexToken(groupKey, fieldName, value);
}
