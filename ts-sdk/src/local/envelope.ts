// Thin bridge between the JSON keystore format and the SDK's decrypt/Entry surface.
// No decryption or entry-construction logic lives here — all delegated to the SDK.

import { btnCiphertextPublisherId } from "../raw.js";
import { aadBytesFor, decryptAllGroups } from "../core/decrypt.js";
import type { GroupCiphertext, GroupKits } from "../core/decrypt.js";
import { RESERVED_ENVELOPE_KEYS, isGroupPayloadValue } from "../core/read_shape.js";
import { Entry } from "../Entry.js";
import { fromBase64, bytesToHex } from "./_utils.js";
import type { KeystoreHandle } from "./keystore.js";

export function extractGroupCts(
  envelope: Record<string, unknown>,
): Record<string, GroupCiphertext> {
  const out: Record<string, GroupCiphertext> = {};
  for (const [k, v] of Object.entries(envelope)) {
    if (RESERVED_ENVELOPE_KEYS.has(k)) continue;
    if (!isGroupPayloadValue(v)) continue;
    const ctB64 = (v as { ciphertext: string }).ciphertext;
    if (typeof ctB64 !== "string") continue;
    // Reconstruct the group's aad from the public tn_aad echo (empty for a
    // btn group, which cannot be aad-bound; carried uniformly regardless).
    out[k] = { ct: fromBase64(ctB64), aad: aadBytesFor(envelope, k) };
  }
  return out;
}

/** Bridge: for each group, extract publisher ID from ciphertext bytes,
 * look up kits from the keystore, return the GroupKits map SDK decrypt expects.
 *
 * @param getPublisherId — injectable for unit tests (defaults to SDK's btnCiphertextPublisherId)
 */
export function buildGroupKitsMap(
  groupCts: Map<string, GroupCiphertext>,
  keystore: KeystoreHandle,
  getPublisherId: (ct: Uint8Array) => Uint8Array = btnCiphertextPublisherId,
): Map<string, GroupKits> {
  const out = new Map<string, GroupKits>();
  for (const [gname, { ct }] of groupCts) {
    let kits: Uint8Array[] = [];
    try {
      kits = keystore.kitsForPublisher(bytesToHex(getPublisherId(ct)));
    } catch {
      // corrupt/short ciphertext — leave kits empty
    }
    out.set(gname, { cipher: "btn", kits });
  }
  return out;
}

/** Process one raw envelope into a typed Entry.
 * Delegates decrypt to SDK's decryptAllGroups, construction to SDK's Entry.fromRaw. */
export function processEnvelope(
  envelope: Record<string, unknown>,
  keystore?: KeystoreHandle,
): Entry {
  let plaintext: Record<string, unknown> = {};
  if (keystore) {
    const groupCtsMap = new Map(Object.entries(extractGroupCts(envelope)));
    if (groupCtsMap.size > 0) {
      plaintext = decryptAllGroups(groupCtsMap, buildGroupKitsMap(groupCtsMap, keystore));
    }
  }
  return Entry.fromRaw({ envelope, plaintext });
}
