// Pure envelope-decrypt helper. Browser-safe — no fs, no Node imports.
// Wraps `btnDecrypt` (the wasm-backed cipher primitive in `../raw.js`)
// with per-group kit-trying and plaintext markers, so callers don't
// duplicate the bookkeeping.

import { btnDecrypt } from "../raw.js";

/** Per-group ciphertext bytes the runtime extracts from an envelope. */
export interface GroupCiphertext {
  ct: Uint8Array;
}

/** Set of decrypt kits the caller holds for one group. The caller picks
 * the kit list off its own keystore and hands it in. */
export interface GroupKits {
  /** One or more kits to try (publisher might have rotated). The first
   * kit that successfully decrypts wins. */
  kits: Uint8Array[];
}

/** Outcome marker on a per-group plaintext entry when decrypt fails. */
export type DecryptMarker =
  | { $no_read_key: true }
  | { $decrypt_error: true };

/** Try each kit in `kits.kits` against `cipher.ct`. Return the JSON-parsed
 * plaintext if one succeeds; `{$decrypt_error: true}` if a kit decrypts
 * but JSON.parse fails; `{$no_read_key: true}` if no kit decrypts.
 *
 * Layer 1: no fs, no global state. The caller is responsible for
 * assembling `kits` from its own keystore (Layer 2 work).
 */
export function decryptGroup(
  cipher: GroupCiphertext,
  kits: GroupKits,
): Record<string, unknown> | DecryptMarker {
  if (kits.kits.length === 0) {
    return { $no_read_key: true };
  }
  let pt: Uint8Array | null = null;
  for (const kit of kits.kits) {
    try {
      pt = btnDecrypt(kit, cipher.ct);
      break;
    } catch {
      /* try next kit */
    }
  }
  if (!pt) {
    return { $no_read_key: true };
  }
  try {
    return JSON.parse(new TextDecoder("utf-8").decode(pt)) as Record<string, unknown>;
  } catch {
    return { $decrypt_error: true };
  }
}

/** Decrypt every group named in `groups` against the kits map. Returns
 * a `{groupName → plaintext-or-marker}` shape. The runtime's read path
 * uses this to populate the `plaintext` field of a `ReadEntry`. */
export function decryptAllGroups(
  groups: Map<string, GroupCiphertext>,
  kitsByGroup: Map<string, GroupKits>,
): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const [gname, cipher] of groups) {
    const kits = kitsByGroup.get(gname) ?? { kits: [] };
    out[gname] = decryptGroup(cipher, kits) as Record<string, unknown>;
  }
  return out;
}
