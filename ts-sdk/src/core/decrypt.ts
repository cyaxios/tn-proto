// Pure envelope-decrypt helper. Browser-safe — no fs, no Node imports.
// Branches on the kit's declared cipher, then wraps the cipher's primitive
// (today: `btnDecrypt` from `../raw.js`; soon: `jweDecrypt`) with per-group
// kit-trying and plaintext markers, so callers don't duplicate the
// bookkeeping.

import { btnDecrypt } from "../raw.js";

/** Cipher kinds the decrypt path knows how to handle. New ciphers add a
 * variant here and a `case` in `_runKit` below. Wire this in lockstep
 * with the matching publisher path (the cipher names match Python's
 * `tn.yaml`'s `groups.*.cipher` field byte-identically). */
export type CipherKind = "btn" | "jwe";

/** Per-group ciphertext bytes the runtime extracts from an envelope. */
export interface GroupCiphertext {
  ct: Uint8Array;
}

/** Set of decrypt kits the caller holds for one group. The caller picks
 * the kit list off its own keystore and hands it in along with the
 * declared cipher (loaded from the ceremony yaml). */
export interface GroupKits {
  cipher: CipherKind;
  /** One or more kits to try (publisher might have rotated). The first
   * kit that successfully decrypts wins. */
  kits: Uint8Array[];
}

/** Outcome marker on a per-group plaintext entry when decrypt fails. */
export type DecryptMarker =
  | { $no_read_key: true }
  | { $decrypt_error: true }
  | { $unsupported_cipher: true; cipher: string };

/** Run one kit against the ciphertext for the given cipher. Throws if the
 * kit doesn't match (caller catches and tries the next kit). Returns
 * `null` if the cipher is recognized but its primitive isn't wired yet
 * (e.g., JWE pre-implementation), so callers can surface
 * `$unsupported_cipher` instead of mistaking it for `$no_read_key`. */
function _runKit(cipher: CipherKind, kit: Uint8Array, ct: Uint8Array): Uint8Array | null {
  switch (cipher) {
    case "btn":
      return btnDecrypt(kit, ct);
    case "jwe":
      // jweDecrypt isn't wired yet — landing in a follow-up. The signature
      // here will be `return jweDecrypt(kit, ct)`. For now: signal that the
      // cipher is recognized but not implemented so callers can flag it.
      return null;
  }
}

/** Try each kit against the ciphertext. Return raw plaintext bytes on
 * success, or one of the failure markers if no kit decrypts. Used by
 * both `decryptGroup` (JSON-parsed result) and `decryptGroupRaw`
 * (bytes-out caller decides parsing). */
function _tryDecryptKits(
  cipher: GroupCiphertext,
  kits: GroupKits,
): Uint8Array | DecryptMarker {
  if (kits.kits.length === 0) {
    return { $no_read_key: true };
  }
  let pt: Uint8Array | null = null;
  let cipherUnsupported = false;
  for (const kit of kits.kits) {
    try {
      const result = _runKit(kits.cipher, kit, cipher.ct);
      if (result === null) {
        cipherUnsupported = true;
        break;
      }
      pt = result;
      break;
    } catch {
      /* try next kit */
    }
  }
  if (cipherUnsupported) {
    return { $unsupported_cipher: true, cipher: kits.cipher };
  }
  if (!pt) {
    return { $no_read_key: true };
  }
  return pt;
}

/** Try each kit in `kits.kits` against `cipher.ct`. Return the JSON-parsed
 * plaintext if one succeeds; `{$decrypt_error: true}` if a kit decrypts
 * but JSON.parse fails; `{$no_read_key: true}` if no kit decrypts;
 * `{$unsupported_cipher, cipher}` if the cipher kind is recognized but
 * the wasm primitive for it isn't wired yet (e.g., jwe before its
 * decrypter lands).
 *
 * Layer 1: no fs, no global state. The caller is responsible for
 * assembling `kits` from its own keystore (Layer 2 work).
 */
export function decryptGroup(
  cipher: GroupCiphertext,
  kits: GroupKits,
): Record<string, unknown> | DecryptMarker {
  const result = _tryDecryptKits(cipher, kits);
  if (result instanceof Uint8Array) {
    try {
      return JSON.parse(new TextDecoder("utf-8").decode(result)) as Record<string, unknown>;
    } catch {
      return { $decrypt_error: true };
    }
  }
  return result;
}

/** Try each kit; on success, return the raw plaintext bytes. The caller
 * decides whether to parse as JSON, decode UTF-8, hex-display, etc.
 * Returns the same failure markers as `decryptGroup` (no `$decrypt_error`
 * since this version doesn't try to JSON-parse). */
export function decryptGroupRaw(
  cipher: GroupCiphertext,
  kits: GroupKits,
): Uint8Array | DecryptMarker {
  return _tryDecryptKits(cipher, kits);
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
    const kits = kitsByGroup.get(gname);
    if (!kits) {
      out[gname] = { $no_read_key: true };
      continue;
    }
    out[gname] = decryptGroup(cipher, kits) as Record<string, unknown>;
  }
  return out;
}
