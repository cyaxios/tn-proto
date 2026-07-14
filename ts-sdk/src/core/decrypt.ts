// Pure envelope-decrypt helper. Browser-safe — no fs, no Node imports.
// Branches on the kit's declared cipher, then wraps the cipher's primitive
// (`btnDecrypt`, Rust/WASM JWE, or HIBE) with per-group
// kit-trying and plaintext markers, so callers don't duplicate the
// bookkeeping.

import { subscribe as subscribeJwe } from "../jwe.js";
import { btnDecrypt, canonicalBytes, hibeOpen } from "../raw.js";

/** Reconstruct a group's additional-authenticated-data bytes from a record's
 * public ``tn_aad`` echo. The writer bound ``canonicalBytes(effectiveAad)``
 * to the group seal and echoed the ``{group: dict}`` map as a CANONICAL JSON
 * STRING into ``env.tn_aad``. Parse it and re-canonicalize this group's dict
 * so the AEAD verifies; an absent / empty / malformed entry yields empty
 * bytes (the writer bound nothing). Tampering the echo changes these bytes
 * and every kit fails the AEAD — the group surfaces `$decrypt_error`, never
 * plaintext. Mirrors Python ``tn.reader._aad_bytes_for`` byte-for-byte (same
 * canonical routine, same string wire shape). */
export function aadBytesFor(
  env: Record<string, unknown>,
  group: string,
): Uint8Array {
  const raw = env["tn_aad"];
  if (typeof raw !== "string" || raw.length === 0) {
    return new Uint8Array(0);
  }
  let binding: unknown;
  try {
    binding = JSON.parse(raw);
  } catch {
    return new Uint8Array(0);
  }
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    return new Uint8Array(0);
  }
  const groupAad = (binding as Record<string, unknown>)[group];
  if (
    !groupAad ||
    typeof groupAad !== "object" ||
    Array.isArray(groupAad) ||
    Object.keys(groupAad as Record<string, unknown>).length === 0
  ) {
    return new Uint8Array(0);
  }
  return canonicalBytes(groupAad);
}

/** Cipher kinds the decrypt path knows how to handle. New ciphers add a
 * variant here and a `case` in `_runKit` below. Wire this in lockstep
 * with the matching publisher path (the cipher names match Python's
 * `tn.yaml`'s `groups.*.cipher` field byte-identically). */
export type CipherKind = "btn" | "jwe" | "hibe";

/** Per-group ciphertext bytes the runtime extracts from an envelope. */
export interface GroupCiphertext {
  ct: Uint8Array;
  /** Additional-authenticated-data reconstructed from the record's public
   * ``tn_aad`` echo for THIS group (canonical bytes of the effective aad
   * dict). Must byte-match what the writer bound; empty / absent when the
   * group bound nothing. A tampered echo yields different bytes and every
   * kit fails the AEAD — the group surfaces `$decrypt_error`, never
   * plaintext. */
  aad?: Uint8Array;
}

/** Set of decrypt kits the caller holds for one group. The caller picks
 * the kit list off its own keystore and hands it in along with the
 * declared cipher (loaded from the ceremony yaml). */
export interface GroupKits {
  cipher: CipherKind;
  /** One or more kits to try (publisher might have rotated). The first
   * kit that successfully decrypts wins. For `cipher: "hibe"` each kit
   * is an identity key (`<group>.hibe.sk`), current first, then the
   * superseded `.previous` keys and any msk-minted candidates the
   * keystore assembler produced. */
  kits: Uint8Array[];
  /** hibe only: the authority master public key (`<group>.hibe.mpk`).
   * Required to open hibe blobs; ignored by every other cipher. */
  mpk?: Uint8Array;
}

/** Outcome marker on a per-group plaintext entry when decrypt fails. */
export type DecryptMarker =
  | { $no_read_key: true }
  | { $decrypt_error: true }
  | { $unsupported_cipher: true; cipher: string };

/** Run one kit against the ciphertext for the given cipher. Throws if the
 * kit doesn't match so the caller can try the next rotated kit. */
function _runKit(
  kits: GroupKits,
  kit: Uint8Array,
  ct: Uint8Array,
  aad: Uint8Array | undefined,
): Uint8Array {
  const aadArg = aad && aad.length > 0 ? aad : undefined;
  switch (kits.cipher) {
    case "btn":
      // btn binds the reconstructed marker into the body AEAD (empty/absent
      // when the group bound nothing) — same as hibe.
      return btnDecrypt(kit, ct, aadArg);
    case "hibe": {
      if (kits.mpk === undefined) {
        // A hibe kit is unusable without the authority mpk; the keystore
        // assembler always ships them together, so a missing mpk means the
        // caller misassembled the kits. Throwing (caught per kit) surfaces
        // as $no_read_key — the honest outcome: this holder cannot open it.
        throw new Error("hibe: GroupKits.mpk is required to open a hibe blob");
      }
      return hibeOpen(kits.mpk, kit, ct, aadArg);
    }
    case "jwe":
      return subscribeJwe([kit]).decryptSync(ct, aadArg);
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
  for (const kit of kits.kits) {
    try {
      pt = _runKit(kits, kit, cipher.ct, cipher.aad);
      break;
    } catch {
      /* try next kit */
    }
  }
  if (!pt) {
    return { $no_read_key: true };
  }
  return pt;
}

/** Try each kit in `kits.kits` against `cipher.ct`. Return the JSON-parsed
 * plaintext if one succeeds; `{$decrypt_error: true}` if a kit decrypts
 * but JSON.parse fails; `{$no_read_key: true}` if no kit decrypts;
 * `{$unsupported_cipher, cipher}` if a future recognized cipher has no
 * synchronous primitive yet.
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

/** Backward-compatible async delegate to {@link decryptGroup}. */
export async function decryptGroupAsync(
  cipher: GroupCiphertext,
  kits: GroupKits,
): Promise<Record<string, unknown> | DecryptMarker> {
  return decryptGroup(cipher, kits);
}
