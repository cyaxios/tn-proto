// Pure envelope-decrypt helper. Browser-safe — no fs, no Node imports.
// Branches on the kit's declared cipher, then wraps the cipher's primitive
// (today: `btnDecrypt` from `../raw.js`; soon: `jweDecrypt`) with per-group
// kit-trying and plaintext markers, so callers don't duplicate the
// bookkeeping.

import { x25519 } from "@noble/curves/ed25519";

import { btnDecrypt, canonicalBytes, hibeOpen } from "../raw.js";
import { jweDecrypt, okpPrivateJwk } from "./jwe.js";

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
 * kit doesn't match (caller catches and tries the next kit). Returns
 * `null` if the cipher is recognized but its primitive isn't wired yet
 * (e.g., JWE pre-implementation), so callers can surface
 * `$unsupported_cipher` instead of mistaking it for `$no_read_key`. */
function _runKit(
  kits: GroupKits,
  kit: Uint8Array,
  ct: Uint8Array,
  aad: Uint8Array | undefined,
): Uint8Array | null {
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
      // jwe seals/opens through panva/jose, which is async (WebCrypto). This
      // SYNCHRONOUS path handles btn/hibe only; jwe is opened by the async
      // sibling `decryptGroupAsync` (used by `readAsync` / `tn.readAsync`).
      // Returning null here surfaces $unsupported_cipher on the sync path so a
      // caller knows to use the async read verb, never a silent mis-read.
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
      const result = _runKit(kits, kit, cipher.ct, cipher.aad);
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

/** Async sibling of {@link decryptGroup} that also opens `cipher: jwe` groups
 * (panva/jose is async). btn/hibe resolve synchronously; jwe uses the reader's
 * raw 32-byte X25519 private (`kits.kits[i]`), deriving the public half to form
 * the OKP JWK. Used by the async read path (`tn.readAsync`). The sync
 * {@link decryptGroup} stays untouched for btn/hibe callers. */
export async function decryptGroupAsync(
  cipher: GroupCiphertext,
  kits: GroupKits,
): Promise<Record<string, unknown> | DecryptMarker> {
  if (kits.kits.length === 0) {
    return { $no_read_key: true };
  }
  for (const kit of kits.kits) {
    const aadArg = cipher.aad && cipher.aad.length > 0 ? cipher.aad : undefined;
    try {
      let pt: Uint8Array;
      if (kits.cipher === "jwe") {
        const opened = await jweDecrypt(okpPrivateJwk(x25519.getPublicKey(kit), kit), cipher.ct, aadArg);
        if (opened === null) throw new Error("jwe: this key opens no recipient block");
        pt = opened;
      } else if (kits.cipher === "hibe") {
        if (kits.mpk === undefined) throw new Error("hibe: GroupKits.mpk is required");
        pt = hibeOpen(kits.mpk, kit, cipher.ct, aadArg);
      } else {
        pt = btnDecrypt(kit, cipher.ct, aadArg);
      }
      try {
        return JSON.parse(new TextDecoder("utf-8").decode(pt)) as Record<string, unknown>;
      } catch {
        return { $decrypt_error: true };
      }
    } catch {
      /* try next kit */
    }
  }
  return { $no_read_key: true };
}
