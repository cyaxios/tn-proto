// RFC 7516 JWE for `cipher: jwe` groups, via panva/jose — the production JOSE
// library. This is the TS peer of Python's `tn/cipher.py::JWEGroupCipher`:
// per recipient ECDH-ES+A256KW over X25519, one shared A256GCM CEK for the
// body, the TN marker bound as the native JWE `aad` member. Output is a JWE
// General JSON Serialization object — the same standard the Python side emits,
// so a record sealed by either impl opens in the other (see
// docs/JWE-cipher-spec.md).
//
// Runtime: panva/jose leans on the WebCrypto global (`globalThis.crypto`),
// which is present in browsers, Deno, Cloudflare Workers, and Node >= 20 (the
// SDK's declared minimum — see package.json `engines`). On Node < 20 it is
// absent and these calls throw `crypto is not defined`; run on a supported Node.
//
// Unlike btn/hibe (native, sealed/opened through the wasm runtime), JWE is a
// pure-JS cipher: there is no wasm-compatible Rust JOSE, and JWE's crypto is
// commodity, so panva/jose is the right engine. These calls are ASYNC (they use
// WebCrypto), which is why jwe seals/opens ride the async emit/read path
// (`emitAsync` / `readAsync` / `decryptGroupAsync`) rather than the synchronous
// btn/hibe loop.

import { GeneralEncrypt, generalDecrypt, importJWK, type GeneralJWE, type JWK } from "jose";

/** Per-recipient key-management algorithm: ECDH-ES derives a KEK, A256KW wraps
 * the shared CEK. Body content-encryption is A256GCM. */
export const JWE_ALG = "ECDH-ES+A256KW";
export const JWE_ENC = "A256GCM";

/** base64url (no padding) — browser- and Node-safe (no Buffer). */
function b64u(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A raw 32-byte X25519 public key as an RFC 8037 OKP JWK. */
export function okpPublicJwk(pubRaw: Uint8Array): JWK {
  return { kty: "OKP", crv: "X25519", x: b64u(pubRaw) };
}

/** A raw X25519 keypair (32-byte public + 32-byte private) as an OKP private JWK. */
export function okpPrivateJwk(pubRaw: Uint8Array, privRaw: Uint8Array): JWK {
  return { kty: "OKP", crv: "X25519", x: b64u(pubRaw), d: b64u(privRaw) };
}

/** Seal `plaintext` to N X25519 recipients as an RFC 7516 General JSON JWE.
 *
 * Returns the UTF-8 JSON bytes that become the group's opaque `ciphertext`.
 * An empty/absent `aad` omits the JWE `aad` member so the no-marker path stays
 * a plain seal, byte-compatible in shape with the Python side. */
export async function jweSeal(
  recipientPubs: Uint8Array[],
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (recipientPubs.length === 0) {
    throw new Error("jwe: cannot seal with zero recipients");
  }
  const enc = new GeneralEncrypt(plaintext).setProtectedHeader({ enc: JWE_ENC });
  if (aad && aad.length > 0) {
    enc.setAdditionalAuthenticatedData(aad);
  }
  for (const pub of recipientPubs) {
    const key = await importJWK(okpPublicJwk(pub), JWE_ALG);
    enc.addRecipient(key).setUnprotectedHeader({ alg: JWE_ALG });
  }
  const obj = await enc.encrypt();
  return new TextEncoder().encode(JSON.stringify(obj));
}

/** Open a General JSON JWE with the reader's X25519 key.
 *
 * panva/jose trials the recipient blocks internally (our blocks are anonymous —
 * no `kid`). Returns the plaintext bytes, or `null` if this key opens no block
 * or the blob is malformed. The embedded `aad` member must byte-match `aad`
 * (the marker reconstructed from the record's public `tn_aad` echo); a mismatch
 * — including a tampered echo — returns `null`, never plaintext. */
export async function jweDecrypt(
  readerJwk: JWK,
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array | null> {
  let obj: GeneralJWE;
  try {
    obj = JSON.parse(new TextDecoder().decode(blob)) as GeneralJWE;
  } catch {
    return null;
  }
  let key;
  try {
    key = await importJWK(readerJwk, JWE_ALG);
  } catch {
    return null;
  }
  try {
    const r = await generalDecrypt(obj, key);
    const got = r.additionalAuthenticatedData ?? new Uint8Array(0);
    const want = aad ?? new Uint8Array(0);
    if (got.length !== want.length || !got.every((v, i) => v === want[i])) {
      return null;
    }
    return r.plaintext;
  } catch {
    return null;
  }
}
