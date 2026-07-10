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
import { x25519 } from "@noble/curves/ed25519";

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

function requireRawX25519(bytes: Uint8Array, label: string): Uint8Array {
  if (bytes.length !== 32) {
    throw new Error(`jwe: ${label} must be 32 raw X25519 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/** Mint a fresh X25519 recipient keypair (raw 32-byte halves). The
 * public half enrolls the recipient (`tn.admin.addRecipient` /
 * `jweSeal`); the private half opens their blocks — package it with
 * {@link okpPrivateJwk} for {@link jweDecrypt}, or store it under
 * `<group>.jwe.mykey` in a recipient keystore / key bag for `unseal`. */
export function generateX25519KeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = x25519.utils.randomPrivateKey();
  return { publicKey: x25519.getPublicKey(privateKey), privateKey };
}

/** A raw 32-byte X25519 public key as an RFC 8037 OKP JWK. */
export function okpPublicJwk(pubRaw: Uint8Array): JWK {
  requireRawX25519(pubRaw, "recipient public key");
  return { kty: "OKP", crv: "X25519", x: b64u(pubRaw) };
}

/** A raw X25519 keypair (32-byte public + 32-byte private) as an OKP private JWK. */
export function okpPrivateJwk(pubRaw: Uint8Array, privRaw: Uint8Array): JWK {
  requireRawX25519(pubRaw, "reader public key");
  requireRawX25519(privRaw, "reader private key");
  return { kty: "OKP", crv: "X25519", x: b64u(pubRaw), d: b64u(privRaw) };
}

type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
}

function b64uDecodeText(value: string): string {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return atob(padded);
}

function decodeProtectedHeader(value: unknown): JsonObject | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    return asObject(JSON.parse(b64uDecodeText(value)));
  } catch {
    return null;
  }
}

function mergedHeaderValue(
  key: string,
  protectedHeader: JsonObject,
  sharedHeader: JsonObject,
  recipientHeader: JsonObject,
): unknown {
  return recipientHeader[key] ?? sharedHeader[key] ?? protectedHeader[key];
}

function isTnJweProfile(obj: GeneralJWE): boolean {
  const doc = obj as unknown as JsonObject;
  const protectedHeader = decodeProtectedHeader(doc.protected);
  if (protectedHeader === null || protectedHeader.enc !== JWE_ENC) return false;
  const sharedHeader = asObject(doc.unprotected) ?? {};
  if (sharedHeader.enc !== undefined && sharedHeader.enc !== JWE_ENC) return false;
  if (sharedHeader.alg !== undefined && sharedHeader.alg !== JWE_ALG) return false;
  const recipients = Array.isArray(doc.recipients) ? doc.recipients : null;
  if (recipients === null || recipients.length === 0) return false;
  for (const rawRecipient of recipients) {
    const recipient = asObject(rawRecipient);
    if (recipient === null) return false;
    const recipientHeader = asObject(recipient.header) ?? {};
    if (recipientHeader.enc !== undefined && recipientHeader.enc !== JWE_ENC) return false;
    if (mergedHeaderValue("enc", protectedHeader, sharedHeader, recipientHeader) !== JWE_ENC) {
      return false;
    }
    if (mergedHeaderValue("alg", protectedHeader, sharedHeader, recipientHeader) !== JWE_ALG) {
      return false;
    }
  }
  return true;
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
 * no `kid`). Returns the plaintext bytes, or `null` if this key opens no block,
 * the blob is malformed, or the blob is outside TN's JOSE profile
 * (`ECDH-ES+A256KW` + `A256GCM`). Local reader-key import/runtime failures are
 * thrown with a `jwe:` message instead of being collapsed into recipient misses.
 * The embedded `aad` member must byte-match `aad` (the marker reconstructed from
 * the record's public `tn_aad` echo); a mismatch — including a tampered echo —
 * returns `null`, never plaintext. */
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
  if (!isTnJweProfile(obj)) return null;
  let key;
  try {
    key = await importJWK(readerJwk, JWE_ALG);
  } catch (err) {
    throw new Error(`jwe: failed to import reader key for TN profile: ${(err as Error).message}`, {
      cause: err,
    });
  }
  try {
    const r = await generalDecrypt(obj, key, {
      keyManagementAlgorithms: [JWE_ALG],
      contentEncryptionAlgorithms: [JWE_ENC],
    });
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
