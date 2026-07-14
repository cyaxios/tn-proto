// RFC 7516 JWE for `cipher: jwe` groups, via the panva/jose JOSE
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
// TypeScript JWE uses panva/jose. The native Rust SDK now has its own RFC 7516
// implementation; only the wasm path lacks a Rust JOSE surface. These calls are
// ASYNC (they use WebCrypto), which is why jwe seals/opens ride the async
// emit/read path
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

const MAX_PROFILE_RECIPIENTS = 1_024;
const MAX_JWE_BYTES = 128 * 1024 * 1024;
const MAX_AAD_BYTES = 64 * 1024;
const X25519_VALIDATION_SCALAR = new Uint8Array(32).fill(1);
const HEADER_MEMBERS = new Set(["alg", "enc", "epk"]);
const EPK_MEMBERS = new Set(["kty", "crv", "x"]);
const RECIPIENT_MEMBERS = new Set(["header", "encrypted_key"]);
const JWE_MEMBERS = new Set([
  "protected",
  "unprotected",
  "recipients",
  "aad",
  "iv",
  "ciphertext",
  "tag",
]);
const BASE64URL = /^[A-Za-z0-9_-]*$/;
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function asObject(value: unknown): JsonObject | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
}

function hasMember(obj: JsonObject, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function hasOnlyMembers(obj: JsonObject, allowed: ReadonlySet<string>): boolean {
  return Object.keys(obj).every((key) => allowed.has(key));
}

function isCanonicalB64u(value: string, maxBytes: number, exactBytes?: number): boolean {
  if (value.length > Math.ceil((maxBytes * 4) / 3) || !BASE64URL.test(value)) return false;
  const remainder = value.length % 4;
  if (remainder === 1) return false;
  const decodedLength = Math.floor((value.length * 3) / 4);
  if (decodedLength > maxBytes || (exactBytes !== undefined && decodedLength !== exactBytes)) {
    return false;
  }
  const tail = BASE64URL_ALPHABET.indexOf(value.at(-1) ?? "A");
  if (remainder === 2 && (tail & 15) !== 0) return false;
  if (remainder === 3 && (tail & 3) !== 0) return false;
  return true;
}

function b64uDecode(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function b64uDecodeText(value: string): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(b64uDecode(value));
}

export function isUsableX25519PublicKey(value: Uint8Array): boolean {
  try {
    x25519.getSharedSecret(X25519_VALIDATION_SCALAR, value);
    return true;
  } catch {
    return false;
  }
}

function aadMatches(segment: string | undefined, expected: Uint8Array | undefined): boolean {
  const actual = segment === undefined ? new Uint8Array(0) : b64uDecode(segment);
  const wanted = expected ?? new Uint8Array(0);
  return actual.length === wanted.length && actual.every((value, index) => value === wanted[index]);
}

function decodeProtectedHeader(value: unknown): JsonObject | null {
  if (typeof value !== "string" || value.length === 0 || !isCanonicalB64u(value, 256)) {
    return null;
  }
  try {
    const header = asObject(JSON.parse(b64uDecodeText(value)));
    return header !== null && isJoseHeader(header) ? header : null;
  } catch {
    return null;
  }
}

function isEphemeralPublicKey(value: unknown): boolean {
  const epk = asObject(value);
  return (
    epk !== null &&
    hasOnlyMembers(epk, EPK_MEMBERS) &&
    epk.kty === "OKP" &&
    epk.crv === "X25519" &&
    typeof epk.x === "string" &&
    isCanonicalB64u(epk.x, 32, 32) &&
    isUsableX25519PublicKey(b64uDecode(epk.x))
  );
}

function isJoseHeader(header: JsonObject): boolean {
  if (!hasOnlyMembers(header, HEADER_MEMBERS)) return false;
  if (hasMember(header, "alg") && typeof header.alg !== "string") return false;
  if (hasMember(header, "enc") && typeof header.enc !== "string") return false;
  if (hasMember(header, "epk") && !isEphemeralPublicKey(header.epk)) return false;
  return true;
}

function mergedHeaderValue(
  key: string,
  protectedHeader: JsonObject,
  sharedHeader: JsonObject | undefined,
  recipientHeader: JsonObject | undefined,
): unknown {
  if (hasMember(protectedHeader, key)) return protectedHeader[key];
  if (sharedHeader !== undefined && hasMember(sharedHeader, key)) return sharedHeader[key];
  return recipientHeader?.[key];
}

function headerMemberCount(key: string, headers: (JsonObject | undefined)[]): number {
  return headers.reduce(
    (count, header) => count + Number(header !== undefined && hasMember(header, key)),
    0,
  );
}

function isProfileRecipient(
  value: unknown,
  protectedHeader: JsonObject,
  sharedHeader: JsonObject | undefined,
  multiple: boolean,
): boolean {
  const recipient = asObject(value);
  if (recipient === null || !hasOnlyMembers(recipient, RECIPIENT_MEMBERS)) return false;
  if (
    typeof recipient.encrypted_key !== "string" ||
    !isCanonicalB64u(recipient.encrypted_key, 40, 40)
  ) {
    return false;
  }
  let localHeader: JsonObject | undefined;
  if (hasMember(recipient, "header")) {
    localHeader = asObject(recipient.header) ?? undefined;
    if (localHeader === undefined || !isJoseHeader(localHeader)) return false;
  }
  const headers = [protectedHeader, sharedHeader, localHeader];
  if (["alg", "enc", "epk"].some((name) => headerMemberCount(name, headers) > 1)) return false;
  if (mergedHeaderValue("alg", protectedHeader, sharedHeader, localHeader) !== JWE_ALG)
    return false;
  const protectedEpk = hasMember(protectedHeader, "epk");
  const sharedEpk = sharedHeader !== undefined && hasMember(sharedHeader, "epk");
  const localEpk = localHeader !== undefined && hasMember(localHeader, "epk");
  if (sharedEpk || (multiple && (protectedEpk || !localEpk))) return false;
  return multiple || protectedEpk || localEpk;
}

function isTnJweProfile(value: unknown): value is GeneralJWE {
  const doc = asObject(value);
  if (doc === null || !hasOnlyMembers(doc, JWE_MEMBERS)) return false;
  if (!["protected", "recipients", "iv", "ciphertext", "tag"].every((key) => hasMember(doc, key))) {
    return false;
  }
  const protectedHeader = decodeProtectedHeader(doc.protected);
  if (protectedHeader === null || protectedHeader.enc !== JWE_ENC) return false;
  let sharedHeader: JsonObject | undefined;
  if (hasMember(doc, "unprotected")) {
    sharedHeader = asObject(doc.unprotected) ?? undefined;
    if (sharedHeader === undefined || !isJoseHeader(sharedHeader)) return false;
  }
  if (typeof doc.iv !== "string" || !isCanonicalB64u(doc.iv, 12, 12)) return false;
  if (typeof doc.tag !== "string" || !isCanonicalB64u(doc.tag, 16, 16)) return false;
  if (typeof doc.ciphertext !== "string" || !isCanonicalB64u(doc.ciphertext, MAX_JWE_BYTES)) {
    return false;
  }
  if (hasMember(doc, "aad")) {
    if (typeof doc.aad !== "string" || doc.aad.length === 0) return false;
    if (!isCanonicalB64u(doc.aad, MAX_AAD_BYTES)) return false;
  }
  const recipients = Array.isArray(doc.recipients) ? doc.recipients : [];
  if (recipients.length === 0 || recipients.length > MAX_PROFILE_RECIPIENTS) return false;
  return recipients.every((recipient) =>
    isProfileRecipient(recipient, protectedHeader, sharedHeader, recipients.length > 1),
  );
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

export type JweDecryptOutcome =
  | { status: "opened"; plaintext: Uint8Array }
  | { status: "malformed" }
  | { status: "authentication_failed" }
  | { status: "not_entitled" };

type ImportedJweKey = Awaited<ReturnType<typeof importJWK>>;

function parseTnJwe(blob: Uint8Array): GeneralJWE | null {
  if (blob.length > MAX_JWE_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(blob));
  } catch {
    return null;
  }
  return isTnJweProfile(parsed) ? parsed : null;
}

async function importReaderKeys(readerJwks: readonly JWK[]): Promise<ImportedJweKey[]> {
  const keys: ImportedJweKey[] = [];
  for (const readerJwk of readerJwks) {
    try {
      keys.push(await importJWK(readerJwk, JWE_ALG));
    } catch (err) {
      throw new Error("jwe: failed to import reader key for TN profile", { cause: err });
    }
  }
  return keys;
}

async function decryptWithReaderKeys(
  obj: GeneralJWE,
  keys: readonly ImportedJweKey[],
  aad: Uint8Array | undefined,
): Promise<JweDecryptOutcome> {
  for (const key of keys) {
    try {
      const result = await generalDecrypt(obj, key, {
        keyManagementAlgorithms: [JWE_ALG],
        contentEncryptionAlgorithms: [JWE_ENC],
      });
      const got = result.additionalAuthenticatedData ?? new Uint8Array(0);
      const want = aad ?? new Uint8Array(0);
      if (got.length !== want.length || !got.every((value, index) => value === want[index])) {
        return { status: "authentication_failed" };
      }
      return { status: "opened", plaintext: result.plaintext };
    } catch {
      continue;
    }
  }
  return { status: "not_entitled" };
}

/** Open a General JSON JWE with multiple reader JWKs after one strict parse. */
export async function jweDecryptManyDetailed(
  readerJwks: readonly JWK[],
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<JweDecryptOutcome> {
  const obj = parseTnJwe(blob);
  if (obj === null) return { status: "malformed" };
  const keys = await importReaderKeys(readerJwks);
  if (!aadMatches(obj.aad, aad)) return { status: "authentication_failed" };
  return decryptWithReaderKeys(obj, keys, aad);
}

/** Open a General JSON JWE and retain its stable failure classification. */
export async function jweDecryptDetailed(
  readerJwk: JWK,
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<JweDecryptOutcome> {
  return jweDecryptManyDetailed([readerJwk], blob, aad);
}

/** Open a General JSON JWE, preserving the legacy plaintext-or-null contract. */
export async function jweDecrypt(
  readerJwk: JWK,
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array | null> {
  const outcome = await jweDecryptDetailed(readerJwk, blob, aad);
  return outcome.status === "opened" ? outcome.plaintext : null;
}
