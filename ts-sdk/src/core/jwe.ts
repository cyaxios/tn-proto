// RFC 7516 General JSON JWE for `cipher: jwe` groups. Cryptography and strict
// wire parsing run in the shared Rust implementation through tn-wasm; this
// module keeps the established JWK-oriented TypeScript API and failure markers.

import { x25519 } from "@noble/curves/ed25519";
import type { JWK } from "jose";

import { encryptSync, keygen, subscribe } from "../jwe.js";
import {
  AuthenticationFailedError,
  LimitExceededError,
  MalformedError,
  NotEntitledError,
} from "../primitive_errors.js";

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
  return keygen();
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

function isTnJweProfile(value: unknown): value is JsonObject {
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
export function jweSealSync(
  recipientPubs: Uint8Array[],
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  if (recipientPubs.length === 0) {
    throw new Error("jwe: cannot seal with zero recipients");
  }
  for (const pub of recipientPubs) {
    requireRawX25519(pub, "recipient public key");
    if (!isUsableX25519PublicKey(pub)) {
      throw new Error("jwe: recipient public key is not a usable X25519 point");
    }
  }
  return encryptSync(plaintext, recipientPubs, aad);
}

/** Backward-compatible async delegate to {@link jweSealSync}. */
export async function jweSeal(
  recipientPubs: Uint8Array[],
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  return jweSealSync(recipientPubs, plaintext, aad);
}

export type JweDecryptOutcome =
  | { status: "opened"; plaintext: Uint8Array }
  | { status: "malformed" }
  | { status: "authentication_failed" }
  | { status: "not_entitled" };

function parseTnJwe(blob: Uint8Array): JsonObject | null {
  if (blob.length > MAX_JWE_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(blob));
  } catch {
    return null;
  }
  return isTnJweProfile(parsed) ? parsed : null;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function importReaderKey(readerJwk: JWK): Uint8Array {
  try {
    const key = asObject(readerJwk);
    if (key === null || key.kty !== "OKP" || key.crv !== "X25519") {
      throw new Error("reader key must be an X25519 OKP JWK");
    }
    if (
      typeof key.x !== "string" ||
      typeof key.d !== "string" ||
      !isCanonicalB64u(key.x, 32, 32) ||
      !isCanonicalB64u(key.d, 32, 32)
    ) {
      throw new Error("reader key must contain canonical 32-byte x and d members");
    }
    const publicKey = b64uDecode(key.x);
    const privateKey = b64uDecode(key.d);
    if (!isUsableX25519PublicKey(publicKey)) {
      throw new Error("reader public key is not a usable X25519 point");
    }
    if (!sameBytes(x25519.getPublicKey(privateKey), publicKey)) {
      throw new Error("reader JWK public and private key material do not match");
    }
    return privateKey;
  } catch (error) {
    throw new Error("jwe: failed to import reader key for TN profile", { cause: error });
  }
}

function importReaderKeys(readerJwks: readonly JWK[]): Uint8Array[] {
  const keys: Uint8Array[] = [];
  for (const readerJwk of readerJwks) {
    keys.push(importReaderKey(readerJwk));
  }
  return keys;
}

function decryptFailure(error: unknown): JweDecryptOutcome {
  if (error instanceof AuthenticationFailedError) {
    return { status: "authentication_failed" };
  }
  if (error instanceof NotEntitledError) {
    return { status: "not_entitled" };
  }
  if (error instanceof MalformedError || error instanceof LimitExceededError) {
    return { status: "malformed" };
  }
  throw error;
}

/** Open a General JSON JWE with multiple reader JWKs after one strict parse. */
export function jweDecryptManyDetailedSync(
  readerJwks: readonly JWK[],
  blob: Uint8Array,
  aad?: Uint8Array,
): JweDecryptOutcome {
  if (parseTnJwe(blob) === null) return { status: "malformed" };
  const stableBlob = new Uint8Array(blob);
  const keys = importReaderKeys(readerJwks);
  if (keys.length === 0) return { status: "not_entitled" };
  try {
    return { status: "opened", plaintext: subscribe(keys).decryptSync(stableBlob, aad) };
  } catch (error) {
    return decryptFailure(error);
  }
}

/** Backward-compatible async delegate to {@link jweDecryptManyDetailedSync}. */
export async function jweDecryptManyDetailed(
  readerJwks: readonly JWK[],
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<JweDecryptOutcome> {
  return jweDecryptManyDetailedSync(readerJwks, blob, aad);
}

/** Open a General JSON JWE and retain its stable failure classification. */
export function jweDecryptDetailedSync(
  readerJwk: JWK,
  blob: Uint8Array,
  aad?: Uint8Array,
): JweDecryptOutcome {
  return jweDecryptManyDetailedSync([readerJwk], blob, aad);
}

/** Backward-compatible async delegate to {@link jweDecryptDetailedSync}. */
export async function jweDecryptDetailed(
  readerJwk: JWK,
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<JweDecryptOutcome> {
  return jweDecryptDetailedSync(readerJwk, blob, aad);
}

/** Open a General JSON JWE, preserving the legacy plaintext-or-null contract. */
export function jweDecryptSync(
  readerJwk: JWK,
  blob: Uint8Array,
  aad?: Uint8Array,
): Uint8Array | null {
  const outcome = jweDecryptDetailedSync(readerJwk, blob, aad);
  return outcome.status === "opened" ? outcome.plaintext : null;
}

/** Backward-compatible async delegate to {@link jweDecryptSync}. */
export async function jweDecrypt(
  readerJwk: JWK,
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array | null> {
  return jweDecryptSync(readerJwk, blob, aad);
}
