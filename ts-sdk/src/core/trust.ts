// Strict trusted-principal primitives shared by enrollment ceremonies.
//
// Byte-faithful port of `python/tn/trust.py` + `python/tn/key_binding.py`.
// Only canonical Ed25519 `did:key` identifiers are accepted, every statement
// is strict canonical JSON (unknown fields and versions are rejected before
// any signature check), and every failure carries a stable {@link TrustReason}
// that is identical across SDKs.
//
// Layer 1 (browser-safe): no node:* imports. DID parsing is pure JS so the
// sealed-box path can decode identities before wasm initializes; signature
// verification and canonical bytes route through the shared wasm core.

import { canonicalize } from "./canonical.js";
import { sha256HexBytes } from "./chain.js";
import { bytesToB64, randomBytes } from "./encoding.js";
import { verify as verifyDidSignatureBool, type DeviceKey } from "./signing.js";
import { asDid } from "./types.js";

// ── Stable reasons ──────────────────────────────────────────────────

export const TRUST_REASONS = [
  "statement_invalid",
  "statement_expired",
  "signature_invalid",
  "did_invalid",
  "did_signer_mismatch",
  "outer_inner_signer_mismatch",
  "wrong_recipient",
  "scope_mismatch",
  "body_digest_mismatch",
  "challenge_missing",
  "challenge_expired",
  "challenge_replayed",
  "replay_conflict",
  "binding_invalid",
  "untrusted_principal",
  "epoch_rollback",
  "epoch_conflict",
] as const;

/** Stable machine-readable reasons for trust-boundary rejection. */
export type TrustReason = (typeof TRUST_REASONS)[number];

/** A rejected trust statement with a stable reason and human detail. */
export class TrustError extends Error {
  override readonly name = "TrustError";
  readonly reason: TrustReason;
  readonly detail: string;

  constructor(reason: TrustReason, detail: string) {
    super(`${reason}: ${detail}`);
    this.reason = reason;
    this.detail = detail;
  }
}

function error(reason: TrustReason, detail: string): TrustError {
  return new TrustError(reason, detail);
}

// ── base58btc (the single TS did:key decoder) ───────────────────────
//
// This module owns the one strict base58btc implementation; the sealed-box
// recipient path (`core/recipient_seal.ts`) delegates here so both surfaces
// accept exactly the same identities. Pure JS by design: parsing must work
// before wasm initializes.

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < B58_ALPHABET.length; i += 1) m[B58_ALPHABET.charAt(i)] = i;
  return m;
})();
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

function base58Decode(s: string): Uint8Array {
  if (s.length === 0) {
    throw error("did_invalid", "did:key multibase payload is empty");
  }
  let zeros = 0;
  while (zeros < s.length && s.charAt(zeros) === "1") zeros += 1;
  const bytes: number[] = [];
  for (let i = zeros; i < s.length; i += 1) {
    const digit = B58_INDEX[s.charAt(i)];
    if (digit === undefined) {
      throw error("did_invalid", "did:key contains a non-base58btc character");
    }
    let carry = digit;
    for (let j = 0; j < bytes.length; j += 1) {
      carry += (bytes[j] as number) * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[zeros + i] = bytes[bytes.length - 1 - i] as number;
  return out;
}

function base58Encode(value: Uint8Array): string {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === 0) zeros += 1;
  const digits: number[] = [];
  for (let i = zeros; i < value.length; i += 1) {
    let carry = value[i] as number;
    for (let j = 0; j < digits.length; j += 1) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i -= 1) out += B58_ALPHABET.charAt(digits[i] as number);
  return out;
}

/**
 * Return the raw key from a canonical Ed25519 `did:key` identifier.
 *
 * Only base58btc multibase, the Ed25519 multicodec (`0xed`), and an exactly
 * 32-byte raw public key are accepted; the payload must round-trip to the
 * same base58 spelling (no lossy normalization).
 */
export function parseEd25519DidKey(did: string): Uint8Array {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) {
    throw error("did_invalid", "expected an Ed25519 did:key with a base58btc multibase payload");
  }
  const payload = did.slice("did:key:z".length);
  const decoded = base58Decode(payload);
  if (base58Encode(decoded) !== payload) {
    throw error("did_invalid", "did:key base58btc payload is not canonical");
  }
  if (decoded.length < 2 || decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    throw error("did_invalid", "did:key does not use the Ed25519 multicodec");
  }
  const publicKey = decoded.slice(2);
  if (publicKey.length !== 32) {
    throw error(
      "did_invalid",
      `Ed25519 did:key must contain 32 public-key bytes, got ${publicKey.length}`,
    );
  }
  return publicKey;
}

/**
 * Strictly verify a 64-byte Ed25519 signature for `did`.
 *
 * Verification is always performed against the key embedded in the asserted
 * DID — an unrelated raw verification key never establishes identity. Returns
 * on success and throws {@link TrustError} with `did_invalid` or
 * `signature_invalid` on failure.
 */
export function verifyEd25519DidSignature(
  did: string,
  message: Uint8Array,
  signature: Uint8Array,
): void {
  parseEd25519DidKey(did);
  if (!(message instanceof Uint8Array)) {
    throw error("statement_invalid", "signed message must be bytes");
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw error("signature_invalid", "Ed25519 signature must contain exactly 64 bytes");
  }
  if (!verifyDidSignatureBool(asDid(did), message, signature)) {
    throw error("signature_invalid", "Ed25519 signature is invalid");
  }
}

// ── Timestamps (canonical UTC RFC 3339) ─────────────────────────────

const TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{6}))?Z$/;

/**
 * Parse a canonical UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`, optionally with a
 * non-zero six-digit fraction) into epoch microseconds. Matches the exact
 * strings Python's `datetime.isoformat()` round-trip accepts.
 */
export function parseTrustTimestamp(value: unknown, field: string): number {
  if (typeof value !== "string" || value.length === 0) {
    throw error("statement_invalid", `${field} must be a non-empty string`);
  }
  if (!value.endsWith("Z")) {
    throw error("statement_invalid", `${field} must be a UTC timestamp ending in Z`);
  }
  const match = TIMESTAMP_RE.exec(value);
  if (match === null) {
    throw error("statement_invalid", `${field} is not in canonical UTC form`);
  }
  const [, y, mo, d, h, mi, s, fraction] = match;
  if (fraction === "000000") {
    throw error("statement_invalid", `${field} is not in canonical UTC form`);
  }
  const year = Number(y);
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(s);
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  const check = new Date(ms);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day ||
    check.getUTCHours() !== hour ||
    check.getUTCMinutes() !== minute ||
    check.getUTCSeconds() !== second
  ) {
    throw error("statement_invalid", `${field} is not a valid UTC timestamp`);
  }
  return ms * 1000 + (fraction === undefined ? 0 : Number(fraction));
}

/** Format epoch microseconds as the canonical UTC wire timestamp. */
export function formatTrustTimestamp(epochMicros: number): string {
  if (!Number.isSafeInteger(epochMicros)) {
    throw error("statement_invalid", "timestamp must be an integer microsecond count");
  }
  const micros = ((epochMicros % 1_000_000) + 1_000_000) % 1_000_000;
  const date = new Date((epochMicros - micros) / 1000);
  const pad = (n: number, width: number): string => String(n).padStart(width, "0");
  const base =
    `${pad(date.getUTCFullYear(), 4)}-${pad(date.getUTCMonth() + 1, 2)}-${pad(date.getUTCDate(), 2)}` +
    `T${pad(date.getUTCHours(), 2)}:${pad(date.getUTCMinutes(), 2)}:${pad(date.getUTCSeconds(), 2)}`;
  return micros === 0 ? `${base}Z` : `${base}.${pad(micros, 6)}Z`;
}

function validateTimeOrder(issuedAt: string, expiresAt: string): void {
  const issued = parseTrustTimestamp(issuedAt, "issued_at");
  const expires = parseTrustTimestamp(expiresAt, "expires_at");
  if (expires <= issued) {
    throw error("statement_invalid", "expires_at must be later than issued_at");
  }
}

function validateFreshness(issuedAt: string, expiresAt: string, now: string): void {
  validateTimeOrder(issuedAt, expiresAt);
  const nowMicros = parseTrustTimestamp(now, "now");
  if (nowMicros < parseTrustTimestamp(issuedAt, "issued_at")) {
    throw error("statement_invalid", "statement was issued in the future");
  }
  if (nowMicros >= parseTrustTimestamp(expiresAt, "expires_at")) {
    throw error("statement_expired", "statement has expired");
  }
}

// ── Strict field helpers ────────────────────────────────────────────

function exactFields(
  value: unknown,
  expected: readonly string[],
  label: string,
  reason: TrustReason = "statement_invalid",
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw error(reason, `${label} must be an object`);
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const expectedSet = new Set(expected);
  const missing = expected.filter((k) => !(k in record)).sort();
  const unknown = keys.filter((k) => !expectedSet.has(k)).sort();
  if (missing.length > 0 || unknown.length > 0) {
    const details: string[] = [];
    if (missing.length > 0) details.push(`missing fields ${JSON.stringify(missing)}`);
    if (unknown.length > 0) details.push(`unknown fields ${JSON.stringify(unknown)}`);
    throw error(reason, `${label} has ` + details.join(" and "));
  }
  return record;
}

function requireString(
  value: unknown,
  field: string,
  reason: TrustReason = "statement_invalid",
  allowEmpty = false,
): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    const suffix = allowEmpty ? "a string" : "a non-empty string";
    throw error(reason, `${field} must be ${suffix}`);
  }
  return value;
}

function requireInteger(
  value: unknown,
  field: string,
  minimum: number,
  reason: TrustReason = "statement_invalid",
): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    throw error(reason, `${field} must be an integer greater than or equal to ${minimum}`);
  }
  return value;
}

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/** Decode canonical padded standard base64 of an exact byte length. */
function decodeCanonicalB64(
  value: unknown,
  field: string,
  length: number,
  reason: TrustReason,
): Uint8Array {
  const text = requireString(value, field, reason);
  if (text.length % 4 !== 0 || !B64_RE.test(text)) {
    throw error(reason, `${field} must be canonical base64`);
  }
  let decoded: Uint8Array;
  try {
    const bin = atob(text);
    decoded = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) decoded[i] = bin.charCodeAt(i);
  } catch {
    throw error(reason, `${field} must be canonical base64`);
  }
  if (bytesToB64(decoded) !== text) {
    throw error(reason, `${field} must be canonical padded base64`);
  }
  if (decoded.length !== length) {
    throw error(reason, `${field} must decode to exactly ${length} bytes`);
  }
  return decoded;
}

function validateNonce(value: unknown): void {
  decodeCanonicalB64(value, "nonce_b64", 32, "statement_invalid");
}

function signatureBytes(value: unknown, allowUnsigned: boolean): Uint8Array | null {
  if (allowUnsigned && value === "") return null;
  return decodeCanonicalB64(value, "signature_b64", 64, "signature_invalid");
}

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

function validateDigest(
  value: unknown,
  field: string,
  reason: TrustReason = "statement_invalid",
): string {
  const text = requireString(value, field, reason);
  if (!SHA256_RE.test(text)) {
    throw error(reason, `${field} must be a lowercase sha256 digest`);
  }
  return text;
}

/** `sha256:<lowercase hex>` over raw bytes — the tagged digest form every
 * trust statement uses. */
export function sha256Digest(value: Uint8Array): string {
  return `sha256:${sha256HexBytes(value)}`;
}

function validateDid(value: unknown, field: string): string {
  const did = requireString(value, field);
  parseEd25519DidKey(did);
  return did;
}

function ensureSigningKey(key: DeviceKey, expectedDid: string): void {
  if (key.did !== expectedDid) {
    throw error("did_signer_mismatch", "signing key identity does not match the statement signer");
  }
}

function signBytes(key: DeviceKey, signingBytesValue: Uint8Array): string {
  const signature = key.sign(signingBytesValue);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw error("signature_invalid", "signing key returned an invalid signature");
  }
  return bytesToB64(signature);
}

// ── Statement shapes ────────────────────────────────────────────────

export type ProofPurpose = "jwe-reader" | "hibe-reader" | "hibe-authority";

const PURPOSES: readonly ProofPurpose[] = ["jwe-reader", "hibe-reader", "hibe-authority"];

export interface EnrollmentChallengeV1 {
  version: 1;
  kind: "tn-enrollment-challenge";
  publisher_did: string;
  expected_reader_did: string;
  ceremony_id: string;
  group: string;
  nonce_b64: string;
  issued_at: string;
  expires_at: string;
  challenge_id: string;
  signature_b64: string;
}

export interface KeyBindingProofV1 {
  version: 1;
  purpose: ProofPurpose;
  subject_did: string;
  audience_did: string;
  ceremony_id: string;
  group: string;
  issued_at: string;
  expires_at: string;
  nonce_b64: string;
  binding: Record<string, unknown>;
  signature_b64: string;
}

export interface EnrollmentResponseV1 {
  version: 1;
  kind: "tn-enrollment-response";
  publisher_did: string;
  reader_did: string;
  ceremony_id: string;
  group: string;
  accepted_offer_digest: string;
  x25519_public_key_sha256: string;
  group_epoch: number;
  issued_at: string;
  expires_at: string;
  signature_b64: string;
}

/** Identity and scope established by a verified key-binding proof. */
export interface VerifiedPrincipal {
  did: string;
  purpose: ProofPurpose;
  audienceDid: string;
  ceremonyId: string;
  group: string;
  proofDigest: string;
  issuedAt: string;
  expiresAt: string;
}

/** A verified principal together with its bound X25519 public key. */
export interface VerifiedJweBinding {
  principal: VerifiedPrincipal;
  publicKey: Uint8Array;
  publicKeySha256: string;
  proofDigest: string;
  challengeDigest: string | null;
}

/** Digest-bound result of accepting an authenticated JWE offer. */
export interface AcceptedOffer {
  binding: VerifiedJweBinding;
  offerDigest: string;
  artifactDigest: string;
}

export interface ProofExpectation {
  purpose: ProofPurpose;
  audienceDid: string;
  ceremonyId: string;
  group: string;
  now: string;
  challenge?: EnrollmentChallengeV1;
}

const CHALLENGE_FIELDS = [
  "version",
  "kind",
  "publisher_did",
  "expected_reader_did",
  "ceremony_id",
  "group",
  "nonce_b64",
  "issued_at",
  "expires_at",
  "challenge_id",
  "signature_b64",
] as const;

const PROOF_FIELDS = [
  "version",
  "purpose",
  "subject_did",
  "audience_did",
  "ceremony_id",
  "group",
  "issued_at",
  "expires_at",
  "nonce_b64",
  "binding",
  "signature_b64",
] as const;

const RESPONSE_FIELDS = [
  "version",
  "kind",
  "publisher_did",
  "reader_did",
  "ceremony_id",
  "group",
  "accepted_offer_digest",
  "x25519_public_key_sha256",
  "group_epoch",
  "issued_at",
  "expires_at",
  "signature_b64",
] as const;

const BINDING_FIELDS: Record<ProofPurpose, readonly string[]> = {
  "jwe-reader": ["algorithm", "public_key_b64", "challenge_digest"],
  "hibe-reader": ["algorithm", "delivery", "challenge_digest"],
  "hibe-authority": ["algorithm", "mpk_sha256", "path_epoch", "max_depth", "id_path"],
};

function validateProofBinding(binding: unknown, purpose: ProofPurpose): Record<string, unknown> {
  const value = exactFields(binding, BINDING_FIELDS[purpose], `${purpose} binding`, "binding_invalid");

  if (purpose === "jwe-reader") {
    if (requireString(value["algorithm"], "binding.algorithm", "binding_invalid") !== "X25519") {
      throw error("binding_invalid", "jwe-reader binding algorithm must be X25519");
    }
    decodeCanonicalB64(value["public_key_b64"], "binding.public_key_b64", 32, "binding_invalid");
    if (value["challenge_digest"] !== null) {
      validateDigest(value["challenge_digest"], "binding.challenge_digest", "binding_invalid");
    }
    return { ...value };
  }

  if (purpose === "hibe-reader") {
    if (
      requireString(value["algorithm"], "binding.algorithm", "binding_invalid") !== "Ed25519-did-key"
    ) {
      throw error("binding_invalid", "hibe-reader binding algorithm must be Ed25519-did-key");
    }
    if (
      requireString(value["delivery"], "binding.delivery", "binding_invalid") !== "recipient-seal-v1"
    ) {
      throw error("binding_invalid", "hibe-reader delivery must be recipient-seal-v1");
    }
    if (value["challenge_digest"] !== null) {
      validateDigest(value["challenge_digest"], "binding.challenge_digest", "binding_invalid");
    }
    return { ...value };
  }

  if (
    requireString(value["algorithm"], "binding.algorithm", "binding_invalid") !==
    "TN-BBG-HIBE-BLS12-381"
  ) {
    throw error("binding_invalid", "hibe-authority binding algorithm must be TN-BBG-HIBE-BLS12-381");
  }
  validateDigest(value["mpk_sha256"], "binding.mpk_sha256", "binding_invalid");
  requireInteger(value["path_epoch"], "binding.path_epoch", 0, "binding_invalid");
  const maxDepth = requireInteger(value["max_depth"], "binding.max_depth", 1, "binding_invalid");
  const idPath = requireString(value["id_path"], "binding.id_path", "binding_invalid");
  const parts = idPath.split("/");
  if (parts.some((part) => part.length === 0) || parts.length > maxDepth) {
    throw error("binding_invalid", "binding.id_path must contain one to max_depth non-empty components");
  }
  return { ...value };
}

// ── Challenge ───────────────────────────────────────────────────────

function validateChallenge(challenge: EnrollmentChallengeV1, allowUnsigned: boolean): void {
  if (
    typeof challenge.version !== "number" ||
    challenge.version !== 1 ||
    challenge.kind !== "tn-enrollment-challenge"
  ) {
    throw error("statement_invalid", "unsupported enrollment challenge");
  }
  validateDid(challenge.publisher_did, "publisher_did");
  validateDid(challenge.expected_reader_did, "expected_reader_did");
  requireString(challenge.ceremony_id, "ceremony_id");
  requireString(challenge.group, "group");
  requireString(challenge.challenge_id, "challenge_id");
  validateNonce(challenge.nonce_b64);
  parseTrustTimestamp(challenge.issued_at, "issued_at");
  parseTrustTimestamp(challenge.expires_at, "expires_at");
  validateTimeOrder(challenge.issued_at, challenge.expires_at);
  signatureBytes(challenge.signature_b64, allowUnsigned);
}

/** Parse and strictly validate a version-1 enrollment challenge. */
export function parseEnrollmentChallenge(value: unknown): EnrollmentChallengeV1 {
  const record = exactFields(value, CHALLENGE_FIELDS, "enrollment challenge");
  const version = requireInteger(record["version"], "version", 1);
  if (version !== 1) {
    throw error("statement_invalid", "unsupported enrollment challenge version");
  }
  if (requireString(record["kind"], "kind") !== "tn-enrollment-challenge") {
    throw error("statement_invalid", "unsupported enrollment challenge kind");
  }
  const challenge: EnrollmentChallengeV1 = {
    version: 1,
    kind: "tn-enrollment-challenge",
    publisher_did: requireString(record["publisher_did"], "publisher_did"),
    expected_reader_did: requireString(record["expected_reader_did"], "expected_reader_did"),
    ceremony_id: requireString(record["ceremony_id"], "ceremony_id"),
    group: requireString(record["group"], "group"),
    nonce_b64: requireString(record["nonce_b64"], "nonce_b64"),
    issued_at: requireString(record["issued_at"], "issued_at"),
    expires_at: requireString(record["expires_at"], "expires_at"),
    challenge_id: requireString(record["challenge_id"], "challenge_id"),
    signature_b64: requireString(record["signature_b64"], "signature_b64", "statement_invalid", true),
  };
  validateChallenge(challenge, false);
  return challenge;
}

function challengeWireValue(
  challenge: EnrollmentChallengeV1,
  includeSignature: boolean,
): Record<string, unknown> {
  const value: Record<string, unknown> = {
    version: challenge.version,
    kind: challenge.kind,
    publisher_did: challenge.publisher_did,
    expected_reader_did: challenge.expected_reader_did,
    ceremony_id: challenge.ceremony_id,
    group: challenge.group,
    nonce_b64: challenge.nonce_b64,
    issued_at: challenge.issued_at,
    expires_at: challenge.expires_at,
    challenge_id: challenge.challenge_id,
  };
  if (includeSignature) value["signature_b64"] = challenge.signature_b64;
  return value;
}

/** Canonical bytes of the challenge minus its signature — the signing domain. */
export function enrollmentChallengeSigningBytes(challenge: EnrollmentChallengeV1): Uint8Array {
  validateChallenge(challenge, true);
  return canonicalize(challengeWireValue(challenge, false));
}

/** `sha256:` digest over the complete signed challenge bytes. */
export function enrollmentChallengeDigest(challenge: EnrollmentChallengeV1): string {
  validateChallenge(challenge, true);
  return sha256Digest(canonicalize(challengeWireValue(challenge, true)));
}

/** Sign a challenge with the publisher's device key (must match `publisher_did`). */
export function signEnrollmentChallenge(
  challenge: EnrollmentChallengeV1,
  key: DeviceKey,
): EnrollmentChallengeV1 {
  validateChallenge(challenge, true);
  ensureSigningKey(key, challenge.publisher_did);
  return { ...challenge, signature_b64: signBytes(key, enrollmentChallengeSigningBytes(challenge)) };
}

/** Verify a publisher-signed challenge against the receiver's expectations. */
export function verifyEnrollmentChallenge(
  challenge: EnrollmentChallengeV1,
  expected: { publisherDid: string; readerDid: string; ceremonyId: string; group: string; now: string },
): void {
  validateChallenge(challenge, false);
  validateDid(expected.publisherDid, "expected_publisher_did");
  validateDid(expected.readerDid, "expected_reader_did");
  if (challenge.publisher_did !== expected.publisherDid) {
    throw error("did_signer_mismatch", "challenge publisher does not match the expected publisher");
  }
  if (challenge.expected_reader_did !== expected.readerDid) {
    throw error("wrong_recipient", "challenge names a different reader");
  }
  if (challenge.ceremony_id !== expected.ceremonyId || challenge.group !== expected.group) {
    throw error("scope_mismatch", "challenge ceremony or group does not match");
  }
  validateFreshness(challenge.issued_at, challenge.expires_at, expected.now);
  const signature = signatureBytes(challenge.signature_b64, false) as Uint8Array;
  verifyEd25519DidSignature(
    challenge.publisher_did,
    enrollmentChallengeSigningBytes(challenge),
    signature,
  );
}

// ── Key-binding proof ───────────────────────────────────────────────

function validateProof(proof: KeyBindingProofV1, allowUnsigned: boolean): void {
  if (
    typeof proof.version !== "number" ||
    proof.version !== 1 ||
    !PURPOSES.includes(proof.purpose)
  ) {
    throw error("statement_invalid", "unsupported key-binding proof");
  }
  validateDid(proof.subject_did, "subject_did");
  validateDid(proof.audience_did, "audience_did");
  requireString(proof.ceremony_id, "ceremony_id");
  requireString(proof.group, "group");
  validateNonce(proof.nonce_b64);
  parseTrustTimestamp(proof.issued_at, "issued_at");
  parseTrustTimestamp(proof.expires_at, "expires_at");
  validateTimeOrder(proof.issued_at, proof.expires_at);
  validateProofBinding(proof.binding, proof.purpose);
  signatureBytes(proof.signature_b64, allowUnsigned);
}

/** Parse and strictly validate a version-1 key-binding proof. */
export function parseKeyBindingProof(value: unknown): KeyBindingProofV1 {
  const record = exactFields(value, PROOF_FIELDS, "key-binding proof");
  const version = requireInteger(record["version"], "version", 1);
  if (version !== 1) {
    throw error("statement_invalid", "unsupported key-binding proof version");
  }
  const purposeText = requireString(record["purpose"], "purpose");
  if (!PURPOSES.includes(purposeText as ProofPurpose)) {
    throw error("statement_invalid", "unsupported key-binding proof purpose");
  }
  const purpose = purposeText as ProofPurpose;
  const proof: KeyBindingProofV1 = {
    version: 1,
    purpose,
    subject_did: requireString(record["subject_did"], "subject_did"),
    audience_did: requireString(record["audience_did"], "audience_did"),
    ceremony_id: requireString(record["ceremony_id"], "ceremony_id"),
    group: requireString(record["group"], "group"),
    issued_at: requireString(record["issued_at"], "issued_at"),
    expires_at: requireString(record["expires_at"], "expires_at"),
    nonce_b64: requireString(record["nonce_b64"], "nonce_b64"),
    // Snapshot nested input so a stateful object cannot change between
    // signature verification and purpose-specific key extraction.
    binding: validateProofBinding(record["binding"], purpose),
    signature_b64: requireString(record["signature_b64"], "signature_b64", "statement_invalid", true),
  };
  validateProof(proof, false);
  return proof;
}

function proofWireValue(proof: KeyBindingProofV1, includeSignature: boolean): Record<string, unknown> {
  const value: Record<string, unknown> = {
    version: proof.version,
    purpose: proof.purpose,
    subject_did: proof.subject_did,
    audience_did: proof.audience_did,
    ceremony_id: proof.ceremony_id,
    group: proof.group,
    issued_at: proof.issued_at,
    expires_at: proof.expires_at,
    nonce_b64: proof.nonce_b64,
    binding: { ...proof.binding },
  };
  if (includeSignature) value["signature_b64"] = proof.signature_b64;
  return value;
}

/** Canonical bytes of the proof minus its signature — the signing domain. */
export function keyBindingProofSigningBytes(proof: KeyBindingProofV1): Uint8Array {
  validateProof(proof, true);
  return canonicalize(proofWireValue(proof, false));
}

/** `sha256:` digest over the complete signed proof bytes (the offer digest). */
export function keyBindingProofDigest(proof: KeyBindingProofV1): string {
  validateProof(proof, true);
  return sha256Digest(canonicalize(proofWireValue(proof, true)));
}

/** Sign a proof with the subject's device key (must match `subject_did`). */
export function signKeyBindingProof(proof: KeyBindingProofV1, key: DeviceKey): KeyBindingProofV1 {
  validateProof(proof, true);
  ensureSigningKey(key, proof.subject_did);
  return {
    ...proof,
    binding: { ...proof.binding },
    signature_b64: signBytes(key, keyBindingProofSigningBytes(proof)),
  };
}

/**
 * Verify a key-binding proof and return the verified principal.
 *
 * All strict shape, scope, freshness, and challenge-binding checks run before
 * the wasm signature verification; the signature is verified against the key
 * embedded in `subject_did`.
 */
export function verifyKeyBindingProof(
  proof: KeyBindingProofV1,
  expected: ProofExpectation,
): VerifiedPrincipal {
  validateProof(proof, false);
  if (!PURPOSES.includes(expected.purpose) || proof.purpose !== expected.purpose) {
    throw error("binding_invalid", "key-binding proof purpose does not match");
  }
  validateDid(expected.audienceDid, "expected_audience_did");
  if (proof.audience_did !== expected.audienceDid) {
    throw error("wrong_recipient", "key-binding proof names a different audience");
  }
  if (proof.ceremony_id !== expected.ceremonyId || proof.group !== expected.group) {
    throw error("scope_mismatch", "key-binding proof ceremony or group does not match");
  }
  validateFreshness(proof.issued_at, proof.expires_at, expected.now);

  if (proof.purpose === "jwe-reader" || proof.purpose === "hibe-reader") {
    const boundChallengeDigest = proof.binding["challenge_digest"];
    const challenge = expected.challenge;
    if (challenge === undefined && boundChallengeDigest !== null) {
      throw error("challenge_missing", "reader proof requires a challenge");
    }
    if (challenge !== undefined) {
      try {
        verifyEnrollmentChallenge(challenge, {
          publisherDid: expected.audienceDid,
          readerDid: proof.subject_did,
          ceremonyId: expected.ceremonyId,
          group: expected.group,
          now: expected.now,
        });
      } catch (err) {
        if (err instanceof TrustError && err.reason === "statement_expired") {
          throw error("challenge_expired", err.detail);
        }
        throw err;
      }
      const proofIssued = parseTrustTimestamp(proof.issued_at, "issued_at");
      if (
        proofIssued < parseTrustTimestamp(challenge.issued_at, "issued_at") ||
        proofIssued >= parseTrustTimestamp(challenge.expires_at, "expires_at")
      ) {
        throw error("binding_invalid", "proof issuance time is outside the challenge validity interval");
      }
      if (boundChallengeDigest !== enrollmentChallengeDigest(challenge)) {
        throw error("binding_invalid", "proof is bound to a different challenge");
      }
    }
  }

  const signature = signatureBytes(proof.signature_b64, false) as Uint8Array;
  verifyEd25519DidSignature(proof.subject_did, keyBindingProofSigningBytes(proof), signature);
  return {
    did: proof.subject_did,
    purpose: proof.purpose,
    audienceDid: proof.audience_did,
    ceremonyId: proof.ceremony_id,
    group: proof.group,
    proofDigest: keyBindingProofDigest(proof),
    issuedAt: proof.issued_at,
    expiresAt: proof.expires_at,
  };
}

/** Verify a `jwe-reader` proof and return its typed X25519 binding. */
export function verifyJweKeyBinding(
  proof: KeyBindingProofV1,
  expected: Omit<ProofExpectation, "purpose">,
): VerifiedJweBinding {
  const principal = verifyKeyBindingProof(proof, { ...expected, purpose: "jwe-reader" });
  const publicKey = decodeCanonicalB64(
    proof.binding["public_key_b64"],
    "binding.public_key_b64",
    32,
    "binding_invalid",
  );
  const challengeDigest = proof.binding["challenge_digest"];
  if (challengeDigest !== null && typeof challengeDigest !== "string") {
    throw error("binding_invalid", "challenge digest has an invalid type");
  }
  return {
    principal,
    publicKey,
    publicKeySha256: sha256Digest(publicKey),
    proofDigest: principal.proofDigest,
    challengeDigest: challengeDigest === null ? null : (challengeDigest as string),
  };
}

// ── Enrollment response ─────────────────────────────────────────────

function validateResponse(response: EnrollmentResponseV1, allowUnsigned: boolean): void {
  if (
    typeof response.version !== "number" ||
    response.version !== 1 ||
    response.kind !== "tn-enrollment-response"
  ) {
    throw error("statement_invalid", "unsupported enrollment response");
  }
  validateDid(response.publisher_did, "publisher_did");
  validateDid(response.reader_did, "reader_did");
  requireString(response.ceremony_id, "ceremony_id");
  requireString(response.group, "group");
  validateDigest(response.accepted_offer_digest, "accepted_offer_digest");
  validateDigest(response.x25519_public_key_sha256, "x25519_public_key_sha256");
  requireInteger(response.group_epoch, "group_epoch", 0);
  parseTrustTimestamp(response.issued_at, "issued_at");
  parseTrustTimestamp(response.expires_at, "expires_at");
  validateTimeOrder(response.issued_at, response.expires_at);
  signatureBytes(response.signature_b64, allowUnsigned);
}

/** Parse and strictly validate a version-1 enrollment response. */
export function parseEnrollmentResponse(value: unknown): EnrollmentResponseV1 {
  const record = exactFields(value, RESPONSE_FIELDS, "enrollment response");
  const version = requireInteger(record["version"], "version", 1);
  if (version !== 1) {
    throw error("statement_invalid", "unsupported enrollment response version");
  }
  if (requireString(record["kind"], "kind") !== "tn-enrollment-response") {
    throw error("statement_invalid", "unsupported enrollment response kind");
  }
  const response: EnrollmentResponseV1 = {
    version: 1,
    kind: "tn-enrollment-response",
    publisher_did: requireString(record["publisher_did"], "publisher_did"),
    reader_did: requireString(record["reader_did"], "reader_did"),
    ceremony_id: requireString(record["ceremony_id"], "ceremony_id"),
    group: requireString(record["group"], "group"),
    accepted_offer_digest: requireString(record["accepted_offer_digest"], "accepted_offer_digest"),
    x25519_public_key_sha256: requireString(
      record["x25519_public_key_sha256"],
      "x25519_public_key_sha256",
    ),
    group_epoch: requireInteger(record["group_epoch"], "group_epoch", 0),
    issued_at: requireString(record["issued_at"], "issued_at"),
    expires_at: requireString(record["expires_at"], "expires_at"),
    signature_b64: requireString(record["signature_b64"], "signature_b64", "statement_invalid", true),
  };
  validateResponse(response, false);
  return response;
}

function responseWireValue(
  response: EnrollmentResponseV1,
  includeSignature: boolean,
): Record<string, unknown> {
  const value: Record<string, unknown> = {
    version: response.version,
    kind: response.kind,
    publisher_did: response.publisher_did,
    reader_did: response.reader_did,
    ceremony_id: response.ceremony_id,
    group: response.group,
    accepted_offer_digest: response.accepted_offer_digest,
    x25519_public_key_sha256: response.x25519_public_key_sha256,
    group_epoch: response.group_epoch,
    issued_at: response.issued_at,
    expires_at: response.expires_at,
  };
  if (includeSignature) value["signature_b64"] = response.signature_b64;
  return value;
}

/** Canonical bytes of the response minus its signature — the signing domain. */
export function enrollmentResponseSigningBytes(response: EnrollmentResponseV1): Uint8Array {
  validateResponse(response, true);
  return canonicalize(responseWireValue(response, false));
}

/** `sha256:` digest over the complete signed response bytes. */
export function enrollmentResponseDigest(response: EnrollmentResponseV1): string {
  validateResponse(response, true);
  return sha256Digest(canonicalize(responseWireValue(response, true)));
}

/** Sign a response with the publisher's device key (must match `publisher_did`). */
export function signEnrollmentResponse(
  response: EnrollmentResponseV1,
  key: DeviceKey,
): EnrollmentResponseV1 {
  validateResponse(response, true);
  ensureSigningKey(key, response.publisher_did);
  return { ...response, signature_b64: signBytes(key, enrollmentResponseSigningBytes(response)) };
}

/** Verify an accepted-enrollment response against the reader's expectations. */
export function verifyEnrollmentResponse(
  response: EnrollmentResponseV1,
  expected: {
    publisherDid: string;
    readerDid: string;
    ceremonyId: string;
    group: string;
    offerDigest: string;
    publicKeySha256: string;
    now: string;
  },
): void {
  validateResponse(response, false);
  validateDid(expected.publisherDid, "expected_publisher_did");
  validateDid(expected.readerDid, "expected_reader_did");
  if (response.publisher_did !== expected.publisherDid) {
    throw error("did_signer_mismatch", "response publisher does not match the expected publisher");
  }
  if (response.reader_did !== expected.readerDid) {
    throw error("wrong_recipient", "response names a different reader");
  }
  if (response.ceremony_id !== expected.ceremonyId || response.group !== expected.group) {
    throw error("scope_mismatch", "response ceremony or group does not match");
  }
  validateDigest(expected.offerDigest, "expected_offer_digest", "binding_invalid");
  validateDigest(expected.publicKeySha256, "expected_public_key_sha256", "binding_invalid");
  if (response.accepted_offer_digest !== expected.offerDigest) {
    throw error("binding_invalid", "response names a different accepted offer");
  }
  if (response.x25519_public_key_sha256 !== expected.publicKeySha256) {
    throw error("binding_invalid", "response names a different X25519 key");
  }
  validateFreshness(response.issued_at, response.expires_at, expected.now);
  const signature = signatureBytes(response.signature_b64, false) as Uint8Array;
  verifyEd25519DidSignature(
    response.publisher_did,
    enrollmentResponseSigningBytes(response),
    signature,
  );
}

// ── HIBE reader proof creation ──────────────────────────────────────

/**
 * Answer a HIBE authority's scoped challenge with a signed `hibe-reader`
 * key-binding proof. Verifies the challenge signature against its embedded
 * publisher DID and requires this reader to be the named recipient before
 * anything is signed.
 */
export async function createHibeReaderProof(
  challenge: EnrollmentChallengeV1,
  reader: DeviceKey,
  opts: { now?: string } = {},
): Promise<KeyBindingProofV1> {
  const now = opts.now ?? formatTrustTimestamp(Date.now() * 1000);
  validateChallenge(challenge, false);
  if (challenge.expected_reader_did !== reader.did) {
    throw error("wrong_recipient", "challenge names a different reader");
  }
  verifyEnrollmentChallenge(challenge, {
    publisherDid: challenge.publisher_did,
    readerDid: reader.did,
    ceremonyId: challenge.ceremony_id,
    group: challenge.group,
    now,
  });
  const proof: KeyBindingProofV1 = {
    version: 1,
    purpose: "hibe-reader",
    subject_did: reader.did,
    audience_did: challenge.publisher_did,
    ceremony_id: challenge.ceremony_id,
    group: challenge.group,
    issued_at: now,
    expires_at: challenge.expires_at,
    nonce_b64: bytesToB64(randomBytes(32)),
    binding: {
      algorithm: "Ed25519-did-key",
      delivery: "recipient-seal-v1",
      challenge_digest: enrollmentChallengeDigest(challenge),
    },
    signature_b64: "",
  };
  return signKeyBindingProof(proof, reader);
}
