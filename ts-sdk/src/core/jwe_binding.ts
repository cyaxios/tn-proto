// Public-only JWE recipient binding sources.
//
// DID documents arrive here only after a caller-controlled DID-method
// resolver has authenticated them. This module never fetches a DID document
// and never treats arbitrary JSON as authenticated resolution output.

import { canonicalize } from "./canonical.js";
import { b64ToBytes, bytesToB64 } from "./encoding.js";
import {
  formatTrustTimestamp,
  parseTrustTimestamp,
  sha256Digest,
  TrustError,
  type AcceptedOffer,
} from "./trust.js";

export interface ResolvedX25519KeyAgreement {
  did: string;
  verificationMethodId: string;
  publicKey: Uint8Array;
  publicKeySha256: string;
}

export interface JweBindingScope {
  audienceDid: string;
  ceremonyId: string;
  group: string;
  now: string;
  ttlMs: number;
}

export interface AuthenticatedDidResolution {
  /** Description of the DID method/resolver authentication boundary. */
  resolver: string;
  /** Digest of the resolver result, including verification metadata. */
  resolutionDigest: string;
  /** Digest of the exact DID document passed to extraction. */
  documentDigest: string;
}

export interface FingerprintPin {
  expectedFingerprint: string;
  verifiedBy: string;
  verificationMethod: string;
  /** Evidence reference; only its digest is retained. */
  evidence: string;
}

export type JweBindingEvidence =
  | {
      kind: "signed-key-card";
      offerDigest: string;
      artifactDigest: string;
      proofDigest: string;
    }
  | {
      kind: "challenge-response";
      offerDigest: string;
      artifactDigest: string;
      proofDigest: string;
      challengeDigest: string;
    }
  | {
      kind: "did-document";
      verificationMethodId: string;
      resolver: string;
      resolutionDigest: string;
      documentDigest: string;
    }
  | {
      kind: "fingerprint-pin";
      expectedFingerprint: string;
      verifiedBy: string;
      verificationMethod: string;
      evidenceDigest: string;
    };

export interface VerifiedJweRecipient {
  readerDid: string;
  audienceDid: string;
  ceremonyId: string;
  group: string;
  publicKey: Uint8Array;
  publicKeySha256: string;
  bindingDigest: string;
  issuedAt: string;
  expiresAt: string;
  evidence: JweBindingEvidence;
}

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX = new Map([...B58_ALPHABET].map((char, index) => [char, index]));

function bindingError(detail: string): TrustError {
  return new TrustError("binding_invalid", detail);
}

function didError(detail: string): TrustError {
  return new TrustError("did_invalid", detail);
}

function asRecord(value: unknown, detail: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw bindingError(detail);
  }
  return value as Record<string, unknown>;
}

function requiredString(object: Record<string, unknown>, name: string): string {
  const value = object[name];
  if (typeof value !== "string" || value.length === 0) {
    throw bindingError(`keyAgreement method ${name} must be a string`);
  }
  return value;
}

function base58Decode(value: string): Uint8Array {
  if (value.length === 0) throw bindingError("publicKeyMultibase is not base58btc");
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros += 1;
  const bytes: number[] = [];
  for (const char of value.slice(zeros)) {
    const digit = B58_INDEX.get(char);
    if (digit === undefined) throw bindingError("publicKeyMultibase is not base58btc");
    let carry = digit;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[zeros + i] = bytes[bytes.length - 1 - i]!;
  return out;
}

function base58Encode(value: Uint8Array): string {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === 0) zeros += 1;
  const digits: number[] = [];
  for (const byte of value.slice(zeros)) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i]! << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return (
    "1".repeat(zeros) +
    digits
      .reverse()
      .map((digit) => B58_ALPHABET[digit])
      .join("")
  );
}

function decodeJwk(value: unknown): Uint8Array {
  const jwk = asRecord(value, "publicKeyJwk must be an object");
  if (Object.hasOwn(jwk, "d"))
    throw bindingError("publicKeyJwk must not contain private key material");
  if (jwk["kty"] !== "OKP" || jwk["crv"] !== "X25519") {
    throw bindingError("publicKeyJwk must be an OKP X25519 key");
  }
  const encoded = jwk["x"];
  if (typeof encoded !== "string") throw bindingError("publicKeyJwk.x must be a string");
  if (encoded.includes("=")) throw bindingError("publicKeyJwk.x must be unpadded base64url");
  let bytes: Uint8Array;
  try {
    bytes = b64ToBytes(encoded);
  } catch {
    throw bindingError("publicKeyJwk.x is not canonical base64url");
  }
  const canonical = bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (canonical !== encoded || bytes.length !== 32) {
    throw bindingError("publicKeyJwk.x must encode exactly 32 bytes");
  }
  return bytes;
}

function decodeMultibase(value: unknown): Uint8Array {
  if (typeof value !== "string") throw bindingError("publicKeyMultibase must be a string");
  if (!value.startsWith("z")) throw bindingError("publicKeyMultibase must use base58btc");
  const payload = value.slice(1);
  const decoded = base58Decode(payload);
  if (base58Encode(decoded) !== payload) {
    throw bindingError("publicKeyMultibase is not canonical base58btc");
  }
  if (decoded.length !== 34 || decoded[0] !== 0xec || decoded[1] !== 0x01) {
    throw bindingError("publicKeyMultibase must contain x25519-pub bytes");
  }
  return decoded.slice(2);
}

function parseMethod(
  method: Record<string, unknown>,
  expectedDid: string,
): ResolvedX25519KeyAgreement {
  const id = requiredString(method, "id");
  if (!id.startsWith(`${expectedDid}#`)) {
    throw bindingError("keyAgreement method id is outside the DID subject");
  }
  if (requiredString(method, "controller") !== expectedDid) {
    throw bindingError("keyAgreement method has a different controller");
  }
  const type = requiredString(method, "type");
  const hasJwk = Object.hasOwn(method, "publicKeyJwk");
  const hasMultibase = Object.hasOwn(method, "publicKeyMultibase");
  if (hasJwk && hasMultibase) throw bindingError("keyAgreement method has two key encodings");
  const jwkType = type === "JsonWebKey" || type === "JsonWebKey2020";
  const multikeyType = [
    "Multikey",
    "X25519KeyAgreementKey2019",
    "X25519KeyAgreementKey2020",
  ].includes(type);
  let publicKey: Uint8Array;
  if (hasJwk && jwkType) publicKey = decodeJwk(method["publicKeyJwk"]);
  else if (hasMultibase && multikeyType) publicKey = decodeMultibase(method["publicKeyMultibase"]);
  else throw bindingError("unsupported X25519 keyAgreement method encoding");
  requireUsableKey(publicKey);
  return {
    did: expectedDid,
    verificationMethodId: id,
    publicKey,
    publicKeySha256: sha256Digest(publicKey),
  };
}

function resolveRelationship(
  document: Record<string, unknown>,
  value: unknown,
): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return { ...(value as Record<string, unknown>) };
  }
  if (typeof value !== "string") {
    throw bindingError("keyAgreement entries must be objects or DID URL strings");
  }
  const methods = document["verificationMethod"];
  if (!Array.isArray(methods)) throw bindingError("referenced keyAgreement method is not defined");
  const matches = methods.filter(
    (method) =>
      method !== null &&
      typeof method === "object" &&
      !Array.isArray(method) &&
      (method as Record<string, unknown>)["id"] === value,
  ) as Array<Record<string, unknown>>;
  if (matches.length === 0) throw bindingError("referenced keyAgreement method is not defined");
  if (matches.length > 1) throw bindingError("referenced keyAgreement method is duplicated");
  return { ...matches[0]! };
}

/** Strictly extract one X25519 method authorized by `keyAgreement`. */
export function extractX25519KeyAgreement(
  documentValue: unknown,
  expectedDid: string,
  verificationMethodId?: string,
): ResolvedX25519KeyAgreement {
  const document = asRecord(documentValue, "DID document must be an object");
  if (document["id"] !== expectedDid) {
    throw didError("DID document id does not match the expected DID");
  }
  const relations = document["keyAgreement"];
  if (!Array.isArray(relations))
    throw bindingError("DID document has no keyAgreement relationship");
  const ids = new Set<string>();
  const found: ResolvedX25519KeyAgreement[] = [];
  for (const relation of relations) {
    const parsed = parseMethod(resolveRelationship(document, relation), expectedDid);
    if (ids.has(parsed.verificationMethodId)) {
      throw bindingError("duplicate keyAgreement verification method");
    }
    ids.add(parsed.verificationMethodId);
    if (
      verificationMethodId === undefined ||
      parsed.verificationMethodId === verificationMethodId
    ) {
      found.push(parsed);
    }
  }
  if (found.length === 1) return found[0]!;
  if (found.length === 0 && verificationMethodId !== undefined) {
    throw bindingError("requested keyAgreement method was not found");
  }
  if (found.length === 0)
    throw bindingError("DID document has no usable X25519 keyAgreement method");
  throw bindingError("ambiguous X25519 keyAgreement methods; select one by id");
}

function requireDid(value: string, name: string): void {
  if (!value.startsWith("did:") || /\s/.test(value)) {
    throw didError(`${name} must be a DID`);
  }
}

function requireText(value: string, name: string): void {
  if (value.trim().length === 0) throw bindingError(`${name} must not be empty`);
}

function requireDigest(value: string, name: string): void {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw bindingError(`${name} must contain 64 lowercase hex characters`);
  }
}

function requireUsableKey(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw bindingError("X25519 public key must contain exactly 32 bytes");
  }
  if (value.every((byte) => byte === 0))
    throw bindingError("X25519 public key must not be all zero");
}

function scopeTimes(scope: JweBindingScope): { issuedAt: string; expiresAt: string } {
  requireDid(scope.audienceDid, "audience_did");
  requireText(scope.ceremonyId, "ceremony_id");
  requireText(scope.group, "group");
  if (!Number.isSafeInteger(scope.ttlMs) || scope.ttlMs <= 0) {
    throw bindingError("binding ttl must be greater than zero");
  }
  const issuedMicros = parseTrustTimestamp(scope.now, "now");
  const expiresMicros = issuedMicros + scope.ttlMs * 1000;
  if (!Number.isSafeInteger(expiresMicros)) throw bindingError("binding expiry is out of range");
  return {
    issuedAt: formatTrustTimestamp(issuedMicros),
    expiresAt: formatTrustTimestamp(expiresMicros),
  };
}

function evidenceValue(evidence: JweBindingEvidence): Record<string, unknown> {
  if (evidence.kind === "signed-key-card") {
    return {
      kind: evidence.kind,
      offer_digest: evidence.offerDigest,
      artifact_digest: evidence.artifactDigest,
      proof_digest: evidence.proofDigest,
    };
  }
  if (evidence.kind === "challenge-response") {
    return {
      kind: evidence.kind,
      offer_digest: evidence.offerDigest,
      artifact_digest: evidence.artifactDigest,
      proof_digest: evidence.proofDigest,
      challenge_digest: evidence.challengeDigest,
    };
  }
  if (evidence.kind === "did-document") {
    return {
      kind: evidence.kind,
      verification_method_id: evidence.verificationMethodId,
      resolver: evidence.resolver,
      resolution_digest: evidence.resolutionDigest,
      document_digest: evidence.documentDigest,
    };
  }
  return {
    kind: evidence.kind,
    expected_fingerprint: evidence.expectedFingerprint,
    verified_by: evidence.verifiedBy,
    verification_method: evidence.verificationMethod,
    evidence_digest: evidence.evidenceDigest,
  };
}

function buildBinding(
  readerDid: string,
  publicKeyValue: Uint8Array,
  scope: JweBindingScope,
  evidence: JweBindingEvidence,
): VerifiedJweRecipient {
  requireDid(readerDid, "reader_did");
  requireUsableKey(publicKeyValue);
  const publicKey = new Uint8Array(publicKeyValue);
  const { issuedAt, expiresAt } = scopeTimes(scope);
  const publicKeySha256 = sha256Digest(publicKey);
  const digestValue = {
    reader_did: readerDid,
    audience_did: scope.audienceDid,
    ceremony_id: scope.ceremonyId,
    group: scope.group,
    public_key_sha256: publicKeySha256,
    issued_at: issuedAt,
    expires_at: expiresAt,
    evidence: evidenceValue(evidence),
  };
  return {
    readerDid,
    audienceDid: scope.audienceDid,
    ceremonyId: scope.ceremonyId,
    group: scope.group,
    publicKey,
    publicKeySha256,
    bindingDigest: sha256Digest(canonicalize(digestValue)),
    issuedAt,
    expiresAt,
    evidence,
  };
}

/** Normalize an already accepted signed card or challenge response. */
export function jweRecipientFromAcceptedOffer(accepted: AcceptedOffer): VerifiedJweRecipient {
  const binding = accepted.binding;
  const principal = binding.principal;
  const evidence: JweBindingEvidence =
    binding.challengeDigest === null
      ? {
          kind: "signed-key-card",
          offerDigest: accepted.offerDigest,
          artifactDigest: accepted.artifactDigest,
          proofDigest: binding.proofDigest,
        }
      : {
          kind: "challenge-response",
          offerDigest: accepted.offerDigest,
          artifactDigest: accepted.artifactDigest,
          proofDigest: binding.proofDigest,
          challengeDigest: binding.challengeDigest,
        };
  return {
    readerDid: principal.did,
    audienceDid: principal.audienceDid,
    ceremonyId: principal.ceremonyId,
    group: principal.group,
    publicKey: new Uint8Array(binding.publicKey),
    publicKeySha256: binding.publicKeySha256,
    bindingDigest: accepted.offerDigest,
    issuedAt: principal.issuedAt,
    expiresAt: principal.expiresAt,
    evidence,
  };
}

/** Normalize an extracted key plus caller-authenticated resolver evidence. */
export function jweRecipientFromDidResolution(
  resolved: ResolvedX25519KeyAgreement,
  scope: JweBindingScope,
  evidence: AuthenticatedDidResolution,
): VerifiedJweRecipient {
  if (!resolved.verificationMethodId.startsWith(`${resolved.did}#`)) {
    throw bindingError("verification method does not belong to the resolved DID");
  }
  requireText(evidence.resolver, "resolver");
  requireDigest(evidence.resolutionDigest, "resolution_digest");
  requireDigest(evidence.documentDigest, "document_digest");
  requireUsableKey(resolved.publicKey);
  if (sha256Digest(resolved.publicKey) !== resolved.publicKeySha256) {
    throw bindingError("public key digest does not match the X25519 key");
  }
  return buildBinding(resolved.did, resolved.publicKey, scope, {
    kind: "did-document",
    verificationMethodId: resolved.verificationMethodId,
    resolver: evidence.resolver,
    resolutionDigest: evidence.resolutionDigest,
    documentDigest: evidence.documentDigest,
  });
}

/** Extract and normalize one key from authenticated DID resolution output. */
export function jweRecipientFromAuthenticatedDidDocument(opts: {
  document: unknown;
  expectedDid: string;
  verificationMethodId?: string;
  scope: JweBindingScope;
  evidence: AuthenticatedDidResolution;
}): VerifiedJweRecipient {
  requireText(opts.evidence.resolver, "resolver");
  requireDigest(opts.evidence.resolutionDigest, "resolution_digest");
  requireDigest(opts.evidence.documentDigest, "document_digest");
  if (sha256Digest(canonicalize(opts.document)) !== opts.evidence.documentDigest) {
    throw bindingError("document_digest does not match the exact DID document");
  }
  const resolved = extractX25519KeyAgreement(
    opts.document,
    opts.expectedDid,
    opts.verificationMethodId,
  );
  return jweRecipientFromDidResolution(resolved, opts.scope, opts.evidence);
}

/** Normalize an X25519 key whose fingerprint was explicitly compared. */
export function jweRecipientFromFingerprintPin(opts: {
  readerDid: string;
  publicKey: Uint8Array;
  scope: JweBindingScope;
  pin: FingerprintPin;
}): VerifiedJweRecipient {
  requireDigest(opts.pin.expectedFingerprint, "expected_fingerprint");
  requireUsableKey(opts.publicKey);
  if (sha256Digest(opts.publicKey) !== opts.pin.expectedFingerprint) {
    throw bindingError("pinned fingerprint does not match the X25519 public key");
  }
  requireText(opts.pin.verifiedBy, "verified_by");
  requireText(opts.pin.verificationMethod, "verification_method");
  requireText(opts.pin.evidence, "evidence");
  return buildBinding(opts.readerDid, opts.publicKey, opts.scope, {
    kind: "fingerprint-pin",
    expectedFingerprint: opts.pin.expectedFingerprint,
    verifiedBy: opts.pin.verifiedBy,
    verificationMethod: opts.pin.verificationMethod,
    evidenceDigest: sha256Digest(new TextEncoder().encode(opts.pin.evidence)),
  });
}
