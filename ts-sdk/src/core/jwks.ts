import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { x25519 } from "@noble/curves/ed25519";

import { bytesToB64 } from "./encoding.js";
import {
  jweRecipientFromFingerprintPin,
  type JweBindingScope,
  type VerifiedJweRecipient,
} from "./jwe_binding.js";
import type { DeviceKey } from "./signing.js";
import { sha256Digest } from "./trust.js";

export type TnJwksKeyUse = "sig" | "enc";
export type TnJwksKeyStatus = "active" | "retiring" | "retired";
export type TnJwksTrustPolicy = "hosted" | "did_bound" | "tofu" | "pinned";

export const TN_JWKS_KEY_SELECTED_EVENT = "tn.jwks.key_selected";

export interface TnJwksKey {
  kty: "OKP";
  crv: "Ed25519" | "X25519";
  kid: string;
  use: TnJwksKeyUse;
  alg: "EdDSA" | "ECDH-ES+A256KW";
  x: string;
  tn_status?: TnJwksKeyStatus;
  tn_fingerprint?: string;
}

export interface TnJwksDocument {
  issuer: string;
  issued_at?: string;
  expires_at?: string;
  keys: TnJwksKey[];
}

export interface LocalDeviceJwksOptions {
  issuer?: string;
  kid?: string;
  issuedAt?: string;
  expiresAt?: string;
}

export interface LocalJweEncryptionKeyOptions {
  kid?: string;
  status?: TnJwksKeyStatus;
}

export interface TnSelectedJwksEncryptionKey {
  issuer: string;
  kid: string;
  jwk: TnJwksKey;
  fingerprint: string;
}

export interface TnJwksEncryptionRecipient {
  publicKey: Uint8Array;
  kid: string;
}

export interface TnTrustedJwksEncryptionRecipient {
  issuer: string;
  kid: string;
  publicKey: Uint8Array;
  keyFingerprint: string;
  jwksFingerprint: string;
  trust: TnJwksTrustDecision;
}

export interface TnJwksKeySelectedEvent {
  issuer: string;
  encryption_kid: string;
  encryption_key_fingerprint: string;
  jwks_fingerprint: string;
  trust_policy: TnJwksTrustPolicy;
  trust_reason: TnJwksTrustDecision["reason"];
  selected_at: string;
  jwks_url?: string;
  signing_kid?: string;
  signing_key_fingerprint?: string;
}

export interface TnJwksKeySelectedEventOptions {
  selectedAt?: string;
  jwksUrl?: string;
  signingKid?: string;
  signingKeyFingerprint?: string;
}

export interface TnJwksVerifiedRecipientOptions {
  scope: JweBindingScope;
  verifiedBy?: string;
  verificationMethod?: string;
  evidence?: string;
}

export interface TnJwksPinnedTrust {
  issuer: string;
  jwksFingerprint: string;
}

export interface TnJwksTrustInput {
  policy: TnJwksTrustPolicy;
  pinned?: TnJwksPinnedTrust;
}

export interface TnJwksTrustDecision {
  trusted: boolean;
  policy: TnJwksTrustPolicy;
  issuer: string;
  jwksFingerprint: string;
  reason:
    | "pin-created"
    | "pin-match"
    | "pin-missing"
    | "issuer-mismatch"
    | "fingerprint-mismatch"
    | "policy-unsupported";
  pin?: TnJwksPinnedTrust;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`jwks: ${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(record: Record<string, unknown>, key: string, label: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`jwks: ${label}.${key} must be a non-empty string`);
  }
  return value;
}

function optionalString(record: Record<string, unknown>, key: string, label: string): string | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`jwks: ${label}.${key} must be a non-empty string when present`);
  }
  return value;
}

function validateIsoDate(value: string | undefined, label: string): void {
  if (value === undefined) return;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`jwks: ${label} must be an ISO timestamp`);
  }
}

function base64UrlDecode(value: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`jwks: ${label} must be base64url without padding`);
  }
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function validateKeyMaterial(key: TnJwksKey): void {
  const publicKey = base64UrlDecode(key.x, `${key.kid}.x`);
  if (publicKey.length !== 32) {
    throw new Error(`jwks: ${key.kid}.x must decode to 32 raw public-key bytes`);
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function parseKey(value: unknown, index: number): TnJwksKey {
  const record = asRecord(value, `keys[${index}]`);
  const kty = requiredString(record, "kty", `keys[${index}]`);
  const crv = requiredString(record, "crv", `keys[${index}]`);
  const kid = requiredString(record, "kid", `keys[${index}]`);
  const use = requiredString(record, "use", `keys[${index}]`);
  const alg = requiredString(record, "alg", `keys[${index}]`);
  const x = requiredString(record, "x", `keys[${index}]`);
  const tnStatus = optionalString(record, "tn_status", `keys[${index}]`);
  const tnFingerprint = optionalString(record, "tn_fingerprint", `keys[${index}]`);

  if (kty !== "OKP") throw new Error(`jwks: ${kid}.kty must be "OKP"`);
  if (crv !== "Ed25519" && crv !== "X25519") {
    throw new Error(`jwks: ${kid}.crv must be "Ed25519" or "X25519"`);
  }
  if (use !== "sig" && use !== "enc") {
    throw new Error(`jwks: ${kid}.use must be "sig" or "enc"`);
  }
  if (alg !== "EdDSA" && alg !== "ECDH-ES+A256KW") {
    throw new Error(`jwks: ${kid}.alg must be "EdDSA" or "ECDH-ES+A256KW"`);
  }
  if (tnStatus !== undefined && tnStatus !== "active" && tnStatus !== "retiring" && tnStatus !== "retired") {
    throw new Error(`jwks: ${kid}.tn_status must be active, retiring, or retired`);
  }

  if (use === "sig" && (crv !== "Ed25519" || alg !== "EdDSA")) {
    throw new Error(`jwks: ${kid} signing keys must use Ed25519/EdDSA`);
  }
  if (use === "enc" && (crv !== "X25519" || alg !== "ECDH-ES+A256KW")) {
    throw new Error(`jwks: ${kid} encryption keys must use X25519/ECDH-ES+A256KW`);
  }

  const key: TnJwksKey = {
    kty,
    crv,
    kid,
    use,
    alg,
    x,
    ...(tnStatus === undefined ? {} : { tn_status: tnStatus }),
    ...(tnFingerprint === undefined ? {} : { tn_fingerprint: tnFingerprint }),
  };
  validateKeyMaterial(key);
  return key;
}

function publicKeyThumbprintInput(key: TnJwksKey): string {
  return JSON.stringify({
    crv: key.crv,
    kty: key.kty,
    x: key.x,
  });
}

function jwksFingerprintInput(jwks: TnJwksDocument): string {
  return JSON.stringify({
    issuer: jwks.issuer,
    keys: jwks.keys
      .map((key) => ({
        alg: key.alg,
        crv: key.crv,
        kid: key.kid,
        kty: key.kty,
        use: key.use,
        x: key.x,
      }))
      .sort((a, b) => a.kid.localeCompare(b.kid)),
  });
}

export function jwksKeyFingerprint(key: TnJwksKey): string {
  return `sha256:${bytesToHex(sha256(new TextEncoder().encode(publicKeyThumbprintInput(key))))}`;
}

export function jwksDocumentFingerprint(jwks: TnJwksDocument): string {
  return `sha256:${bytesToHex(sha256(new TextEncoder().encode(jwksFingerprintInput(jwks))))}`;
}

export function jwksPublicKeyBytes(key: TnJwksKey): Uint8Array {
  return base64UrlDecode(key.x, `${key.kid}.x`);
}

export function parseTnJwks(value: unknown): TnJwksDocument {
  const record = asRecord(value, "document");
  const issuer = requiredString(record, "issuer", "document");
  const issuedAt = optionalString(record, "issued_at", "document");
  const expiresAt = optionalString(record, "expires_at", "document");
  validateIsoDate(issuedAt, "document.issued_at");
  validateIsoDate(expiresAt, "document.expires_at");

  const keysValue = record["keys"];
  if (!Array.isArray(keysValue)) {
    throw new Error("jwks: document.keys must be an array");
  }
  if (keysValue.length === 0) {
    throw new Error("jwks: document.keys must not be empty");
  }

  const keys = keysValue.map((key, index) => parseKey(key, index));
  const kids = new Set<string>();
  for (const key of keys) {
    if (kids.has(key.kid)) throw new Error(`jwks: duplicate kid ${JSON.stringify(key.kid)}`);
    kids.add(key.kid);
    if (key.tn_fingerprint !== undefined && key.tn_fingerprint !== jwksKeyFingerprint(key)) {
      throw new Error(`jwks: ${key.kid}.tn_fingerprint does not match key material`);
    }
  }

  return {
    issuer,
    ...(issuedAt === undefined ? {} : { issued_at: issuedAt }),
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
    keys,
  };
}

/**
 * Build a TN JWKS document for the local device's public signing key.
 *
 * This intentionally exports only public Ed25519 signing material. Recipient
 * encryption JWKS uses X25519 keys and should be generated/managed separately.
 */
export function localDeviceJwks(
  device: Pick<DeviceKey, "did" | "publicKey">,
  options: LocalDeviceJwksOptions = {},
): TnJwksDocument {
  const key: TnJwksKey = {
    kty: "OKP",
    crv: "Ed25519",
    kid: options.kid ?? "device-signing-current",
    use: "sig",
    alg: "EdDSA",
    x: base64UrlEncode(device.publicKey),
    tn_status: "active",
  };
  const withFingerprint: TnJwksKey = {
    ...key,
    tn_fingerprint: jwksKeyFingerprint(key),
  };
  return parseTnJwks({
    issuer: options.issuer ?? device.did,
    ...(options.issuedAt === undefined ? {} : { issued_at: options.issuedAt }),
    ...(options.expiresAt === undefined ? {} : { expires_at: options.expiresAt }),
    keys: [withFingerprint],
  });
}

/** Convert a local JWE/X25519 private reader key into a public JWKS entry. */
export function localJweEncryptionJwksKey(
  group: string,
  privateKey: Uint8Array,
  options: LocalJweEncryptionKeyOptions = {},
): TnJwksKey {
  if (privateKey.length !== 32) {
    throw new Error(`jwks: ${group}.jwe.mykey must be 32 raw X25519 bytes, got ${privateKey.length}`);
  }
  const key: TnJwksKey = {
    kty: "OKP",
    crv: "X25519",
    kid: options.kid ?? `${group}-jwe-current`,
    use: "enc",
    alg: "ECDH-ES+A256KW",
    x: base64UrlEncode(x25519.getPublicKey(privateKey)),
    tn_status: options.status ?? "active",
  };
  return {
    ...key,
    tn_fingerprint: jwksKeyFingerprint(key),
  };
}

export function selectActiveJwksEncryptionKey(jwks: TnJwksDocument): TnSelectedJwksEncryptionKey {
  const active = jwks.keys.filter((key) => key.use === "enc" && (key.tn_status ?? "active") === "active");
  if (active.length === 0) {
    throw new Error("jwks: no active encryption key");
  }
  if (active.length > 1) {
    throw new Error("jwks: multiple active encryption keys; pass an explicit kid before using this key set");
  }
  const key = active[0];
  if (key === undefined) throw new Error("jwks: no active encryption key");
  return {
    issuer: jwks.issuer,
    kid: key.kid,
    jwk: key,
    fingerprint: jwksKeyFingerprint(key),
  };
}

export function jwksEncryptionRecipient(
  selected: TnSelectedJwksEncryptionKey,
): TnJwksEncryptionRecipient {
  return {
    publicKey: jwksPublicKeyBytes(selected.jwk),
    kid: selected.kid,
  };
}

export function trustedJwksEncryptionRecipient(
  value: unknown,
  trustInput: TnJwksTrustInput,
): TnTrustedJwksEncryptionRecipient {
  const jwks = parseTnJwks(value);
  const trust = evaluateJwksTrust(jwks, trustInput);
  if (!trust.trusted) {
    throw new Error(`jwks: key set is not trusted (${trust.reason})`);
  }
  const selected = selectActiveJwksEncryptionKey(jwks);
  const recipient = jwksEncryptionRecipient(selected);
  return {
    issuer: selected.issuer,
    kid: selected.kid,
    publicKey: recipient.publicKey,
    keyFingerprint: selected.fingerprint,
    jwksFingerprint: trust.jwksFingerprint,
    trust,
  };
}

export function jwksKeySelectedEvent(
  recipient: TnTrustedJwksEncryptionRecipient,
  options: TnJwksKeySelectedEventOptions = {},
): TnJwksKeySelectedEvent {
  return {
    issuer: recipient.issuer,
    encryption_kid: recipient.kid,
    encryption_key_fingerprint: recipient.keyFingerprint,
    jwks_fingerprint: recipient.jwksFingerprint,
    trust_policy: recipient.trust.policy,
    trust_reason: recipient.trust.reason,
    selected_at: options.selectedAt ?? new Date().toISOString(),
    ...(options.jwksUrl === undefined ? {} : { jwks_url: options.jwksUrl }),
    ...(options.signingKid === undefined ? {} : { signing_kid: options.signingKid }),
    ...(options.signingKeyFingerprint === undefined
      ? {}
      : { signing_key_fingerprint: options.signingKeyFingerprint }),
  };
}

export function verifiedJweRecipientFromTrustedJwks(
  recipient: TnTrustedJwksEncryptionRecipient,
  options: TnJwksVerifiedRecipientOptions,
): VerifiedJweRecipient {
  const evidence =
    options.evidence ??
    JSON.stringify({
      issuer: recipient.issuer,
      encryption_kid: recipient.kid,
      encryption_key_fingerprint: recipient.keyFingerprint,
      jwks_fingerprint: recipient.jwksFingerprint,
      trust_policy: recipient.trust.policy,
      trust_reason: recipient.trust.reason,
    });

  return jweRecipientFromFingerprintPin({
    readerDid: recipient.issuer,
    publicKey: recipient.publicKey,
    scope: options.scope,
    pin: {
      expectedFingerprint: sha256Digest(recipient.publicKey),
      verifiedBy: options.verifiedBy ?? "tn-jwks-pin",
      verificationMethod: options.verificationMethod ?? "jwks-document-fingerprint",
      evidence,
    },
  });
}

export function evaluateJwksTrust(
  jwks: TnJwksDocument,
  input: TnJwksTrustInput,
): TnJwksTrustDecision {
  const jwksFingerprint = jwksDocumentFingerprint(jwks);

  if (input.policy === "tofu") {
    const pin = { issuer: jwks.issuer, jwksFingerprint };
    return {
      trusted: true,
      policy: "tofu",
      issuer: jwks.issuer,
      jwksFingerprint,
      reason: "pin-created",
      pin,
    };
  }

  if (input.policy === "hosted" || input.policy === "did_bound") {
    return {
      trusted: false,
      policy: input.policy,
      issuer: jwks.issuer,
      jwksFingerprint,
      reason: "policy-unsupported",
    };
  }

  const pinned = input.pinned;
  if (pinned === undefined) {
    return {
      trusted: false,
      policy: "pinned",
      issuer: jwks.issuer,
      jwksFingerprint,
      reason: "pin-missing",
    };
  }
  if (pinned.issuer !== jwks.issuer) {
    return {
      trusted: false,
      policy: "pinned",
      issuer: jwks.issuer,
      jwksFingerprint,
      reason: "issuer-mismatch",
      pin: pinned,
    };
  }
  if (pinned.jwksFingerprint !== jwksFingerprint) {
    return {
      trusted: false,
      policy: "pinned",
      issuer: jwks.issuer,
      jwksFingerprint,
      reason: "fingerprint-mismatch",
      pin: pinned,
    };
  }
  return {
    trusted: true,
    policy: "pinned",
    issuer: jwks.issuer,
    jwksFingerprint,
    reason: "pin-match",
    pin: pinned,
  };
}
