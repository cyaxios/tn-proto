import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { x25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../core/canonical.js";
import {
  jweBindingEvidenceValue,
  validateVerifiedJweRecipient,
  type VerifiedJweRecipient,
} from "../core/jwe_binding.js";
import {
  TrustError,
  formatTrustTimestamp,
  parseEd25519DidKey,
  parseTrustTimestamp,
  sha256Digest,
  type TrustReason,
} from "../core/trust.js";

const RECIPIENTS_FILE = "jwe_recipients.v1.json";
const EXPECTATIONS_FILE = "jwe_activation_expectations.v1.json";

export interface JweActivationExpectation {
  publisherDid: string;
  readerDid: string;
  ceremonyId: string;
  group: string;
  x25519PublicKeySha256: string;
  bindingDigest: string;
  issuedAt: string;
  expiresAt: string;
}

export interface ExpectJweActivationOptions {
  publisherDid: string;
  readerDid: string;
  ceremonyId: string;
  group: string;
  x25519PublicKeySha256: string;
  bindingDigest: string;
  expiresAt: string;
  now?: string;
}

function trustError(reason: TrustReason, message: string): TrustError {
  return new TrustError(reason, message);
}

function requireDigest(value: string, name: string): void {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw trustError("binding_invalid", `${name} must be a canonical sha256 digest`);
  }
}

function requireText(value: string, name: string): void {
  if (!value || value !== value.trim()) {
    throw trustError("statement_invalid", `${name} must be nonempty canonical text`);
  }
}

function requireGroup(group: string): string {
  if (
    !group ||
    group !== group.trim() ||
    /[\\/\0]/.test(group) ||
    group === "." ||
    group === ".."
  ) {
    throw trustError("scope_mismatch", "JWE group is not a safe keystore component");
  }
  return group;
}

function readObject(path: string, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw trustError("statement_invalid", `${label} is unreadable`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw trustError("statement_invalid", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function atomicWrite(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, canonicalize(value));
  renameSync(tmp, path);
}

export function jweRecipientTrustPath(keystoreDir: string): string {
  return join(keystoreDir, "trust", RECIPIENTS_FILE);
}

export function jweActivationExpectationsPath(keystoreDir: string): string {
  return join(keystoreDir, "trust", EXPECTATIONS_FILE);
}

function recipientRecord(binding: VerifiedJweRecipient): Record<string, unknown> {
  const evidence = jweBindingEvidenceValue(binding.evidence);
  return {
    verified: true,
    public_key_sha256: binding.publicKeySha256,
    binding_digest: binding.bindingDigest,
    issued_at: binding.issuedAt,
    expires_at: binding.expiresAt,
    evidence_kind: binding.evidence.kind,
    evidence,
    ...(binding.evidence.kind === "signed-key-card" ||
    binding.evidence.kind === "challenge-response"
      ? {
          offer_digest: binding.evidence.offerDigest,
          artifact_digest: binding.evidence.artifactDigest,
          proof_digest: binding.evidence.proofDigest,
          ...(binding.evidence.kind === "challenge-response"
            ? { challenge_digest: binding.evidence.challengeDigest }
            : {}),
        }
      : {}),
  };
}

function recipientRegistry(path: string): Record<string, unknown> {
  if (!existsSync(path)) return { version: 1, recipients: {} };
  const doc = readObject(path, "verified JWE recipient registry");
  if (doc["version"] !== 1) throw trustError("statement_invalid", "unsupported registry version");
  const recipients = doc["recipients"];
  if (recipients === null || typeof recipients !== "object" || Array.isArray(recipients)) {
    throw trustError("statement_invalid", "verified JWE recipient registry is malformed");
  }
  return doc;
}

/** Commit public trust metadata before the recipient becomes active. */
export function storeVerifiedJweRecipient(
  keystoreDir: string,
  recipient: VerifiedJweRecipient,
): void {
  const binding = validateVerifiedJweRecipient(recipient);
  const path = jweRecipientTrustPath(keystoreDir);
  const doc = recipientRegistry(path);
  const recipients = doc["recipients"] as Record<string, unknown>;
  const groupValue = recipients[binding.group] ?? {};
  if (groupValue === null || typeof groupValue !== "object" || Array.isArray(groupValue)) {
    throw trustError("statement_invalid", "verified JWE group registry is malformed");
  }
  const group = groupValue as Record<string, unknown>;
  const record = recipientRecord(binding);
  const old = group[binding.readerDid];
  if (old !== undefined) {
    const oldRecord = readRegistryRecord(old);
    if (oldRecord["public_key_sha256"] !== binding.publicKeySha256) {
      throw trustError("replay_conflict", "a different JWE key is already registered for this DID");
    }
  }
  group[binding.readerDid] = record;
  recipients[binding.group] = group;
  atomicWrite(path, { version: 1, recipients });
}

function readRegistryRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw trustError("statement_invalid", "verified JWE recipient record is malformed");
  }
  return value as Record<string, unknown>;
}

function expectationValue(record: JweActivationExpectation): Record<string, unknown> {
  return {
    publisher_did: record.publisherDid,
    reader_did: record.readerDid,
    ceremony_id: record.ceremonyId,
    group: record.group,
    x25519_public_key_sha256: record.x25519PublicKeySha256,
    binding_digest: record.bindingDigest,
    issued_at: record.issuedAt,
    expires_at: record.expiresAt,
  };
}

function expectationFromValue(value: unknown): JweActivationExpectation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw trustError("statement_invalid", "JWE activation expectation is malformed");
  }
  const row = value as Record<string, unknown>;
  const text = (name: string): string => {
    const item = row[name];
    if (typeof item !== "string") throw trustError("statement_invalid", "expectation is malformed");
    return item;
  };
  const record = {
    publisherDid: text("publisher_did"),
    readerDid: text("reader_did"),
    ceremonyId: text("ceremony_id"),
    group: text("group"),
    x25519PublicKeySha256: text("x25519_public_key_sha256"),
    bindingDigest: text("binding_digest"),
    issuedAt: text("issued_at"),
    expiresAt: text("expires_at"),
  };
  parseEd25519DidKey(record.publisherDid);
  parseEd25519DidKey(record.readerDid);
  requireText(record.ceremonyId, "ceremony_id");
  requireGroup(record.group);
  requireDigest(record.x25519PublicKeySha256, "x25519_public_key_sha256");
  requireDigest(record.bindingDigest, "binding_digest");
  const issued = parseTrustTimestamp(record.issuedAt, "issued_at");
  const expires = parseTrustTimestamp(record.expiresAt, "expires_at");
  if (issued >= expires) throw trustError("statement_invalid", "expectation times are reversed");
  return record;
}

function sameExpectationPin(
  left: JweActivationExpectation,
  right: JweActivationExpectation,
): boolean {
  return (
    left.publisherDid === right.publisherDid &&
    left.readerDid === right.readerDid &&
    left.ceremonyId === right.ceremonyId &&
    left.group === right.group &&
    left.x25519PublicKeySha256 === right.x25519PublicKeySha256 &&
    left.bindingDigest === right.bindingDigest &&
    left.expiresAt === right.expiresAt
  );
}

function localPublicKeyDigest(keystoreDir: string, group: string): string {
  const path = join(keystoreDir, `${requireGroup(group)}.jwe.mykey`);
  if (!existsSync(path)) throw trustError("binding_invalid", "local JWE reader key is missing");
  const privateKey = new Uint8Array(readFileSync(path));
  try {
    if (privateKey.length !== 32) {
      throw trustError("binding_invalid", "local JWE reader key is malformed");
    }
    return sha256Digest(x25519.getPublicKey(privateKey));
  } finally {
    privateKey.fill(0);
  }
}

function expectationRecord(
  keystoreDir: string,
  opts: ExpectJweActivationOptions,
): JweActivationExpectation {
  parseEd25519DidKey(opts.publisherDid);
  parseEd25519DidKey(opts.readerDid);
  requireText(opts.ceremonyId, "ceremony_id");
  requireDigest(opts.bindingDigest, "binding_digest");
  requireDigest(opts.x25519PublicKeySha256, "x25519_public_key_sha256");
  if (localPublicKeyDigest(keystoreDir, opts.group) !== opts.x25519PublicKeySha256) {
    throw trustError("binding_invalid", "local JWE reader key digest does not match expectation");
  }
  const issuedAt = opts.now ?? formatTrustTimestamp(Date.now() * 1000);
  if (parseTrustTimestamp(opts.expiresAt, "expires_at") <= parseTrustTimestamp(issuedAt, "now")) {
    throw trustError("statement_expired", "JWE activation expectation has expired");
  }
  return {
    publisherDid: opts.publisherDid,
    readerDid: opts.readerDid,
    ceremonyId: opts.ceremonyId,
    group: opts.group,
    x25519PublicKeySha256: opts.x25519PublicKeySha256,
    bindingDigest: opts.bindingDigest,
    issuedAt,
    expiresAt: opts.expiresAt,
  };
}

function expectationMap(path: string): Record<string, unknown> {
  if (!existsSync(path)) return {};
  const doc = readObject(path, "JWE activation expectation registry");
  const expectations = doc["expectations"];
  if (
    doc["version"] !== 1 ||
    expectations === null ||
    typeof expectations !== "object" ||
    Array.isArray(expectations)
  ) {
    throw trustError("statement_invalid", "JWE activation expectation registry is malformed");
  }
  return expectations as Record<string, unknown>;
}

/** Explicitly approve one direct binding against this reader's local key. */
export function recordJweActivationExpectation(
  keystoreDir: string,
  opts: ExpectJweActivationOptions,
): JweActivationExpectation {
  const record = expectationRecord(keystoreDir, opts);
  const path = jweActivationExpectationsPath(keystoreDir);
  const expectations = expectationMap(path);
  const value = expectationValue(record);
  const existing = expectations[record.bindingDigest];
  if (existing !== undefined) {
    const retained = expectationFromValue(existing);
    if (!sameExpectationPin(retained, record)) {
      throw trustError("replay_conflict", "a conflicting JWE activation expectation exists");
    }
    return retained;
  }
  expectations[record.bindingDigest] = value;
  atomicWrite(path, { version: 1, expectations });
  return record;
}

export function loadJweActivationExpectation(
  keystoreDir: string,
  bindingDigest: string,
): JweActivationExpectation | null {
  requireDigest(bindingDigest, "binding_digest");
  const path = jweActivationExpectationsPath(keystoreDir);
  if (!existsSync(path)) return null;
  const value = expectationMap(path)[bindingDigest];
  if (value === undefined) return null;
  const record = expectationFromValue(value);
  if (record.bindingDigest !== bindingDigest) {
    throw trustError("replay_conflict", "expectation key does not match its binding digest");
  }
  return record;
}
