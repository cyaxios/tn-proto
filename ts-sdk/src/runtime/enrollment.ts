// Receiver-local trusted enrollment challenge and pending-offer state.
//
// Node-side port of `python/tn/enrollment.py` (the locked version-1 state
// layout) plus the reader-side offer/response producers the public
// PkgNamespace verbs build on. One private state root holds separate
// `challenges/`, `offers/`, `approvals/`, `consumed/`, `accepted/`, and
// `preauthorized/` trees plus one `enrollment.lock`. Challenge consumption,
// exact-digest approval, and promotion are serialized under that
// cross-process lock; writes are same-directory temp files with atomic
// replacement, and no mutation happens before validation passes.

import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join, resolve as pathResolve } from "node:path";

import { type UnzipFileInfo, unzipSync } from "fflate";
import { x25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../core/canonical.js";
import { b64ToBytes, bytesToB64, randomBytes } from "../core/encoding.js";
import { didKeyToX25519Pub, ed25519SeedToX25519Priv } from "../core/recipient_seal.js";
import {
  jweActivationReferenceDigest,
  jweRecipientFromAcceptedOffer,
  validateVerifiedJweRecipient,
  type VerifiedJweRecipient,
} from "../core/jwe_binding.js";
import { type DeviceKey } from "../core/signing.js";
import {
  type Manifest,
  type TnPackage,
  isManifestSignatureValid,
  newManifest,
  parseTnPackage,
  signManifestWithBody,
  tnPackageWireValue,
  signTnPackage,
  verifyTnPackageSignature,
} from "../core/tnpkg.js";
import {
  type AcceptedOffer,
  type EnrollmentChallengeV1,
  type EnrollmentResponseV1,
  type KeyBindingProofV1,
  type VerifiedJweBinding,
  TrustError,
  enrollmentChallengeDigest,
  enrollmentResponseDigest,
  formatTrustTimestamp,
  keyBindingProofDigest,
  parseEd25519DidKey,
  parseEnrollmentChallenge,
  parseEnrollmentResponse,
  parseKeyBindingProof,
  parseTrustTimestamp,
  sha256Digest,
  signEnrollmentChallenge,
  signEnrollmentResponse,
  signKeyBindingProof,
  verifyEd25519DidSignature,
  verifyEnrollmentChallenge,
  verifyEnrollmentResponse,
  verifyJweKeyBinding,
} from "../core/trust.js";
import { sha256HexBytes } from "../core/chain.js";
import { packTnpkgBytes, readTnpkgVerified } from "../tnpkg_io.js";
import type { CeremonyConfig } from "./config.js";
import { loadJweActivationExpectation } from "./jwe_trust.js";

/** The common cross-SDK audit event type for explicit security weakening. */
export const UNSAFE_OPERATION_EVENT_TYPE = "tn.security.unsafe_operation";

// Enrollment offers contain one compact proof/package body. One MiB leaves
// generous extension room while bounding accidental or malicious raw
// artifact retention far below the generic package payload ceiling.
export const MAX_ENROLLMENT_ARTIFACT_BYTES = 1024 * 1024;
// Unsolicited offers consume receiver-local disk before authorization.
export const MAX_UNSOLICITED_OFFER_BYTES = 256 * 1024;
export const MAX_UNSOLICITED_PENDING_COUNT = 128;
export const MAX_UNSOLICITED_PENDING_BYTES = 8 * 1024 * 1024;
// Challenged capacity is reserved independently but still bounded: a reader
// can otherwise mint unlimited distinct signed variants for one challenge.
export const MAX_CHALLENGED_VARIANTS_PER_CHALLENGE = 4;
export const MAX_CHALLENGED_PENDING_COUNT = 256;
export const MAX_CHALLENGED_PENDING_BYTES = 32 * 1024 * 1024;
export const MAX_ENROLLMENT_ZIP_ENTRIES = 8;
export const MAX_ENROLLMENT_MEMBER_BYTES = 256 * 1024;
export const MAX_ENROLLMENT_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024;
export const MAX_ENROLLMENT_COMPRESSION_RATIO = 20;

const SHA256_PREFIX = "sha256:";

function error(reason: TrustError["reason"], detail: string): TrustError {
  return new TrustError(reason, detail);
}

function requireDigest(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    value.length !== SHA256_PREFIX.length + 64 ||
    !value.startsWith(SHA256_PREFIX) ||
    [...value.slice(SHA256_PREFIX.length)].some((ch) => !"0123456789abcdef".includes(ch))
  ) {
    throw error("statement_invalid", `${field} must be a lowercase sha256 digest`);
  }
  return value;
}

function nowTimestamp(): string {
  return formatTrustTimestamp(Date.now() * 1000);
}

/** Map signed ceremony/group text to one portable collision-safe name. */
function scopeComponent(value: string): string {
  return "sha256-" + sha256HexBytes(new TextEncoder().encode(value));
}

function digestComponent(value: string): string {
  return requireDigest(value, "digest").slice(SHA256_PREFIX.length);
}

function didHashComponent(did: string): string {
  return sha256HexBytes(new TextEncoder().encode(did));
}

function canonicalJsonBytes(value: Record<string, unknown>): Uint8Array {
  const body = canonicalize(value);
  const out = new Uint8Array(body.length + 1);
  out.set(body, 0);
  out[out.length - 1] = 0x0a;
  return out;
}

// ── Conventions ─────────────────────────────────────────────────────

/** Private version-1 challenge, offer, approval, and replay state root for a
 * ceremony yaml: `<yaml_dir>/.tn/<stem>/enrollment/v1` (mirrors Python's
 * `tn.conventions.enrollment_dir`). */
export function enrollmentDir(yamlPath: string): string {
  const resolved = pathResolve(yamlPath);
  const base = resolved.split(/[\\/]/).pop() ?? "";
  const stem = base.endsWith(".yaml")
    ? base.slice(0, -".yaml".length)
    : base.endsWith(".yml")
      ? base.slice(0, -".yml".length)
      : null;
  return stem === null
    ? join(resolved, ".tn", "tn", "enrollment", "v1")
    : join(dirname(resolved), ".tn", stem, "enrollment", "v1");
}

// ── Atomic write + advisory lock ────────────────────────────────────

/** Write `data` atomically and owner-only: same-dir temp (0600) + fsync +
 * rename. On Windows the mode is a no-op; the user-profile ACL protects it. */
function atomicWriteBytes(path: string, data: Uint8Array): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true });
  const tmp = join(
    parent,
    `.${path.split(/[\\/]/).pop()}.tmp.${process.pid}.${sha256HexBytes(randomBytes(8)).slice(0, 16)}`,
  );
  let fd: number | null = null;
  let closed = false;
  try {
    fd = openSync(tmp, "wx", 0o600);
    writeSync(fd, data);
    fsyncSync(fd);
    closeSync(fd);
    closed = true;
    renameSync(tmp, path);
  } catch (err) {
    if (fd !== null && !closed) {
      try {
        closeSync(fd);
      } catch {
        // best-effort close before cleanup
      }
    }
    try {
      if (existsSync(tmp)) unlinkSync(tmp);
    } catch {
      // a stale temp file never affects the existing target contents
    }
    throw err;
  }
}

// Cross-process exclusive advisory lock via exclusive-create of
// `enrollment.lock`. Node has no portable flock; create-exclusive plus a
// stale-lock timeout gives the same serialization for the store's short
// critical sections. Store methods are fully synchronous, so a single Node
// thread cannot interleave two critical sections in-process.
const LOCK_RETRY_MS = 10;
const LOCK_STALE_MS = 60_000;
const LOCK_TIMEOUT_MS = 20_000;

function sleepSync(ms: number): void {
  const shared = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(shared), 0, 0, ms);
}

function acquireLockFd(lockPath: string): number {
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (;;) {
    try {
      return openSync(lockPath, "wx", 0o600);
    } catch {
      try {
        const age = Date.now() - statSync(lockPath).mtimeMs;
        if (age > LOCK_STALE_MS) {
          unlinkSync(lockPath);
          continue;
        }
      } catch {
        // raced with the holder's release; retry immediately
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(`enrollment lock timeout: ${lockPath} is still held`);
      }
      sleepSync(LOCK_RETRY_MS);
    }
  }
}

function withFileLock<T>(lockPath: string, fn: () => T): T {
  mkdirSync(dirname(lockPath), { recursive: true });
  const fd = acquireLockFd(lockPath);
  try {
    writeSync(fd, String(process.pid));
    return fn();
  } finally {
    try {
      closeSync(fd);
    } catch {
      // release below still runs
    }
    try {
      unlinkSync(lockPath);
    } catch {
      // a leftover lock file expires via the stale timeout
    }
  }
}

// ── Bounded artifact reads ──────────────────────────────────────────

function raiseOversizedArtifact(size: number): never {
  throw error(
    "statement_invalid",
    `enrollment artifact size ${size} exceeds the maximum enrollment artifact size of ${MAX_ENROLLMENT_ARTIFACT_BYTES} bytes`,
  );
}

/** Read one path with a pre-stat and a re-checked bounded read. */
export function readEnrollmentArtifact(path: string): Uint8Array {
  const size = statSync(path).size;
  if (size > MAX_ENROLLMENT_ARTIFACT_BYTES) raiseOversizedArtifact(size);
  const artifact = new Uint8Array(readFileSync(path));
  if (artifact.length > MAX_ENROLLMENT_ARTIFACT_BYTES) raiseOversizedArtifact(artifact.length);
  return artifact;
}

/** Metadata-only compact-offer limits; reads no archive member bytes. */
export function validateEnrollmentArchive(source: Uint8Array): void {
  let entries = 0;
  let total = 0;
  try {
    unzipSync(source, {
      filter(info: UnzipFileInfo): boolean {
        entries += 1;
        if (entries > MAX_ENROLLMENT_ZIP_ENTRIES) {
          throw error(
            "statement_invalid",
            `enrollment package entry count ${entries} exceeds limit ${MAX_ENROLLMENT_ZIP_ENTRIES}`,
          );
        }
        const size = info.originalSize;
        if (!Number.isSafeInteger(size) || size < 0) {
          throw error("statement_invalid", "enrollment package member size is invalid");
        }
        if (size > MAX_ENROLLMENT_MEMBER_BYTES) {
          throw error(
            "statement_invalid",
            `enrollment package member ${JSON.stringify(info.name)} size ${size} exceeds limit ${MAX_ENROLLMENT_MEMBER_BYTES}`,
          );
        }
        total += size;
        if (total > MAX_ENROLLMENT_TOTAL_UNCOMPRESSED_BYTES) {
          throw error(
            "statement_invalid",
            `enrollment package total uncompressed size ${total} exceeds limit ${MAX_ENROLLMENT_TOTAL_UNCOMPRESSED_BYTES}`,
          );
        }
        const ratio = size / Math.max(info.size, 1);
        if (ratio > MAX_ENROLLMENT_COMPRESSION_RATIO) {
          throw error(
            "statement_invalid",
            `enrollment package member ${JSON.stringify(info.name)} compression ratio ${ratio.toFixed(1)} exceeds limit ${MAX_ENROLLMENT_COMPRESSION_RATIO}`,
          );
        }
        return false;
      },
    });
  } catch (err) {
    if (err instanceof TrustError) throw err;
    const message = err instanceof Error ? err.message : String(err);
    throw error("statement_invalid", `enrollment package is not a valid zip: ${message}`);
  }
}

// ── State records ───────────────────────────────────────────────────

/** A verified binding backed by the complete retained signed artifact. */
export interface PendingOffer {
  ceremonyId: string;
  group: string;
  readerDid: string;
  offerDigest: string;
  artifactPath: string;
  verified: VerifiedJweBinding;
}

interface VerifiedArtifact {
  pending: PendingOffer;
  artifactDigest: string;
  challengeId: string | null;
}

interface PendingUsage {
  unsolicitedCount: number;
  unsolicitedBytes: number;
  challengedCount: number;
  challengedBytes: number;
  challengeVariants: Map<string, number>;
}

export interface PendingScanConflict {
  path: string;
  error: TrustError;
}

/** The receiver-local ceremony facts the store needs. `CeremonyConfig`
 * satisfies this via {@link enrollmentCeremonyFromConfig}. */
export interface EnrollmentCeremony {
  ceremonyId: string;
  yamlPath: string;
  groups: { has(name: string): boolean };
  deviceIdentity: string;
}

/** Adapt a loaded runtime config to the store's ceremony interface. */
export function enrollmentCeremonyFromConfig(cfg: CeremonyConfig): EnrollmentCeremony {
  return {
    ceremonyId: cfg.ceremonyId,
    yamlPath: cfg.yamlPath,
    groups: cfg.groups,
    deviceIdentity: cfg.device.device_identity,
  };
}

function readJsonObject(path: string, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw error("statement_invalid", `${label} is unreadable`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw error("statement_invalid", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactRecordFields(value: Record<string, unknown>, fields: string[], label: string): void {
  const keys = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    throw error("statement_invalid", `${label} has an invalid shape`);
  }
}

const SAFE_CHALLENGE_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;

function safeChallengeIdComponent(challengeId: string): string {
  if (
    typeof challengeId !== "string" ||
    !SAFE_CHALLENGE_ID_RE.test(challengeId) ||
    challengeId === "." ||
    challengeId === ".."
  ) {
    throw error("statement_invalid", "challenge id is invalid");
  }
  return challengeId;
}

/**
 * Classify one incoming use of an already-tracked challenge consumption.
 * `prior === null` means the challenge is unconsumed ("fresh"); a prior
 * record without digests can never be matched and is a replay; an exact
 * digest match is an idempotent no-op; anything else is a conflict.
 */
export function evaluateConsumedChallenge(
  prior: { artifactDigest?: string; offerDigest?: string } | null,
  incoming: { artifactDigest: string; offerDigest?: string },
): "fresh" | "idempotent" {
  if (prior === null) return "fresh";
  if (
    prior.artifactDigest === undefined ||
    (prior.offerDigest === undefined && incoming.offerDigest !== undefined)
  ) {
    throw error("challenge_replayed", "challenge has already been consumed");
  }
  const offerMatches =
    prior.offerDigest === undefined ||
    incoming.offerDigest === undefined ||
    prior.offerDigest === incoming.offerDigest;
  if (prior.artifactDigest === incoming.artifactDigest && offerMatches) {
    return "idempotent";
  }
  throw error("replay_conflict", "challenge was consumed by a different signed artifact");
}

function walkFiles(root: string, suffix: string): string[] {
  if (!existsSync(root)) return [];
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      const full = join(dir, name);
      let stat;
      try {
        stat = statSync(full);
      } catch {
        continue;
      }
      if (stat.isDirectory()) stack.push(full);
      else if (name.endsWith(suffix)) out.push(full);
    }
  }
  return out.sort();
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

// ── The store ───────────────────────────────────────────────────────

/** Durable version-1 enrollment state for one publisher ceremony. */
export class EnrollmentStore {
  readonly ceremony: EnrollmentCeremony;
  readonly publisherKey: DeviceKey;
  readonly stateRoot: string;
  readonly lockPath: string;
  readonly challengesDir: string;
  readonly offersDir: string;
  readonly approvalsDir: string;
  readonly consumedDir: string;
  readonly acceptedDir: string;
  readonly preauthorizedDir: string;

  constructor(ceremony: EnrollmentCeremony, publisherKey: DeviceKey, stateRoot?: string) {
    if (publisherKey.did !== ceremony.deviceIdentity) {
      throw error(
        "did_signer_mismatch",
        "publisher key does not match the loaded ceremony identity",
      );
    }
    parseEd25519DidKey(publisherKey.did);
    this.ceremony = ceremony;
    this.publisherKey = publisherKey;
    this.stateRoot = pathResolve(stateRoot ?? enrollmentDir(ceremony.yamlPath));
    this.lockPath = join(this.stateRoot, "enrollment.lock");
    this.challengesDir = join(this.stateRoot, "challenges");
    this.offersDir = join(this.stateRoot, "offers");
    this.approvalsDir = join(this.stateRoot, "approvals");
    this.consumedDir = join(this.stateRoot, "consumed");
    this.acceptedDir = join(this.stateRoot, "accepted");
    this.preauthorizedDir = join(this.stateRoot, "preauthorized");
  }

  private _lock<T>(fn: () => T): T {
    mkdirSync(this.stateRoot, { recursive: true });
    return withFileLock(this.lockPath, fn);
  }

  private _validateScope(readerDid: string, group: string): void {
    parseEd25519DidKey(readerDid);
    if (typeof group !== "string" || group.length === 0) {
      throw error("scope_mismatch", "group must be non-empty");
    }
    if (!this.ceremony.groups.has(group)) {
      throw error(
        "scope_mismatch",
        `group ${JSON.stringify(group)} is not present in this ceremony`,
      );
    }
  }

  private _preauthorizationPath(readerDid: string, group: string): string {
    return join(
      this.preauthorizedDir,
      scopeComponent(this.ceremony.ceremonyId),
      scopeComponent(group),
      `${didHashComponent(readerDid)}.json`,
    );
  }

  /** Persist exact DID/ceremony/group authorization for challenged offers. */
  preauthorize(readerDid: string, group: string): void {
    this._validateScope(readerDid, group);
    const record: Record<string, unknown> = {
      version: 1,
      ceremony_id: this.ceremony.ceremonyId,
      group,
      reader_did: readerDid,
    };
    const data = canonicalJsonBytes(record);
    const path = this._preauthorizationPath(readerDid, group);
    this._lock(() => {
      if (existsSync(path)) {
        if (!bytesEqual(new Uint8Array(readFileSync(path)), data)) {
          throw error("replay_conflict", "preauthorization scope conflicts with existing state");
        }
        return;
      }
      atomicWriteBytes(path, data);
    });
  }

  private _isPreauthorized(readerDid: string, group: string): boolean {
    const path = this._preauthorizationPath(readerDid, group);
    if (!existsSync(path)) return false;
    const record = readJsonObject(path, "preauthorization record");
    exactRecordFields(
      record,
      ["version", "ceremony_id", "group", "reader_did"],
      "preauthorization record",
    );
    if (
      record["version"] !== 1 ||
      record["ceremony_id"] !== this.ceremony.ceremonyId ||
      record["group"] !== group ||
      record["reader_did"] !== readerDid
    ) {
      throw error("replay_conflict", "preauthorization record does not match the requested scope");
    }
    return true;
  }

  /** Issue and durably retain a one-time publisher-signed challenge. */
  issueChallenge(
    readerDid: string,
    group: string,
    ttlMs: number,
    now?: string,
  ): EnrollmentChallengeV1 {
    this._validateScope(readerDid, group);
    if (typeof ttlMs !== "number" || !Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw error("statement_invalid", "challenge ttl must be positive");
    }
    const issuedMicros = parseTrustTimestamp(now ?? nowTimestamp(), "now");
    const issuedAt = formatTrustTimestamp(issuedMicros);
    const expiresAt = formatTrustTimestamp(issuedMicros + Math.round(ttlMs) * 1000);
    return this._lock(() => {
      let challengeId = globalThis.crypto.randomUUID();
      while (existsSync(join(this.challengesDir, `${challengeId}.json`))) {
        challengeId = globalThis.crypto.randomUUID();
      }
      const challenge = signEnrollmentChallenge(
        {
          version: 1,
          kind: "tn-enrollment-challenge",
          publisher_did: this.publisherKey.did,
          expected_reader_did: readerDid,
          ceremony_id: this.ceremony.ceremonyId,
          group,
          nonce_b64: bytesToB64(randomBytes(32)),
          issued_at: issuedAt,
          expires_at: expiresAt,
          challenge_id: challengeId,
          signature_b64: "",
        },
        this.publisherKey,
      );
      const record: Record<string, unknown> = {
        version: 1,
        challenge_digest: enrollmentChallengeDigest(challenge),
        challenge: { ...challenge },
      };
      atomicWriteBytes(join(this.challengesDir, `${challengeId}.json`), canonicalJsonBytes(record));
      return challenge;
    });
  }

  /** Load one retained challenge by its exact `sha256:` digest. */
  challengeForDigest(challengeDigest: string): EnrollmentChallengeV1 {
    requireDigest(challengeDigest, "challenge digest");
    if (!existsSync(this.challengesDir)) {
      throw error("challenge_missing", "challenge is not retained");
    }
    for (const path of walkFiles(this.challengesDir, ".json")) {
      const record = readJsonObject(path, "challenge record");
      exactRecordFields(record, ["version", "challenge_digest", "challenge"], "challenge record");
      if (record["version"] !== 1) {
        throw error("statement_invalid", "unsupported challenge record");
      }
      if (record["challenge_digest"] !== challengeDigest) continue;
      const challenge = parseEnrollmentChallenge(record["challenge"]);
      const actual = enrollmentChallengeDigest(challenge);
      const stem = (path.split(/[\\/]/).pop() ?? "").replace(/\.json$/, "");
      if (actual !== challengeDigest || stem !== challenge.challenge_id) {
        throw error(
          "replay_conflict",
          "retained challenge digest or identifier conflicts with its bytes",
        );
      }
      return challenge;
    }
    throw error("challenge_missing", "challenge digest is not retained");
  }

  private _offerPath(
    ceremonyId: string,
    group: string,
    readerDid: string,
    offerDigest: string,
  ): string {
    return join(
      this.offersDir,
      scopeComponent(ceremonyId),
      scopeComponent(group),
      didHashComponent(readerDid),
      `${digestComponent(offerDigest)}.tnpkg`,
    );
  }

  private _approvalPath(offerDigest: string): string {
    return join(this.approvalsDir, `${digestComponent(offerDigest)}.json`);
  }

  private _acceptedPath(offerDigest: string): string {
    return join(this.acceptedDir, `${digestComponent(offerDigest)}.json`);
  }

  private _consumedPath(challengeId: string): string {
    return join(this.consumedDir, `${safeChallengeIdComponent(challengeId)}.json`);
  }

  private _loadConsumed(challengeId: string): Record<string, unknown> | null {
    const path = this._consumedPath(challengeId);
    if (!existsSync(path)) return null;
    return readJsonObject(path, "consumed challenge record");
  }

  /** Return true for an exact replay; reject every other consumed use. */
  private _classifyConsumedChallenge(
    challengeId: string,
    offerDigest: string,
    artifactDigest: string,
  ): boolean {
    const record = this._loadConsumed(challengeId);
    if (record === null) return false;
    const prior: { artifactDigest?: string; offerDigest?: string } = {};
    if (typeof record["artifact_digest"] === "string")
      prior.artifactDigest = record["artifact_digest"];
    if (typeof record["offer_digest"] === "string") prior.offerDigest = record["offer_digest"];
    return evaluateConsumedChallenge(prior, { artifactDigest, offerDigest }) === "idempotent";
  }

  /** Return true only for a durable approval of these exact bytes. */
  private _classifyApproval(offerDigest: string, artifactDigest: string): boolean {
    const path = this._approvalPath(offerDigest);
    if (!existsSync(path)) return false;
    const record = readJsonObject(path, "offer approval");
    exactRecordFields(
      record,
      ["version", "offer_digest", "artifact_digest", "approved_at"],
      "offer approval",
    );
    if (record["version"] !== 1 || record["offer_digest"] !== offerDigest) {
      throw error("replay_conflict", "approval does not match the exact offer digest");
    }
    if (record["artifact_digest"] !== artifactDigest) {
      throw error("replay_conflict", "approval does not match the exact retained offer artifact");
    }
    if (typeof record["approved_at"] !== "string") {
      throw error("statement_invalid", "offer approval is malformed");
    }
    return true;
  }

  private _parseInnerPackage(body: Map<string, Uint8Array>): TnPackage {
    const raw = body.get("body/package.json");
    if (raw === undefined) {
      throw error("statement_invalid", "offer body is missing package.json");
    }
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    } catch {
      throw error("statement_invalid", "offer package is invalid JSON");
    }
    const pkg = parseTnPackage(value);
    if (pkg.package_version !== 1) {
      throw error("statement_invalid", "unsupported offer package version");
    }
    if (pkg.package_kind !== "offer") {
      throw error("statement_invalid", "package is not an offer");
    }
    return pkg;
  }

  private _isCommittedReplay(
    proof: KeyBindingProofV1,
    offerDigest: string,
    artifactDigest: string,
    challengeId: string | null,
  ): boolean {
    const publicKeyValue = proof.binding["public_key_b64"];
    if (typeof publicKeyValue !== "string") return false;
    let publicKey: Uint8Array;
    try {
      publicKey = b64ToBytes(publicKeyValue);
    } catch {
      return false;
    }
    const candidate: Record<string, unknown> = {
      version: 1,
      ceremony_id: proof.ceremony_id,
      group: proof.group,
      reader_did: proof.subject_did,
      offer_digest: offerDigest,
      artifact_digest: artifactDigest,
      challenge_id: challengeId,
      proof_digest: offerDigest,
      public_key_sha256: sha256Digest(publicKey),
    };
    const acceptedPath = this._acceptedPath(offerDigest);
    if (existsSync(acceptedPath)) {
      const record = readJsonObject(acceptedPath, "accepted offer record");
      if (JSON.stringify(canonicalOrder(record)) === JSON.stringify(canonicalOrder(candidate))) {
        return true;
      }
    }
    if (challengeId === null) return false;
    const consumed = this._loadConsumed(challengeId);
    return (
      consumed !== null &&
      consumed["version"] === 1 &&
      consumed["challenge_id"] === challengeId &&
      consumed["offer_digest"] === offerDigest &&
      consumed["artifact_digest"] === artifactDigest &&
      Object.keys(consumed).length === 4
    );
  }

  private _verifyArtifact(
    artifact: Uint8Array,
    expectedPublisherDid: string,
    now: string,
  ): VerifiedArtifact {
    if (!(artifact instanceof Uint8Array)) {
      throw error("statement_invalid", "offer artifact must be bytes");
    }
    if (artifact.length > MAX_ENROLLMENT_ARTIFACT_BYTES) raiseOversizedArtifact(artifact.length);
    validateEnrollmentArchive(artifact);
    parseTrustTimestamp(now, "now");
    parseEd25519DidKey(expectedPublisherDid);
    if (expectedPublisherDid !== this.publisherKey.did) {
      throw error("wrong_recipient", "expected publisher does not match this enrollment store");
    }

    let manifest: Manifest;
    let body: Map<string, Uint8Array>;
    try {
      const parsed = readTnpkgVerified(artifact);
      manifest = parsed.manifest;
      body = parsed.body;
    } catch (err) {
      if (err instanceof TrustError) throw err;
      const message = err instanceof Error ? err.message : String(err);
      if (
        message.includes("signature does not verify") ||
        message.includes("manifest is unsigned")
      ) {
        throw error("signature_invalid", message);
      }
      throw error("statement_invalid", `offer artifact is malformed: ${message}`);
    }
    if (manifest.kind !== "offer") {
      throw error("statement_invalid", "artifact is not an offer");
    }
    const pkg = this._parseInnerPackage(body);
    if (manifest.fromDid !== pkg.device_identity) {
      throw error(
        "outer_inner_signer_mismatch",
        "outer manifest and inner offer name different signers",
      );
    }
    if (
      manifest.toDid !== expectedPublisherDid ||
      pkg.recipient_identity !== expectedPublisherDid
    ) {
      throw error("wrong_recipient", "offer names a different publisher");
    }
    if (
      manifest.ceremonyId !== this.ceremony.ceremonyId ||
      pkg.ceremony_id !== this.ceremony.ceremonyId ||
      manifest.scope !== pkg.group ||
      !this.ceremony.groups.has(pkg.group)
    ) {
      throw error("scope_mismatch", "offer ceremony or group does not match");
    }
    verifyTnPackageSignature(pkg);

    const proofValue = pkg.payload["key_binding_proof"];
    if (proofValue === null || typeof proofValue !== "object" || Array.isArray(proofValue)) {
      throw error("binding_invalid", "offer lacks a key-binding proof");
    }
    const proof = parseKeyBindingProof(proofValue);
    if (proof.subject_did !== manifest.fromDid) {
      throw error("outer_inner_signer_mismatch", "outer manifest signer and proof subject differ");
    }
    verifyEd25519DidSignature(
      proof.subject_did,
      canonicalize(proofSigningWire(proof)),
      b64ToBytes(proof.signature_b64),
    );

    const challengeDigest = proof.binding["challenge_digest"];
    let challenge: EnrollmentChallengeV1 | null;
    if (challengeDigest === null) {
      challenge = null;
    } else if (typeof challengeDigest === "string") {
      challenge = this.challengeForDigest(challengeDigest);
    } else {
      throw error("binding_invalid", "challenge digest has invalid type");
    }

    const offerDigest = keyBindingProofDigest(proof);
    const artifactDigest = sha256Digest(artifact);
    const challengeId = challenge === null ? null : challenge.challenge_id;
    const consumedExact =
      challengeId !== null
        ? this._classifyConsumedChallenge(challengeId, offerDigest, artifactDigest)
        : false;
    const approvalExact = this._classifyApproval(offerDigest, artifactDigest);
    // Freshness authorized the original promotion. Exact retained-byte replay
    // stays an idempotent no-op: signatures/scope are reverified at the
    // proof's original valid instant.
    const verificationNow =
      consumedExact ||
      approvalExact ||
      this._isCommittedReplay(proof, offerDigest, artifactDigest, challengeId)
        ? proof.issued_at
        : now;

    if (challenge !== null) {
      // An expired retained challenge can no longer authorize a NEW offer.
      // (An exact replay verifies at the proof's original instant above.)
      const nowMicros = parseTrustTimestamp(verificationNow, "now");
      if (nowMicros >= parseTrustTimestamp(challenge.expires_at, "expires_at")) {
        throw error("challenge_expired", "challenge has expired");
      }
    }

    const binding = verifyJweKeyBinding(proof, {
      audienceDid: expectedPublisherDid,
      ceremonyId: this.ceremony.ceremonyId,
      group: pkg.group,
      now: verificationNow,
      ...(challenge === null ? {} : { challenge }),
    });

    const payloadPublicKey = pkg.payload["x25519_pub_b64"];
    if (payloadPublicKey !== undefined) {
      if (typeof payloadPublicKey !== "string") {
        throw error("binding_invalid", "offer public key is invalid");
      }
      let decoded: Uint8Array;
      try {
        decoded = b64ToBytes(payloadPublicKey);
      } catch {
        throw error("binding_invalid", "offer public key is invalid");
      }
      if (!bytesEqual(decoded, binding.publicKey)) {
        throw error("binding_invalid", "offer public key differs from the signed binding");
      }
    }
    if (binding.proofDigest !== offerDigest) {
      throw error("replay_conflict", "proof digest changed during verification");
    }
    return {
      pending: Object.freeze({
        ceremonyId: proof.ceremony_id,
        group: proof.group,
        readerDid: proof.subject_did,
        offerDigest,
        artifactPath: this._offerPath(
          proof.ceremony_id,
          proof.group,
          proof.subject_did,
          offerDigest,
        ),
        verified: binding,
      }),
      artifactDigest,
      challengeId,
    };
  }

  private _assertChallengeAvailable(verified: VerifiedArtifact): boolean {
    if (verified.challengeId === null) return false;
    return this._classifyConsumedChallenge(
      verified.challengeId,
      verified.pending.offerDigest,
      verified.artifactDigest,
    );
  }

  private _pendingUsage(): PendingUsage {
    const usage: PendingUsage = {
      unsolicitedCount: 0,
      unsolicitedBytes: 0,
      challengedCount: 0,
      challengedBytes: 0,
      challengeVariants: new Map(),
    };
    for (const path of walkFiles(this.offersDir, ".tnpkg")) {
      const artifact = readEnrollmentArtifact(path);
      validateEnrollmentArchive(artifact);
      let manifest: Manifest;
      let body: Map<string, Uint8Array>;
      try {
        const parsed = readTnpkgVerified(artifact);
        manifest = parsed.manifest;
        body = parsed.body;
      } catch (err) {
        if (err instanceof TrustError) throw err;
        const message = err instanceof Error ? err.message : String(err);
        if (
          message.includes("signature does not verify") ||
          message.includes("manifest is unsigned")
        ) {
          throw error("signature_invalid", message);
        }
        throw error("statement_invalid", `retained offer is malformed: ${message}`);
      }
      const pkg = this._parseInnerPackage(body);
      if (manifest.fromDid !== pkg.device_identity) {
        throw error("outer_inner_signer_mismatch", "retained offer outer and inner signers differ");
      }
      verifyTnPackageSignature(pkg);
      const proofValue = pkg.payload["key_binding_proof"];
      if (proofValue === null || typeof proofValue !== "object" || Array.isArray(proofValue)) {
        throw error("binding_invalid", "retained offer lacks a proof");
      }
      const proof = parseKeyBindingProof(proofValue);
      if (proof.subject_did !== pkg.device_identity) {
        throw error(
          "outer_inner_signer_mismatch",
          "retained offer package and proof signers differ",
        );
      }
      verifyEd25519DidSignature(
        proof.subject_did,
        canonicalize(proofSigningWire(proof)),
        b64ToBytes(proof.signature_b64),
      );
      const offerDigest = keyBindingProofDigest(proof);
      const artifactDigest = sha256Digest(artifact);
      const challengeDigest = proof.binding["challenge_digest"];
      if (challengeDigest !== null && typeof challengeDigest !== "string") {
        throw error("binding_invalid", "retained challenge digest has invalid type");
      }
      const challengeId =
        challengeDigest === null
          ? null
          : this.challengeForDigest(requireDigest(challengeDigest, "retained challenge digest"))
              .challenge_id;

      const acceptedPath = this._acceptedPath(offerDigest);
      if (existsSync(acceptedPath)) {
        const accepted = readJsonObject(acceptedPath, "accepted offer record");
        const publicKeyValue = proof.binding["public_key_b64"];
        let publicKey: Uint8Array = new Uint8Array(0);
        if (typeof publicKeyValue === "string") {
          try {
            publicKey = b64ToBytes(publicKeyValue);
          } catch {
            publicKey = new Uint8Array(0);
          }
        }
        const expected: Record<string, unknown> = {
          version: 1,
          ceremony_id: proof.ceremony_id,
          group: proof.group,
          reader_did: proof.subject_did,
          offer_digest: offerDigest,
          artifact_digest: artifactDigest,
          challenge_id: challengeId,
          proof_digest: offerDigest,
          public_key_sha256: sha256Digest(publicKey),
        };
        if (
          publicKey.length === 0 ||
          JSON.stringify(canonicalOrder(accepted)) !== JSON.stringify(canonicalOrder(expected))
        ) {
          throw error(
            "replay_conflict",
            "accepted offer record conflicts with retained artifact bytes",
          );
        }
        continue;
      }
      if (challengeDigest === null) {
        usage.unsolicitedCount += 1;
        usage.unsolicitedBytes += artifact.length;
      } else {
        usage.challengedCount += 1;
        usage.challengedBytes += artifact.length;
        usage.challengeVariants.set(
          challengeDigest,
          (usage.challengeVariants.get(challengeDigest) ?? 0) + 1,
        );
      }
    }
    return usage;
  }

  private _assertPendingQuota(verified: VerifiedArtifact, artifactSize: number): void {
    if (verified.challengeId === null) {
      if (artifactSize > MAX_UNSOLICITED_OFFER_BYTES) {
        throw error(
          "untrusted_principal",
          `unsolicited offer size ${artifactSize} exceeds limit ${MAX_UNSOLICITED_OFFER_BYTES}`,
        );
      }
      const usage = this._pendingUsage();
      if (usage.unsolicitedCount >= MAX_UNSOLICITED_PENDING_COUNT) {
        throw error(
          "untrusted_principal",
          `unsolicited pending offer count reached limit ${MAX_UNSOLICITED_PENDING_COUNT}`,
        );
      }
      if (usage.unsolicitedBytes + artifactSize > MAX_UNSOLICITED_PENDING_BYTES) {
        throw error(
          "untrusted_principal",
          `unsolicited pending offer bytes would exceed limit ${MAX_UNSOLICITED_PENDING_BYTES}`,
        );
      }
      return;
    }
    const challengeDigest = verified.pending.verified.challengeDigest;
    if (challengeDigest === null) {
      throw error("binding_invalid", "challenged offer is missing its verified challenge digest");
    }
    const usage = this._pendingUsage();
    if (
      (usage.challengeVariants.get(challengeDigest) ?? 0) >= MAX_CHALLENGED_VARIANTS_PER_CHALLENGE
    ) {
      throw error(
        "untrusted_principal",
        `challenged offer variants for challenge reached limit ${MAX_CHALLENGED_VARIANTS_PER_CHALLENGE}`,
      );
    }
    if (usage.challengedCount >= MAX_CHALLENGED_PENDING_COUNT) {
      throw error(
        "untrusted_principal",
        `challenged pending offer count reached limit ${MAX_CHALLENGED_PENDING_COUNT}`,
      );
    }
    if (usage.challengedBytes + artifactSize > MAX_CHALLENGED_PENDING_BYTES) {
      throw error(
        "untrusted_principal",
        `challenged pending offer bytes would exceed limit ${MAX_CHALLENGED_PENDING_BYTES}`,
      );
    }
  }

  /** Verify and retain exact `.tnpkg` bytes without authorizing them. */
  stageOffer(artifact: Uint8Array, expectedPublisherDid: string, now?: string): PendingOffer {
    const at = now ?? nowTimestamp();
    // Reject malformed/unscoped input before creating even the lock file. The
    // authoritative verification is repeated under the lock below.
    const preverified = this._verifyArtifact(artifact, expectedPublisherDid, at);
    const preexistingPath = preverified.pending.artifactPath;
    if (existsSync(preexistingPath)) {
      if (bytesEqual(readEnrollmentArtifact(preexistingPath), artifact)) {
        return preverified.pending;
      }
      throw error(
        "replay_conflict",
        "offer digest already names different retained artifact bytes",
      );
    }
    if (preverified.challengeId === null) {
      if (artifact.length > MAX_UNSOLICITED_OFFER_BYTES || !existsSync(this.stateRoot)) {
        this._assertPendingQuota(preverified, artifact.length);
      }
    }
    return this._lock(() => {
      const verified = this._verifyArtifact(artifact, expectedPublisherDid, at);
      this._assertChallengeAvailable(verified);
      const path = verified.pending.artifactPath;
      if (existsSync(path)) {
        if (!bytesEqual(readEnrollmentArtifact(path), artifact)) {
          throw error(
            "replay_conflict",
            "offer digest already names different retained artifact bytes",
          );
        }
      } else {
        this._assertPendingQuota(verified, artifact.length);
        atomicWriteBytes(path, artifact);
      }
      return verified.pending;
    });
  }

  private _reverifyPending(pending: PendingOffer, now: string): VerifiedArtifact {
    if (pending === null || typeof pending !== "object") {
      throw error("statement_invalid", "pending offer has invalid type");
    }
    const expectedPath = this._offerPath(
      pending.ceremonyId,
      pending.group,
      pending.readerDid,
      pending.offerDigest,
    );
    if (pathResolve(pending.artifactPath) !== pathResolve(expectedPath)) {
      throw error("replay_conflict", "pending offer path is not canonical");
    }
    let artifact: Uint8Array;
    try {
      artifact = readEnrollmentArtifact(pending.artifactPath);
    } catch (err) {
      if (err instanceof TrustError) throw err;
      throw error("statement_invalid", "retained offer is unreadable");
    }
    const verified = this._verifyArtifact(artifact, this.publisherKey.did, now);
    if (
      verified.pending.offerDigest !== pending.offerDigest ||
      verified.pending.readerDid !== pending.readerDid ||
      verified.pending.ceremonyId !== pending.ceremonyId ||
      verified.pending.group !== pending.group
    ) {
      throw error(
        "replay_conflict",
        "retained artifact no longer matches the pending verified value",
      );
    }
    return verified;
  }

  private _acceptedRecord(verified: VerifiedArtifact): Record<string, unknown> {
    return {
      version: 1,
      ceremony_id: verified.pending.ceremonyId,
      group: verified.pending.group,
      reader_did: verified.pending.readerDid,
      offer_digest: verified.pending.offerDigest,
      artifact_digest: verified.artifactDigest,
      challenge_id: verified.challengeId,
      proof_digest: verified.pending.verified.proofDigest,
      public_key_sha256: verified.pending.verified.publicKeySha256,
    };
  }

  private _isAcceptedExact(verified: VerifiedArtifact): boolean {
    const path = this._acceptedPath(verified.pending.offerDigest);
    if (!existsSync(path)) return false;
    const record = readJsonObject(path, "accepted offer record");
    const expected = this._acceptedRecord(verified);
    if (JSON.stringify(canonicalOrder(record)) !== JSON.stringify(canonicalOrder(expected))) {
      throw error(
        "replay_conflict",
        "accepted offer record conflicts with retained artifact bytes",
      );
    }
    return true;
  }

  private _accepted(verified: VerifiedArtifact): AcceptedOffer {
    const accepted: AcceptedOffer = {
      binding: verified.pending.verified,
      offerDigest: verified.pending.offerDigest,
      artifactDigest: verified.artifactDigest,
    };
    RECONCILED_ACCEPTED_OFFERS.set(accepted, jweRecipientFromAcceptedOffer(accepted).bindingDigest);
    return accepted;
  }

  private _promoteLocked(verified: VerifiedArtifact): AcceptedOffer {
    const consumedExact = this._assertChallengeAvailable(verified);
    const acceptedExact = this._isAcceptedExact(verified);
    if (consumedExact && acceptedExact) return this._accepted(verified);
    if (verified.challengeId !== null && !consumedExact) {
      const consumedRecord: Record<string, unknown> = {
        version: 1,
        challenge_id: verified.challengeId,
        offer_digest: verified.pending.offerDigest,
        artifact_digest: verified.artifactDigest,
      };
      atomicWriteBytes(
        this._consumedPath(verified.challengeId),
        canonicalJsonBytes(consumedRecord),
      );
    }
    if (!acceptedExact) {
      atomicWriteBytes(
        this._acceptedPath(verified.pending.offerDigest),
        canonicalJsonBytes(this._acceptedRecord(verified)),
      );
    }
    return this._accepted(verified);
  }

  /** Reverify and promote a preauthorized or exact-approved offer. */
  reconcile(pending: PendingOffer, now?: string): AcceptedOffer {
    const at = now ?? nowTimestamp();
    // As with staging, reject an invalid caller-supplied value before the
    // lock file can become the first persistent mutation.
    this._reverifyPending(pending, at);
    return this._lock(() => {
      const verified = this._reverifyPending(pending, at);
      const consumedExact = this._assertChallengeAvailable(verified);
      if (consumedExact && this._isAcceptedExact(verified)) {
        return this._accepted(verified);
      }
      let authorized = this._classifyApproval(
        verified.pending.offerDigest,
        verified.artifactDigest,
      );
      if (verified.challengeId !== null) {
        authorized =
          authorized || this._isPreauthorized(verified.pending.readerDid, verified.pending.group);
      }
      if (!authorized) {
        throw error("untrusted_principal", "offer requires exact-digest administrator approval");
      }
      return this._promoteLocked(verified);
    });
  }

  private _findPendingPath(offerDigest: string): string {
    const component = digestComponent(offerDigest);
    const matches = walkFiles(this.offersDir, `${component}.tnpkg`);
    if (matches.length === 0) {
      throw error("untrusted_principal", "pending offer digest was not found");
    }
    if (matches.length !== 1) {
      throw error("replay_conflict", "pending offer digest is ambiguous");
    }
    return matches[0] as string;
  }

  private _pendingFromPath(path: string, now: string): VerifiedArtifact {
    let artifact: Uint8Array;
    try {
      artifact = readEnrollmentArtifact(path);
    } catch (err) {
      if (err instanceof TrustError) throw err;
      throw error("statement_invalid", "pending offer is unreadable");
    }
    const verified = this._verifyArtifact(artifact, this.publisherKey.did, now);
    if (pathResolve(verified.pending.artifactPath) !== pathResolve(path)) {
      throw error("replay_conflict", "pending offer is stored at a wrong path");
    }
    return verified;
  }

  /** Approve an exact digest, reverify, consume, and promote under one lock. */
  approveAndReconcile(offerDigest: string, now?: string): AcceptedOffer {
    requireDigest(offerDigest, "offer digest");
    const at = now ?? nowTimestamp();
    parseTrustTimestamp(at, "now");
    if (!existsSync(this.offersDir)) {
      throw error("untrusted_principal", "pending offer digest was not found");
    }
    return this._lock(() => {
      const path = this._findPendingPath(offerDigest);
      const verified = this._pendingFromPath(path, at);
      if (verified.pending.offerDigest !== offerDigest) {
        throw error("replay_conflict", "offer digest does not match bytes");
      }
      const consumedExact = this._assertChallengeAvailable(verified);
      if (consumedExact && this._isAcceptedExact(verified)) {
        return this._accepted(verified);
      }
      const approvalPath = this._approvalPath(offerDigest);
      if (existsSync(approvalPath)) {
        const existing = readJsonObject(approvalPath, "offer approval");
        if (
          existing["offer_digest"] !== offerDigest ||
          existing["artifact_digest"] !== verified.artifactDigest
        ) {
          throw error("replay_conflict", "offer approval conflicts with retained bytes");
        }
      } else {
        const record: Record<string, unknown> = {
          version: 1,
          offer_digest: offerDigest,
          artifact_digest: verified.artifactDigest,
          approved_at: at,
        };
        atomicWriteBytes(approvalPath, canonicalJsonBytes(record));
      }
      return this._promoteLocked(verified);
    });
  }

  /** Load and reverify one retained offer by its exact digest. */
  pendingOffer(offerDigest: string, now?: string): PendingOffer {
    requireDigest(offerDigest, "offer digest");
    const at = now ?? nowTimestamp();
    if (!existsSync(this.offersDir)) {
      throw error("untrusted_principal", "pending offer digest was not found");
    }
    return this._lock(() => {
      const verified = this._pendingFromPath(this._findPendingPath(offerDigest), at);
      if (verified.pending.offerDigest !== offerDigest) {
        throw error("replay_conflict", "offer digest does not match bytes");
      }
      return verified.pending;
    });
  }

  /** Isolate retained-artifact failures while preserving explicit reports. */
  scanPendingOffers(now?: string): { offers: PendingOffer[]; conflicts: PendingScanConflict[] } {
    const at = now ?? nowTimestamp();
    parseTrustTimestamp(at, "now");
    if (!existsSync(this.offersDir)) return { offers: [], conflicts: [] };
    return this._lock(() => {
      const offers: PendingOffer[] = [];
      const conflicts: PendingScanConflict[] = [];
      for (const path of walkFiles(this.offersDir, ".tnpkg")) {
        try {
          const verified = this._pendingFromPath(path, at);
          if (!this._isAcceptedExact(verified)) offers.push(verified.pending);
        } catch (err) {
          if (err instanceof TrustError) {
            conflicts.push({ path, error: err });
          } else {
            conflicts.push({ path, error: error("statement_invalid", String(err)) });
          }
        }
      }
      return { offers, conflicts };
    });
  }

  /** Return all verified pending offers, failing closed on corrupt state. */
  pendingOffers(now?: string): PendingOffer[] {
    const scan = this.scanPendingOffers(now);
    if (scan.conflicts.length > 0) {
      throw (scan.conflicts[0] as PendingScanConflict).error;
    }
    return scan.offers;
  }
}

/** Deterministic key order for record equality comparisons. */
function canonicalOrder(value: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) out[key] = value[key];
  return out;
}

/** The proof's signing-domain wire dict (signature omitted). */
function proofSigningWire(proof: KeyBindingProofV1): Record<string, unknown> {
  return {
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
}

// ── Reader-side keys, offers, and response install ──────────────────

function validateGroupFileName(group: string): string {
  if (
    group.length === 0 ||
    group !== group.trim() ||
    group === "." ||
    group === ".." ||
    group.includes("/") ||
    group.includes("\\") ||
    group.includes("\0")
  ) {
    throw new Error(
      `enrollment: invalid group name ${JSON.stringify(group)} for keystore filenames`,
    );
  }
  return group;
}

/**
 * Return a random, per-group JWE reader public key, atomically persisting the
 * private key owner-only when absent. This is the default signed/fingerprint
 * enrollment path and preserves key separation from the device identity.
 */
export function ensureJweReaderKey(keystoreDir: string, group: string): Uint8Array {
  validateGroupFileName(group);
  const path = join(keystoreDir, `${group}.jwe.mykey`);
  const exists = existsSync(path);
  const privateKey = exists ? new Uint8Array(readFileSync(path)) : x25519.utils.randomSecretKey();
  try {
    if (privateKey.length !== 32) {
      throw error(
        "binding_invalid",
        `reader key at ${path} must be 32 bytes, got ${privateKey.length}`,
      );
    }
    if (!exists) atomicWriteBytes(path, privateKey);
    return x25519.getPublicKey(privateKey);
  } finally {
    privateKey.fill(0);
  }
}

/**
 * Explicit identity-key adapter for DID-document enrollment. This deliberately
 * reuses the device identity key across every group that opts in, coupling JWE
 * rotation to identity rotation; callers should prefer the random default.
 */
export function ensureDidKeyBoundJweReaderKey(
  keystoreDir: string,
  group: string,
  readerKey: DeviceKey,
): Uint8Array {
  validateGroupFileName(group);
  const path = join(keystoreDir, `${group}.jwe.mykey`);
  const privateKey = ed25519SeedToX25519Priv(readerKey.seed);
  try {
    const publicKey = x25519.getPublicKey(privateKey);
    const expected = didKeyToX25519Pub(readerKey.did);
    if (publicKey.some((byte, index) => byte !== expected[index])) {
      throw error("binding_invalid", "local Ed25519 seed and did:key conversion disagree");
    }
    if (!existsSync(path)) {
      atomicWriteBytes(path, privateKey);
      return publicKey;
    }
    const retained = new Uint8Array(readFileSync(path));
    try {
      if (
        retained.length !== privateKey.length ||
        retained.some((byte, index) => byte !== privateKey[index])
      ) {
        throw error(
          "binding_invalid",
          `reader key at ${path} is not bound to local did:key; remove or migrate it explicitly`,
        );
      }
      return publicKey;
    } finally {
      retained.fill(0);
    }
  } finally {
    privateKey.fill(0);
  }
}

const SENT_OFFERS_FILENAME = "enrollment_offers.v1.json";
const VERIFIED_PUBLISHERS_FILENAME = "verified_publishers.v1.json";
const RECONCILED_ACCEPTED_OFFERS = new WeakMap<object, string>();

/** Reject structural lookalikes that never passed this process's reconciliation store. */
export function assertReconciledAcceptedOffer(accepted: AcceptedOffer): void {
  if (accepted === null || typeof accepted !== "object") {
    throw error(
      "untrusted_principal",
      "accepted JWE offer must be the exact value returned by reconciliation",
    );
  }
  const expectedDigest = RECONCILED_ACCEPTED_OFFERS.get(accepted);
  let actualDigest: string | undefined;
  try {
    actualDigest = jweRecipientFromAcceptedOffer(accepted).bindingDigest;
  } catch {
    // Use the same provenance error for malformed and structurally forged values.
  }
  if (expectedDigest === undefined || actualDigest !== expectedDigest) {
    throw error(
      "untrusted_principal",
      "accepted JWE offer must be the exact value returned by reconciliation and remain unchanged",
    );
  }
}

function trustDir(keystoreDir: string): string {
  return join(keystoreDir, "trust");
}

/** Path of the reader's retained sent-offer records. */
export function sentOffersPath(keystoreDir: string): string {
  return join(trustDir(keystoreDir), SENT_OFFERS_FILENAME);
}

/** Path of the shared verified-publisher trust records (read-trust adapter). */
export function verifiedPublishersPath(keystoreDir: string): string {
  return join(trustDir(keystoreDir), VERIFIED_PUBLISHERS_FILENAME);
}

/**
 * Admit the exact signer of a body-indexed, signature-verified kit bundle.
 * The caller must have already verified the package body digest index; this
 * function independently rechecks the manifest signature before persisting.
 */
export function recordVerifiedKitBundlePublisher(opts: {
  keystoreDir: string;
  manifest: Manifest;
  artifactDigest: string;
  installedAt?: string;
}): void {
  if (opts.manifest.kind !== "kit_bundle" || !isManifestSignatureValid(opts.manifest)) {
    throw error("untrusted_principal", "publisher trust requires a verified kit_bundle manifest");
  }
  parseEd25519DidKey(opts.manifest.fromDid);
  requireDigest(opts.artifactDigest, "artifact digest");
  const path = verifiedPublishersPath(opts.keystoreDir);
  const doc = existsSync(path)
    ? readJsonObject(path, "verified publisher record")
    : { version: 1, publishers: {} };
  const value = doc["publishers"];
  if (doc["version"] !== 1 || value === null || typeof value !== "object" || Array.isArray(value)) {
    throw error("statement_invalid", "verified publisher registry is malformed");
  }
  const publishers = value as Record<string, unknown>;
  const prior = publishers[opts.manifest.fromDid];
  if (
    prior !== undefined &&
    (prior === null || typeof prior !== "object" || Array.isArray(prior))
  ) {
    throw error("statement_invalid", "verified publisher record is malformed");
  }
  const kit = {
    artifact_digest: opts.artifactDigest,
    ceremony_id: opts.manifest.ceremonyId,
    installed_at: opts.installedAt ?? nowTimestamp(),
    recipient_identity: opts.manifest.toDid ?? null,
    scope: opts.manifest.scope,
  };
  publishers[opts.manifest.fromDid] = {
    ...(prior as Record<string, unknown> | undefined),
    ...((prior === undefined ? { source: "verified-signed-kit-bundle" } : {}) as object),
    verified_kit_bundle: kit,
  };
  atomicWriteBytes(
    path,
    canonicalJsonBytes({ version: 1, publishers: canonicalOrder(publishers) }),
  );
}

export interface SentOfferRecord {
  offerDigest: string;
  publisherDid: string;
  readerDid: string;
  ceremonyId: string;
  group: string;
  publicKeySha256: string;
}

/** Retain one sent offer so the eventual response can be scope-checked. */
export function recordSentOffer(keystoreDir: string, record: SentOfferRecord): void {
  requireDigest(record.offerDigest, "offer digest");
  const path = sentOffersPath(keystoreDir);
  const doc = existsSync(path)
    ? readJsonObject(path, "sent offer record")
    : { version: 1, offers: {} };
  const offers =
    doc["offers"] !== null && typeof doc["offers"] === "object" && !Array.isArray(doc["offers"])
      ? (doc["offers"] as Record<string, unknown>)
      : {};
  offers[record.offerDigest] = {
    ceremony_id: record.ceremonyId,
    group: record.group,
    publisher_did: record.publisherDid,
    reader_did: record.readerDid,
    x25519_public_key_sha256: record.publicKeySha256,
  };
  atomicWriteBytes(path, canonicalJsonBytes({ version: 1, offers: canonicalOrder(offers) }));
}

function loadSentOffer(keystoreDir: string, offerDigest: string): SentOfferRecord | null {
  const path = sentOffersPath(keystoreDir);
  if (!existsSync(path)) return null;
  const doc = readJsonObject(path, "sent offer record");
  const offers = doc["offers"];
  if (offers === null || typeof offers !== "object" || Array.isArray(offers)) return null;
  const entry = (offers as Record<string, unknown>)[offerDigest];
  if (entry === undefined || entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    return null;
  }
  const record = entry as Record<string, unknown>;
  const str = (key: string): string => {
    const v = record[key];
    if (typeof v !== "string") {
      throw error("statement_invalid", "retained sent-offer record is malformed");
    }
    return v;
  };
  return {
    offerDigest,
    publisherDid: str("publisher_did"),
    readerDid: str("reader_did"),
    ceremonyId: str("ceremony_id"),
    group: str("group"),
    publicKeySha256: str("x25519_public_key_sha256"),
  };
}

export interface BuildJweOfferOptions {
  readerKey: DeviceKey;
  readerKeystoreDir: string;
  publisherDid: string;
  ceremonyId: string;
  group: string;
  challenge: EnrollmentChallengeV1 | null;
  now?: string;
  /** Unsolicited offers only: acceptance window (default ten minutes). */
  ttlMs?: number;
  /** Skip retaining the sent-offer record (default: retained). */
  retain?: boolean;
  /** Test hook: put a different key into the unsigned payload mirror. */
  unsignedPayloadPublicKey?: Uint8Array;
  /** Test hook: bind a challenge digest without verifying/retaining it. */
  skipChallengeVerification?: boolean;
}

export interface BuiltJweOffer {
  artifact: Uint8Array;
  proof: KeyBindingProofV1;
  offerDigest: string;
  publicKey: Uint8Array;
  publicKeySha256: string;
}

/**
 * Build the reader-side signed JWE enrollment offer `.tnpkg`.
 *
 * Verifies the publisher-signed challenge (when present) BEFORE creating or
 * reusing the static reader key and signing anything, binds the exact
 * challenge digest into the proof, and signs both the inner package and the
 * outer manifest (with its body digest index) with the reader's device key.
 */
export function buildJweOfferArtifact(opts: BuildJweOfferOptions): BuiltJweOffer {
  const now = opts.now ?? nowTimestamp();
  parseEd25519DidKey(opts.publisherDid);
  const challenge = opts.challenge;
  let ceremonyId = opts.ceremonyId;
  let group = opts.group;
  let issuedAt = now;
  let expiresAt: string;
  let challengeDigest: string | null = null;

  if (challenge !== null) {
    if (challenge.ceremony_id !== ceremonyId || challenge.group !== group) {
      throw error("scope_mismatch", "challenge ceremony or group does not match the offer request");
    }
    if (challenge.publisher_did !== opts.publisherDid) {
      throw error("did_signer_mismatch", "challenge publisher does not match the offer recipient");
    }
    if (opts.skipChallengeVerification !== true) {
      verifyEnrollmentChallenge(challenge, {
        publisherDid: opts.publisherDid,
        readerDid: opts.readerKey.did,
        ceremonyId: challenge.ceremony_id,
        group: challenge.group,
        now,
      });
    }
    ceremonyId = challenge.ceremony_id;
    group = challenge.group;
    issuedAt = now;
    expiresAt = challenge.expires_at;
    challengeDigest = enrollmentChallengeDigest(challenge);
  } else {
    const ttl = opts.ttlMs ?? 10 * 60_000;
    expiresAt = formatTrustTimestamp(parseTrustTimestamp(now, "now") + Math.round(ttl) * 1000);
  }

  const publicKey = ensureJweReaderKey(opts.readerKeystoreDir, group);
  const proof = signKeyBindingProof(
    {
      version: 1,
      purpose: "jwe-reader",
      subject_did: opts.readerKey.did,
      audience_did: opts.publisherDid,
      ceremony_id: ceremonyId,
      group,
      issued_at: issuedAt,
      expires_at: expiresAt,
      nonce_b64: bytesToB64(randomBytes(32)),
      binding: {
        algorithm: "X25519",
        public_key_b64: bytesToB64(publicKey),
        challenge_digest: challengeDigest,
      },
      signature_b64: "",
    },
    opts.readerKey,
  );

  const payloadPublicKey = opts.unsignedPayloadPublicKey ?? publicKey;
  const pkg = signTnPackage(
    {
      package_version: 1,
      package_kind: "offer",
      ceremony_id: ceremonyId,
      group,
      group_epoch: 0,
      device_identity: opts.readerKey.did,
      signer_verify_pub_b64: "",
      recipient_identity: opts.publisherDid,
      payload: {
        key_binding_proof: { ...proof, binding: { ...proof.binding } },
        x25519_pub_b64: bytesToB64(payloadPublicKey),
      },
      compiled_at: issuedAt,
    },
    opts.readerKey,
  );
  const body = { "body/package.json": canonicalize(tnPackageWireValue(pkg)) };
  const manifest = newManifest({
    kind: "offer",
    fromDid: opts.readerKey.did,
    ceremonyId,
    scope: group,
    toDid: opts.publisherDid,
  });
  manifest.asOf = issuedAt;
  manifest.eventCount = 1;
  signManifestWithBody(manifest, body, opts.readerKey);
  const artifact = packTnpkgBytes(manifest, body);
  const offerDigest = keyBindingProofDigest(proof);
  const publicKeySha256 = sha256Digest(publicKey);

  if (opts.retain !== false) {
    recordSentOffer(opts.readerKeystoreDir, {
      offerDigest,
      publisherDid: opts.publisherDid,
      readerDid: opts.readerKey.did,
      ceremonyId,
      group,
      publicKeySha256,
    });
  }
  return { artifact, proof, offerDigest, publicKey, publicKeySha256 };
}

export interface InstalledPublisher {
  publisherDid: string;
  group: string;
  groupEpoch: number;
  offerDigest: string;
  responseDigest: string;
}

interface EnrollmentInstallExpectation {
  publisherDid: string;
  readerDid: string;
  ceremonyId: string;
  group: string;
  publicKeySha256: string;
  referenceDigest: string;
  bindingDigest: string;
}

function enrollmentInstallExpectation(
  keystoreDir: string,
  referenceDigest: string,
  now: string,
): EnrollmentInstallExpectation | null {
  const retained = loadSentOffer(keystoreDir, referenceDigest);
  if (retained !== null) {
    return { ...retained, referenceDigest, bindingDigest: referenceDigest };
  }
  const direct = loadJweActivationExpectation(keystoreDir, referenceDigest);
  if (direct === null) return null;
  if (
    parseTrustTimestamp(direct.expiresAt, "expectation expires_at") <=
    parseTrustTimestamp(now, "now")
  ) {
    throw error("statement_expired", "JWE activation expectation has expired");
  }
  return {
    publisherDid: direct.publisherDid,
    readerDid: direct.readerDid,
    ceremonyId: direct.ceremonyId,
    group: direct.group,
    publicKeySha256: direct.x25519PublicKeySha256,
    referenceDigest,
    bindingDigest: direct.bindingDigest,
  };
}

/**
 * Reader-side verification and installation of an accepted-enrollment
 * response. The response must name a retained sent offer, the local
 * `.jwe.mykey` must already exist and derive the named public key, and every
 * scope/digest/signature check passes before publisher metadata is written to
 * `<keystore>/trust/verified_publishers.v1.json`.
 */
export function installEnrollmentResponse(opts: {
  keystoreDir: string;
  readerDid: string;
  response: unknown;
  now?: string;
}): InstalledPublisher {
  const now = opts.now ?? nowTimestamp();
  const response: EnrollmentResponseV1 = parseEnrollmentResponse(opts.response);
  if (response.reader_did !== opts.readerDid) {
    throw error("wrong_recipient", "response names a different reader");
  }
  const expected = enrollmentInstallExpectation(
    opts.keystoreDir,
    response.accepted_offer_digest,
    now,
  );
  if (expected === null) {
    throw error(
      "scope_mismatch",
      "response matches neither a retained sent offer nor an approved activation expectation",
    );
  }
  if (expected.readerDid !== opts.readerDid) {
    throw error("wrong_recipient", "retained offer names a different reader");
  }
  const myKeyPath = join(opts.keystoreDir, `${validateGroupFileName(expected.group)}.jwe.mykey`);
  if (!existsSync(myKeyPath)) {
    throw error("binding_invalid", "local reader key is missing for the enrolled group");
  }
  const priv = new Uint8Array(readFileSync(myKeyPath));
  let derivedDigest: string;
  try {
    if (priv.length !== 32) {
      throw error("binding_invalid", "local reader key is malformed");
    }
    derivedDigest = sha256Digest(x25519.getPublicKey(priv));
    if (derivedDigest !== expected.publicKeySha256) {
      throw error("binding_invalid", "local reader key does not derive the offered public key");
    }
    verifyEnrollmentResponse(response, {
      publisherDid: expected.publisherDid,
      readerDid: opts.readerDid,
      ceremonyId: expected.ceremonyId,
      group: expected.group,
      offerDigest: expected.referenceDigest,
      publicKeySha256: derivedDigest,
      now,
    });
  } finally {
    priv.fill(0);
  }

  const path = verifiedPublishersPath(opts.keystoreDir);
  const doc = existsSync(path)
    ? readJsonObject(path, "verified publisher record")
    : { version: 1, publishers: {} };
  const publishers =
    doc["publishers"] !== null &&
    typeof doc["publishers"] === "object" &&
    !Array.isArray(doc["publishers"])
      ? (doc["publishers"] as Record<string, unknown>)
      : {};
  const responseDigest = enrollmentResponseDigest(response);
  publishers[response.publisher_did] = {
    accepted_offer_digest: response.accepted_offer_digest,
    ceremony_id: response.ceremony_id,
    group: response.group,
    group_epoch: response.group_epoch,
    binding_digest: expected.bindingDigest,
    installed_at: now,
    response_digest: responseDigest,
    source: "enrollment-response",
    x25519_public_key_sha256: response.x25519_public_key_sha256,
  };
  atomicWriteBytes(
    path,
    canonicalJsonBytes({ version: 1, publishers: canonicalOrder(publishers) }),
  );
  return {
    publisherDid: response.publisher_did,
    group: response.group,
    groupEpoch: response.group_epoch,
    offerDigest: response.accepted_offer_digest,
    responseDigest,
  };
}

export interface BuildJweActivationArtifactOptions {
  publisherKey: DeviceKey;
  ceremonyId: string;
  group: string;
  groupEpoch: number;
  recipient: VerifiedJweRecipient;
  ttlMs: number;
  now?: string;
}

function activationResponse(
  opts: BuildJweActivationArtifactOptions,
  recipient: VerifiedJweRecipient,
  nowMicros: number,
): EnrollmentResponseV1 {
  return signEnrollmentResponse(
    {
      version: 1,
      kind: "tn-enrollment-response",
      publisher_did: opts.publisherKey.did,
      reader_did: recipient.readerDid,
      ceremony_id: opts.ceremonyId,
      group: opts.group,
      accepted_offer_digest: jweActivationReferenceDigest(recipient),
      x25519_public_key_sha256: recipient.publicKeySha256,
      group_epoch: opts.groupEpoch,
      issued_at: formatTrustTimestamp(nowMicros),
      expires_at: formatTrustTimestamp(nowMicros + opts.ttlMs * 1000),
      signature_b64: "",
    },
    opts.publisherKey,
  );
}

function packActivationArtifact(
  opts: BuildJweActivationArtifactOptions,
  recipient: VerifiedJweRecipient,
  response: EnrollmentResponseV1,
): Uint8Array {
  const pkg = signTnPackage(
    {
      package_version: 1,
      package_kind: "enrolment",
      ceremony_id: opts.ceremonyId,
      group: opts.group,
      group_epoch: opts.groupEpoch,
      device_identity: opts.publisherKey.did,
      signer_verify_pub_b64: "",
      recipient_identity: recipient.readerDid,
      payload: { enrollment_response: { ...response } },
      compiled_at: response.issued_at,
    },
    opts.publisherKey,
  );
  const body = { "body/package.json": canonicalize(tnPackageWireValue(pkg)) };
  const manifest = newManifest({
    kind: "enrolment",
    fromDid: opts.publisherKey.did,
    ceremonyId: opts.ceremonyId,
    scope: opts.group,
    toDid: recipient.readerDid,
  });
  manifest.eventCount = 1;
  signManifestWithBody(manifest, body, opts.publisherKey);
  return packTnpkgBytes(manifest, body);
}

function buildJweActivationArtifactCore(
  opts: BuildJweActivationArtifactOptions,
  allowSignedEvidence: boolean,
): { artifact: Uint8Array; response: EnrollmentResponseV1 } {
  const now = opts.now ?? nowTimestamp();
  const recipient = validateVerifiedJweRecipient(opts.recipient, now);
  if (
    !allowSignedEvidence &&
    (recipient.evidence.kind === "signed-key-card" ||
      recipient.evidence.kind === "challenge-response")
  ) {
    throw error("untrusted_principal", "signed JWE evidence requires a reconciled accepted offer");
  }
  if (recipient.audienceDid !== opts.publisherKey.did) {
    throw error("wrong_recipient", "JWE binding names a different publisher");
  }
  if (recipient.ceremonyId !== opts.ceremonyId || recipient.group !== opts.group) {
    throw error("scope_mismatch", "JWE binding ceremony or group does not match");
  }
  if (!Number.isSafeInteger(opts.ttlMs) || opts.ttlMs <= 0) {
    throw error("statement_invalid", "response ttl must be a positive safe integer");
  }
  const nowMicros = parseTrustTimestamp(now, "now");
  const response = activationResponse(opts, recipient, nowMicros);
  return { artifact: packActivationArtifact(opts, recipient, response), response };
}

/** Build one direct DID-document/fingerprint activation. */
export function buildJweActivationArtifact(opts: BuildJweActivationArtifactOptions): {
  artifact: Uint8Array;
  response: EnrollmentResponseV1;
} {
  return buildJweActivationArtifactCore(opts, false);
}

/** Compatibility adapter for the reconciled AcceptedOffer surface. */
export function buildEnrollmentResponseArtifact(opts: {
  publisherKey: DeviceKey;
  ceremonyId: string;
  group: string;
  groupEpoch: number;
  accepted: AcceptedOffer;
  ttlMs: number;
  now?: string;
}): { artifact: Uint8Array; response: EnrollmentResponseV1 } {
  assertReconciledAcceptedOffer(opts.accepted);
  return buildJweActivationArtifactCore(
    {
      publisherKey: opts.publisherKey,
      ceremonyId: opts.ceremonyId,
      group: opts.group,
      groupEpoch: opts.groupEpoch,
      recipient: jweRecipientFromAcceptedOffer(opts.accepted),
      ttlMs: opts.ttlMs,
      ...(opts.now === undefined ? {} : { now: opts.now }),
    },
    true,
  );
}
