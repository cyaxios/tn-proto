// HIBE group keystore material — the TS mirror of Python's
// `tn.cipher.HibeGroupCipher` (python/tn/cipher.py). One group's hibe
// material lives in flat keystore files:
//
//   <keystore>/<group>.hibe.mpk             authority PublicParams (public)
//   <keystore>/<group>.hibe.idpath          identity path seals target (public, utf-8)
//   <keystore>/<group>.hibe.sk              delegated identity key (SECRET)
//   <keystore>/<group>.hibe.msk             master secret (SECRET; authority only)
//   <keystore>/<group>.hibe.idpath.history  prior sealing paths, one per line
//   <keystore>/<group>.hibe.sk.previous.<ts> superseded identity keys (absorb renames)
//
// Writing needs only mpk + idpath (hibeSeal). Reading tries every key this
// keystore can legitimately produce: the held sk as-is, the held sk derived
// down to the current path, each superseded `.previous` sk, and — for the
// authority — msk-minted keys for the current and every prior path.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { Buffer } from "node:buffer";
import { join } from "node:path";

import {
  hibeDelegate,
  hibeKeyIdPath,
  hibeKeygen,
  hibeMpkFingerprint,
  hibeMpkMaxDepth,
  hibeOpen,
  hibeSeal,
  hibeSetup,
} from "../raw.js";
import {
  TrustError,
  parseEd25519DidKey,
  parseTrustTimestamp,
  sha256Digest,
} from "../core/trust.js";
import {
  durableAtomicWrite,
  durableUnlink,
  withDurableFileLock,
} from "./durable_state.js";

/** All on-disk hibe material for one (keystore, group). */
export interface HibeGroupMaterial {
  /** Authority master public key bytes. */
  mpk: Uint8Array;
  /** Identity path this group currently seals to. */
  idPath: string;
  /** Delegated identity key (reader key), when this keystore holds one. */
  sk?: Uint8Array;
  /** Authority master secret — present only when this keystore IS the authority. */
  msk?: Uint8Array;
  /** Paths this group sealed to before rotations, newest first. */
  priorPaths: string[];
  /** Superseded identity keys, newest first (`.hibe.sk.previous.<ts>`). */
  priorSks: Uint8Array[];
}

function validateHibeGroupName(group: string): string {
  if (
    group.length === 0 ||
    group !== group.trim() ||
    group === "." ||
    group === ".." ||
    group.includes("/") ||
    group.includes("\\") ||
    group.includes("\0")
  ) {
    throw new Error(`HIBE: invalid group name ${JSON.stringify(group)} for keystore filenames`);
  }
  return group;
}

export function validateHibeIdentityPath(path: string, subject = "identity path"): string {
  if (path.length === 0) {
    throw new Error(`HIBE: invalid ${subject}: empty identity path`);
  }
  if (path !== path.trim()) {
    throw new Error(`HIBE: invalid ${subject}: leading/trailing whitespace is not allowed`);
  }
  if (path.includes("\\") || path.includes("\0")) {
    throw new Error(`HIBE: invalid ${subject}: labels must not contain path separators`);
  }
  const labels = path.split("/");
  for (const label of labels) {
    if (label.length === 0) {
      throw new Error(`HIBE: invalid ${subject}: empty path segment in ${JSON.stringify(path)}`);
    }
    if (label === "." || label === "..") {
      throw new Error(`HIBE: invalid ${subject}: traversal segment ${JSON.stringify(label)}`);
    }
    if (label !== label.trim()) {
      throw new Error(`HIBE: invalid ${subject}: whitespace-only label mutation`);
    }
  }
  return path;
}

function readHibeIdPath(path: string, subject = "identity path"): string {
  return validateHibeIdentityPath(readFileSync(path, "utf8"), subject);
}

function readHibeHistory(path: string): string[] {
  const raw = readFileSync(path, "utf8").split(/\r?\n/);
  const out: string[] = [];
  for (let i = 0; i < raw.length; i += 1) {
    const line = raw[i]!;
    if (line.length === 0 && i === raw.length - 1) continue;
    if (line.length === 0) {
      throw new Error("HIBE: invalid identity path history: empty path segment");
    }
    out.push(validateHibeIdentityPath(line, "prior identity path"));
  }
  return out;
}

/** Atomic-ish write: temp + rename (same posture as Python's
 * `_atomic_write_text` — rename is not guaranteed atomic on Windows but
 * is far safer than a truncating write). */
function _atomicWrite(path: string, data: Uint8Array | string): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data));
  renameSync(tmp, path);
}

/** Owner-only (0600) atomic write for secret key material — the HIBE master
 *  secret (`msk`) and delegated identity key (`sk`). The temp is created fresh
 *  with mode 0600 and rename carries those bits onto the target (so a rotation
 *  rewrite re-tightens perms too). A bare writeFileSync would inherit the umask
 *  and leave the master secret world-readable (0644). On Windows the mode is a
 *  no-op; the user-profile ACL is the protection, same as local.private. */
function _atomicWriteSecret(path: string, data: Uint8Array): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, Buffer.from(data), { mode: 0o600 });
  renameSync(tmp, path);
}

/** Load a group's hibe material, or `null` when the keystore has no
 * `<group>.hibe.mpk`. Throws when the mpk exists but `.idpath` is missing
 * (mirrors Python `HibeGroupCipher.load`'s CipherError). */
export function loadHibeGroup(keystorePath: string, group: string): HibeGroupMaterial | null {
  validateHibeGroupName(group);
  recoverHibeAuthorityInstall(keystorePath, group);
  recoverHibeRotation(keystorePath, group);
  const mpkPath = join(keystorePath, `${group}.hibe.mpk`);
  if (!existsSync(mpkPath)) return null;
  const idpathPath = join(keystorePath, `${group}.hibe.idpath`);
  if (!existsSync(idpathPath)) {
    throw new Error(
      `HIBE: keystore is missing ${group}.hibe.idpath; ` +
        `was this group minted (or its kit absorbed) here?`,
    );
  }
  const skPath = join(keystorePath, `${group}.hibe.sk`);
  const mskPath = join(keystorePath, `${group}.hibe.msk`);
  const historyPath = join(keystorePath, `${group}.hibe.idpath.history`);
  const priorPaths = existsSync(historyPath) ? readHibeHistory(historyPath) : [];
  const previousPrefix = `${group}.hibe.sk.previous.`;
  const priorSks = readdirSync(keystorePath)
    .filter((e) => e.startsWith(previousPrefix))
    .sort()
    .reverse()
    .map((e) => new Uint8Array(readFileSync(join(keystorePath, e))));
  const mat: HibeGroupMaterial = {
    mpk: new Uint8Array(readFileSync(mpkPath)),
    idPath: readHibeIdPath(idpathPath),
    priorPaths,
    priorSks,
  };
  if (existsSync(skPath)) mat.sk = new Uint8Array(readFileSync(skPath));
  if (existsSync(mskPath)) mat.msk = new Uint8Array(readFileSync(mskPath));
  return mat;
}

/** Mint a fresh hibe group as its OWN authority (the solo-ceremony default,
 * matching Python `HibeGroupCipher.create` without `authority_mpk`): run
 * Setup, keep the msk, and self-delegate a reader key for `idPath`
 * (default `"self"`). With `authorityMpk` plus `idPath`, create a write-only
 * group under an external authority: only `.hibe.mpk` and `.hibe.idpath` are
 * written, and no local reader key or master secret is minted.
 *
 * Throws when `group` is unsafe for flat keystore filenames, when `idPath`
 * has empty/traversal/whitespace-mutating segments, or when `authorityMpk`
 * is malformed. */
export function createHibeGroup(
  keystorePath: string,
  group: string,
  opts: { idPath?: string; maxDepth?: number; authorityMpk?: Uint8Array } = {},
): HibeGroupMaterial {
  validateHibeGroupName(group);
  const path = validateHibeIdentityPath(opts.idPath ?? "self");
  const maxDepth = opts.maxDepth ?? 2;
  mkdirSync(keystorePath, { recursive: true });

  if (opts.authorityMpk !== undefined) {
    if (opts.idPath === undefined) {
      throw new Error("HIBE.create: idPath is required when authorityMpk is provided");
    }
    const mpk = new Uint8Array(opts.authorityMpk);
    hibeMpkFingerprint(mpk);
    writeFileSync(join(keystorePath, `${group}.hibe.mpk`), Buffer.from(mpk));
    _atomicWrite(join(keystorePath, `${group}.hibe.idpath`), path);
    return { mpk, idPath: path, priorPaths: [], priorSks: [] };
  }

  const setup = hibeSetup(maxDepth) as { mpk_b64: string; msk_b64: string };
  const mpk = new Uint8Array(Buffer.from(setup.mpk_b64, "base64"));
  const msk = new Uint8Array(Buffer.from(setup.msk_b64, "base64"));
  const sk = hibeKeygen(mpk, msk, path);
  _atomicWriteSecret(join(keystorePath, `${group}.hibe.msk`), msk);
  _atomicWriteSecret(join(keystorePath, `${group}.hibe.sk`), sk);
  writeFileSync(join(keystorePath, `${group}.hibe.mpk`), Buffer.from(mpk));
  _atomicWrite(join(keystorePath, `${group}.hibe.idpath`), path);
  return { mpk, idPath: path, sk, msk, priorPaths: [], priorSks: [] };
}

/** Seal a group plaintext to the group's current identity path. Needs only
 * the public half (mpk + idpath) — any holder can write. ``aad`` is bound
 * (authenticated, not encrypted); empty binds nothing and uses the same wire
 * shape as a plain seal. */
export function hibeEncrypt(
  mat: HibeGroupMaterial,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (mat.mpk.length === 0 || !mat.idPath) {
    throw new Error("HIBE: no authority mpk / identity path in this keystore");
  }
  return hibeSeal(
    mat.mpk,
    validateHibeIdentityPath(mat.idPath),
    plaintext,
    aad.length > 0 ? aad : undefined,
  );
}

/** The held key if it sits on `targetPath`, derived down from an ancestor
 * when needed (BBG opens only with an exact-path key). `null` when the held
 * key is absent or not an ancestor. Mirrors Python `_derive_from_held`. */
function _deriveFromHeld(mat: HibeGroupMaterial, targetPath: string): Uint8Array | null {
  targetPath = validateHibeIdentityPath(targetPath);
  if (mat.sk === undefined) return null;
  const held = hibeKeyIdPath(mat.sk);
  if (held === targetPath) return mat.sk;
  const targetLabels = targetPath.split("/");
  const heldLabels = held ? held.split("/") : [];
  for (let i = 0; i < heldLabels.length; i += 1) {
    if (heldLabels[i] !== targetLabels[i]) return null;
  }
  if (heldLabels.length > targetLabels.length) return null;
  let sk = mat.sk;
  for (const label of targetLabels.slice(heldLabels.length)) {
    sk = hibeDelegate(mat.mpk, sk, label);
  }
  return sk;
}

/** Decryption-key candidates, most likely first, without minting the same
 * path twice. Mirrors Python `HibeGroupCipher._candidate_keys`. */
export function hibeCandidateKeys(mat: HibeGroupMaterial): Uint8Array[] {
  const out: Uint8Array[] = [];
  const seen = new Set<string>();
  if (mat.sk !== undefined) {
    seen.add(hibeKeyIdPath(mat.sk));
    out.push(mat.sk);
  }
  const derived = _deriveFromHeld(mat, mat.idPath);
  if (derived !== null && !seen.has(mat.idPath)) {
    seen.add(mat.idPath);
    out.push(derived);
  }
  for (const oldSk of mat.priorSks) {
    const path = hibeKeyIdPath(oldSk);
    if (seen.has(path)) continue;
    seen.add(path);
    out.push(oldSk);
  }
  if (mat.msk !== undefined) {
    for (const path of [mat.idPath, ...mat.priorPaths]) {
      if (seen.has(path)) continue;
      seen.add(path);
      out.push(hibeKeygen(mat.mpk, mat.msk, path));
    }
  }
  return out;
}

/** Open a group blob by trying every candidate key. ``aad`` must byte-match
 * whatever was bound at seal time (empty when the group bound nothing).
 * Throws when no key in this keystore opens it (callers surface
 * `$no_read_key`). */
export function hibeDecrypt(
  mat: HibeGroupMaterial,
  ciphertext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const candidates = hibeCandidateKeys(mat);
  if (candidates.length === 0) {
    throw new Error("HIBE: no delegated identity key for this group's path in this keystore");
  }
  const aadArg = aad.length > 0 ? aad : undefined;
  for (const sk of candidates) {
    try {
      return hibeOpen(mat.mpk, sk, ciphertext, aadArg);
    } catch {
      /* try the next candidate */
    }
  }
  throw new Error(
    "HIBE: no identity key in this keystore opens this group's ciphertext " +
      "(sealed to a different path, or tampered bytes)",
  );
}

/** Authority-side grant: generate the identity key for `idPath` from the
 * msk. BBG re-randomizes KeyGen, so each grantee holds distinct key
 * material for the same path. */
export function hibeMintReaderKey(mat: HibeGroupMaterial, idPath: string): Uint8Array {
  if (mat.msk === undefined) {
    throw new Error("HIBE: only the authority (msk holder) can mint reader keys");
  }
  return hibeKeygen(mat.mpk, mat.msk, validateHibeIdentityPath(idPath));
}

interface HibeRotationTransaction {
  version: 1;
  group: string;
  mpk_sha256: string;
  new_path: string;
  prior_paths: string[];
  sk_b64: string;
}

function hibeRotationPath(keystorePath: string, group: string): string {
  return join(keystorePath, `${group}.hibe.rotation.v1.json`);
}

function recoverHibeRotationUnlocked(keystorePath: string, group: string): boolean {
  const marker = hibeRotationPath(keystorePath, group);
  if (!existsSync(marker)) return false;
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(marker, "utf8"));
  } catch {
    throw new Error("HIBE: rotation transaction is unreadable");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("HIBE: rotation transaction is malformed");
  }
  const tx = value as Partial<HibeRotationTransaction>;
  if (
    tx.version !== 1 ||
    tx.group !== group ||
    typeof tx.mpk_sha256 !== "string" ||
    typeof tx.new_path !== "string" ||
    !Array.isArray(tx.prior_paths) ||
    !tx.prior_paths.every((path) => typeof path === "string") ||
    typeof tx.sk_b64 !== "string"
  ) {
    throw new Error("HIBE: rotation transaction is malformed");
  }
  const mpkPath = join(keystorePath, `${group}.hibe.mpk`);
  if (!existsSync(mpkPath) || sha256Digest(new Uint8Array(readFileSync(mpkPath))) !== tx.mpk_sha256) {
    throw new Error("HIBE: rotation transaction belongs to different authority material");
  }
  const newPath = validateHibeIdentityPath(tx.new_path, "rotation target path");
  const priorPaths = tx.prior_paths.map((path) =>
    validateHibeIdentityPath(path, "rotation prior path"),
  );
  const skBytes = Buffer.from(tx.sk_b64, "base64");
  if (skBytes.toString("base64") !== tx.sk_b64 || skBytes.length === 0) {
    throw new Error("HIBE: rotation transaction contains an invalid identity key");
  }
  durableAtomicWrite(
    join(keystorePath, `${group}.hibe.idpath.history`),
    priorPaths.join("\n") + "\n",
  );
  durableAtomicWrite(join(keystorePath, `${group}.hibe.sk`), new Uint8Array(skBytes));
  durableAtomicWrite(join(keystorePath, `${group}.hibe.idpath`), newPath);
  durableUnlink(marker);
  return true;
}

/** Complete a crash-interrupted authority identity-path rotation. */
export function recoverHibeRotation(keystorePath: string, group: string): boolean {
  validateHibeGroupName(group);
  const marker = hibeRotationPath(keystorePath, group);
  if (!existsSync(marker)) return false;
  return withDurableFileLock(`${marker}.lock`, () =>
    recoverHibeRotationUnlocked(keystorePath, group),
  );
}

/** Point future seals at `newPath` (admission rotation, not revocation).
 * Authority-only: mints this keystore's own fresh key for the new path,
 * records the outgoing path in `.idpath.history` (newest first), and
 * refreshes the in-memory material. Mirrors Python `rotate_id_path`. */
export function hibeRotateIdPath(
  keystorePath: string,
  group: string,
  mat: HibeGroupMaterial,
  newPath: string,
): void {
  validateHibeGroupName(group);
  const marker = hibeRotationPath(keystorePath, group);
  withDurableFileLock(`${marker}.lock`, () => {
    recoverHibeRotationUnlocked(keystorePath, group);
    const currentPath = validateHibeIdentityPath(mat.idPath, "current identity path");
    newPath = validateHibeIdentityPath(newPath, "new identity path");
    if (mat.msk === undefined) {
      throw new Error("HIBE: only the authority (msk holder) can rotate the identity path");
    }
    if (newPath === currentPath) {
      throw new Error(`HIBE: new path equals the current path ${JSON.stringify(newPath)}`);
    }
    const sk = hibeKeygen(mat.mpk, mat.msk, newPath);
    const nextPriorPaths = [currentPath, ...mat.priorPaths];
    const tx: HibeRotationTransaction = {
      version: 1,
      group,
      mpk_sha256: sha256Digest(mat.mpk),
      new_path: newPath,
      prior_paths: nextPriorPaths,
      sk_b64: Buffer.from(sk).toString("base64"),
    };
    durableAtomicWrite(marker, JSON.stringify(tx, null, 2) + "\n");
    recoverHibeRotationUnlocked(keystorePath, group);
    mat.priorPaths = nextPriorPaths;
    mat.sk = sk;
    mat.idPath = newPath;
  });
}

/** SHA-256 fingerprint of the authority mpk. */
export function hibeGroupMpkFingerprint(mat: HibeGroupMaterial): Uint8Array {
  return hibeMpkFingerprint(mat.mpk);
}

/** The maximum identity-path depth encoded in raw MPK bytes. */
export function hibeGroupMpkMaxDepth(mpk: Uint8Array): number {
  return Number(hibeMpkMaxDepth(mpk));
}

/**
 * The authority's current path epoch, derived from durable state: every
 * completed identity-path rotation records the outgoing path in
 * `.idpath.history`, so the epoch is exactly the number of prior paths.
 */
export function hibeAuthorityEpoch(mat: HibeGroupMaterial): number {
  return mat.priorPaths.length;
}

// ── Pinned external-authority trust state ───────────────────────────
//
// An external writer must pin WHICH real authority DID signed its MPK and
// current path epoch before it may seal. The pinned record lives beside the
// other receiver-local trust records under `<keystore>/trust/`.

/** One pinned authority record for a hibe group. */
export interface PinnedHibeAuthority {
  authorityDid: string;
  audienceDid: string;
  ceremonyId: string;
  group: string;
  mpkSha256: string;
  maxDepth: number;
  idPath: string;
  pathEpoch: number;
  assertionDigest: string;
  issuedAt: string;
  expiresAt: string;
}

function validatePinnedHibeAuthorityRecord(
  group: string,
  record: PinnedHibeAuthority,
): void {
  validateHibeGroupName(group);
  if (record.group !== group) {
    throw new TrustError("scope_mismatch", "pinned authority record names a different group");
  }
  parseEd25519DidKey(record.authorityDid);
  parseEd25519DidKey(record.audienceDid);
  validateHibeIdentityPath(record.idPath, "pinned identity path");
  if (!Number.isSafeInteger(record.maxDepth) || record.maxDepth <= 0) {
    throw new TrustError("statement_invalid", "pinned authority max depth must be positive");
  }
  if (!Number.isSafeInteger(record.pathEpoch) || record.pathEpoch < 0) {
    throw new TrustError("statement_invalid", "pinned authority path epoch must be non-negative");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(record.mpkSha256)) {
    throw new TrustError("statement_invalid", "pinned authority MPK digest is malformed");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(record.assertionDigest)) {
    throw new TrustError("statement_invalid", "pinned authority assertion digest is malformed");
  }
  const issued = parseTrustTimestamp(record.issuedAt, "issued_at");
  const expires = parseTrustTimestamp(record.expiresAt, "expires_at");
  if (expires <= issued) {
    throw new TrustError("statement_invalid", "pinned authority expiry must follow issuance");
  }
}

function assertHibePinTransition(
  pinned: PinnedHibeAuthority | null,
  record: PinnedHibeAuthority,
): void {
  if (pinned === null) return;
  if (pinned.authorityDid !== record.authorityDid) {
    throw new TrustError("untrusted_principal", "assertion is not from the pinned authority DID");
  }
  if (
    pinned.audienceDid !== record.audienceDid ||
    pinned.ceremonyId !== record.ceremonyId ||
    pinned.group !== record.group
  ) {
    throw new TrustError("scope_mismatch", "authority assertion scope differs from the pinned scope");
  }
  if (record.pathEpoch < pinned.pathEpoch) {
    throw new TrustError("epoch_rollback", "assertion path epoch is lower than the pinned epoch");
  }
  if (record.pathEpoch !== pinned.pathEpoch) return;
  const sameMaterial =
    pinned.mpkSha256 === record.mpkSha256 &&
    pinned.idPath === record.idPath &&
    pinned.maxDepth === record.maxDepth;
  if (!sameMaterial) {
    throw new TrustError("epoch_conflict", "conflicting authority material at the pinned epoch");
  }
  if (
    parseTrustTimestamp(record.issuedAt, "issued_at") <
    parseTrustTimestamp(pinned.issuedAt, "issued_at")
  ) {
    throw new TrustError("epoch_rollback", "same-epoch assertion renewal predates the pinned assertion");
  }
}

function writePinnedHibeAuthorityRecord(
  keystorePath: string,
  group: string,
  record: PinnedHibeAuthority,
): void {
  const doc = readAuthoritiesDoc(keystorePath);
  const authorities =
    doc["authorities"] !== null &&
    typeof doc["authorities"] === "object" &&
    !Array.isArray(doc["authorities"])
      ? { ...(doc["authorities"] as Record<string, unknown>) }
      : {};
  authorities[group] = {
    authority_did: record.authorityDid,
    audience_did: record.audienceDid,
    ceremony_id: record.ceremonyId,
    group: record.group,
    mpk_sha256: record.mpkSha256,
    max_depth: record.maxDepth,
    id_path: record.idPath,
    path_epoch: record.pathEpoch,
    assertion_digest: record.assertionDigest,
    issued_at: record.issuedAt,
    expires_at: record.expiresAt,
  };
  durableAtomicWrite(
    hibeAuthoritiesPath(keystorePath),
    JSON.stringify({ version: 1, authorities }, null, 1),
  );
}

/** Path of the pinned-authority trust records. */
export function hibeAuthoritiesPath(keystorePath: string): string {
  return join(keystorePath, "trust", "hibe_authorities.v1.json");
}

function readAuthoritiesDoc(keystorePath: string): Record<string, unknown> {
  const path = hibeAuthoritiesPath(keystorePath);
  if (!existsSync(path)) return { version: 1, authorities: {} };
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new TrustError("statement_invalid", "pinned hibe authority record is unreadable");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TrustError("statement_invalid", "pinned hibe authority record must be an object");
  }
  return value as Record<string, unknown>;
}

/** Load one group's pinned authority record, or null when never pinned. */
export function loadPinnedHibeAuthority(
  keystorePath: string,
  group: string,
): PinnedHibeAuthority | null {
  const doc = readAuthoritiesDoc(keystorePath);
  const authorities = doc["authorities"];
  if (authorities === null || typeof authorities !== "object" || Array.isArray(authorities)) {
    return null;
  }
  const entry = (authorities as Record<string, unknown>)[group];
  if (entry === undefined) return null;
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new TrustError("statement_invalid", "pinned hibe authority record is malformed");
  }
  const record = entry as Record<string, unknown>;
  const str = (key: string): string => {
    const v = record[key];
    if (typeof v !== "string") {
      throw new TrustError("statement_invalid", "pinned hibe authority record is malformed");
    }
    return v;
  };
  const int = (key: string): number => {
    const v = record[key];
    if (typeof v !== "number" || !Number.isSafeInteger(v)) {
      throw new TrustError("statement_invalid", "pinned hibe authority record is malformed");
    }
    return v;
  };
  return {
    authorityDid: str("authority_did"),
    audienceDid: str("audience_did"),
    ceremonyId: str("ceremony_id"),
    group: str("group"),
    mpkSha256: str("mpk_sha256"),
    maxDepth: int("max_depth"),
    idPath: str("id_path"),
    pathEpoch: int("path_epoch"),
    assertionDigest: str("assertion_digest"),
    issuedAt: str("issued_at"),
    expiresAt: str("expires_at"),
  };
}

/**
 * Atomically pin (or monotonically update) a group's authority record.
 *
 * A lower incoming epoch is `epoch_rollback`. The same epoch must be the
 * byte-identical assertion (an idempotent no-op); any difference —
 * conflicting MPK, path, depth, or assertion digest — is `epoch_conflict`.
 * A different authority DID can never update an existing pin.
 */
export function pinHibeAuthority(
  keystorePath: string,
  group: string,
  record: PinnedHibeAuthority,
): void {
  validatePinnedHibeAuthorityRecord(group, record);
  const lockPath = join(keystorePath, "trust", "hibe_authorities.lock");
  withDurableFileLock(lockPath, () => {
    const pinned = loadPinnedHibeAuthority(keystorePath, group);
    assertHibePinTransition(pinned, record);
    writePinnedHibeAuthorityRecord(keystorePath, group, record);
  });
}

interface HibeAuthorityInstallTransaction {
  version: 1;
  group: string;
  mpk_b64: string;
  id_path: string;
  record: PinnedHibeAuthority;
}

function hibeAuthorityInstallPath(keystorePath: string, group: string): string {
  return join(keystorePath, `${group}.hibe.authority-install.v1.json`);
}

function readHibeAuthorityInstall(
  keystorePath: string,
  group: string,
): { mpk: Uint8Array; idPath: string; record: PinnedHibeAuthority } {
  const path = hibeAuthorityInstallPath(keystorePath, group);
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new TrustError("statement_invalid", "HIBE authority install transaction is unreadable");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TrustError("statement_invalid", "HIBE authority install transaction is malformed");
  }
  const tx = value as Partial<HibeAuthorityInstallTransaction>;
  if (
    tx.version !== 1 ||
    tx.group !== group ||
    typeof tx.mpk_b64 !== "string" ||
    typeof tx.id_path !== "string" ||
    tx.record === null ||
    typeof tx.record !== "object" ||
    Array.isArray(tx.record)
  ) {
    throw new TrustError("statement_invalid", "HIBE authority install transaction is malformed");
  }
  const record = tx.record;
  validatePinnedHibeAuthorityRecord(group, record);
  const idPath = validateHibeIdentityPath(tx.id_path, "authority install identity path");
  const decoded = Buffer.from(tx.mpk_b64, "base64");
  if (decoded.toString("base64") !== tx.mpk_b64) {
    throw new TrustError("statement_invalid", "HIBE authority install MPK encoding is malformed");
  }
  const mpk = new Uint8Array(decoded);
  if (
    idPath !== record.idPath ||
    sha256Digest(mpk) !== record.mpkSha256 ||
    hibeGroupMpkMaxDepth(mpk) !== record.maxDepth
  ) {
    throw new TrustError(
      "binding_invalid",
      "HIBE authority install material differs from its pinned assertion",
    );
  }
  return { mpk, idPath, record };
}

function recoverHibeAuthorityInstallUnlocked(keystorePath: string, group: string): boolean {
  const transactionPath = hibeAuthorityInstallPath(keystorePath, group);
  if (!existsSync(transactionPath)) return false;
  const { mpk, idPath, record } = readHibeAuthorityInstall(keystorePath, group);
  const trustLock = join(keystorePath, "trust", "hibe_authorities.lock");
  withDurableFileLock(trustLock, () => {
    const pinned = loadPinnedHibeAuthority(keystorePath, group);
    try {
      assertHibePinTransition(pinned, record);
    } catch (err) {
      // A rejected transition (epoch rollback/conflict) is terminal, not a
      // recoverable crash — discard the marker so it cannot poison the next
      // install's recovery pass. A write failure below is different: it leaves
      // the marker so the transaction completes on the next load.
      durableUnlink(transactionPath);
      throw err;
    }
    // Promote public material before the pin. A crash in between fails closed
    // because seal-time binding checks see the old pin; the durable marker
    // completes this exact transaction on the next load.
    durableAtomicWrite(join(keystorePath, `${group}.hibe.mpk`), mpk);
    durableAtomicWrite(join(keystorePath, `${group}.hibe.idpath`), idPath);
    writePinnedHibeAuthorityRecord(keystorePath, group, record);
  });
  durableUnlink(transactionPath);
  return true;
}

/** Complete a crash-interrupted external-authority material/pin promotion. */
export function recoverHibeAuthorityInstall(keystorePath: string, group: string): boolean {
  validateHibeGroupName(group);
  const transactionPath = hibeAuthorityInstallPath(keystorePath, group);
  if (!existsSync(transactionPath)) return false;
  const installLock = `${transactionPath}.lock`;
  return withDurableFileLock(installLock, () =>
    recoverHibeAuthorityInstallUnlocked(keystorePath, group),
  );
}

/**
 * Crash-recoverable promotion of authenticated external-authority material.
 * The marker makes the multi-file update idempotent; the pin never advances
 * unless both MPK and identity path have been durably installed.
 */
export function installPinnedHibeAuthorityMaterial(
  keystorePath: string,
  group: string,
  mpk: Uint8Array,
  idPath: string,
  record: PinnedHibeAuthority,
): void {
  validatePinnedHibeAuthorityRecord(group, record);
  validateHibeIdentityPath(idPath, "authority install identity path");
  if (
    idPath !== record.idPath ||
    sha256Digest(mpk) !== record.mpkSha256 ||
    hibeGroupMpkMaxDepth(mpk) !== record.maxDepth
  ) {
    throw new TrustError(
      "binding_invalid",
      "HIBE authority install material differs from its pinned assertion",
    );
  }
  const transactionPath = hibeAuthorityInstallPath(keystorePath, group);
  const installLock = `${transactionPath}.lock`;
  withDurableFileLock(installLock, () => {
    recoverHibeAuthorityInstallUnlocked(keystorePath, group);
    const tx: HibeAuthorityInstallTransaction = {
      version: 1,
      group,
      mpk_b64: Buffer.from(mpk).toString("base64"),
      id_path: idPath,
      record,
    };
    durableAtomicWrite(transactionPath, JSON.stringify(tx, null, 2) + "\n");
    recoverHibeAuthorityInstallUnlocked(keystorePath, group);
  });
}

/**
 * Fail-closed writer-side authorization immediately before every HIBE seal.
 * Local authorities are authorized by possession of the matching MSK. A
 * write-only external group must match a live, audience-addressed pin exactly.
 */
export function assertHibeSealAuthorized(
  keystorePath: string,
  group: string,
  mat: HibeGroupMaterial,
  writerDid: string,
  now: string,
): void {
  parseEd25519DidKey(writerDid);
  if (mat.msk !== undefined) return;
  const pinned = loadPinnedHibeAuthority(keystorePath, group);
  if (pinned === null) {
    throw new TrustError(
      "untrusted_principal",
      "external HIBE writer has no authenticated authority assertion pin",
    );
  }
  if (pinned.audienceDid !== writerDid) {
    throw new TrustError("wrong_recipient", "authority assertion pin names a different writer");
  }
  const at = parseTrustTimestamp(now, "now");
  if (at < parseTrustTimestamp(pinned.issuedAt, "issued_at")) {
    throw new TrustError("statement_invalid", "authority assertion is not yet valid");
  }
  if (at >= parseTrustTimestamp(pinned.expiresAt, "expires_at")) {
    throw new TrustError("statement_expired", "authority assertion pin has expired");
  }
  let encodedDepth: number;
  try {
    encodedDepth = hibeGroupMpkMaxDepth(mat.mpk);
  } catch {
    throw new TrustError("binding_invalid", "installed HIBE MPK is malformed");
  }
  if (
    pinned.group !== group ||
    pinned.mpkSha256 !== sha256Digest(mat.mpk) ||
    pinned.maxDepth !== encodedDepth ||
    pinned.idPath !== mat.idPath
  ) {
    throw new TrustError("binding_invalid", "installed HIBE material differs from the authenticated pin");
  }
}

/** Sibling successor of `path`: bump a `~r<n>` counter on the last label
 * (`policy-a` → `policy-a~r1` → `policy-a~r2`). Mirrors Python
 * `tn.admin._bump_path`. */
export function hibeBumpPath(path: string): string {
  const labels = validateHibeIdentityPath(path).split("/");
  const last = labels[labels.length - 1]!;
  const m = /^(.*?)~r(\d+)$/.exec(last);
  labels[labels.length - 1] = m ? `${m[1]}~r${Number(m[2]) + 1}` : `${last}~r1`;
  return labels.join("/");
}
