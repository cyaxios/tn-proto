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
  hibeOpen,
  hibeSeal,
  hibeSetup,
} from "../raw.js";

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

function validateHibeIdentityPath(path: string, subject = "identity path"): string {
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
  _atomicWrite(
    join(keystorePath, `${group}.hibe.idpath.history`),
    nextPriorPaths.join("\n") + "\n",
  );
  const skPath = join(keystorePath, `${group}.hibe.sk`);
  const idpathPath = join(keystorePath, `${group}.hibe.idpath`);
  const skPending = `${skPath}.pending`;
  const idpathPending = `${idpathPath}.pending`;
  _atomicWriteSecret(skPending, sk);
  _atomicWrite(idpathPending, newPath);
  renameSync(skPending, skPath);
  renameSync(idpathPending, idpathPath);
  mat.priorPaths = nextPriorPaths;
  mat.sk = sk;
  mat.idPath = newPath;
}

/** SHA-256 fingerprint of the authority mpk. */
export function hibeGroupMpkFingerprint(mat: HibeGroupMaterial): Uint8Array {
  return hibeMpkFingerprint(mat.mpk);
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
