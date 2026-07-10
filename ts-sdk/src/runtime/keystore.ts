// Keystore on-disk layout (mirrors Python tn.logger + tn.cipher.BtnGroupCipher
// / tn.cipher.HibeGroupCipher):
//
//   <keystore>/local.private        32-byte Ed25519 seed
//   <keystore>/local.public         UTF-8 did:key:... (diagnostic)
//   <keystore>/index_master.key     32-byte HMAC master for field tokens
//   <keystore>/<group>.btn.state    btn PublisherState bytes (SECRET)
//   <keystore>/<group>.btn.mykit    self-kit bytes so the publisher can read
//   <keystore>/<group>.hibe.*       hibe group material (see runtime/hibe_group.ts)
//
// We do not touch jwe layouts here. A JWE ceremony yaml loaded
// through this module will still read the keystore parts that exist
// but cannot emit or read.

import { readFileSync, readdirSync, writeFileSync, existsSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";

import { DeviceKey } from "../core/signing.js";
import { hibeCandidateKeys, loadHibeGroup, type HibeGroupMaterial } from "./hibe_group.js";

export interface LoadedKeystore {
  device: DeviceKey;
  indexMaster: Uint8Array;
  // Per-group state. Keys are group names. Values carry the raw btn
  // publisher-state bytes plus any kit bytes we found on disk (current
  // self-kit plus any rotation-preserved kits), and/or the group's hibe
  // material — a keystore can hold keys for the SAME group name under
  // several ciphers at once (e.g. its own btn ceremony plus an absorbed
  // hibe grant), mirroring Python's read_as_recipient posture.
  groups: Map<string, GroupKeystore>;
}

export interface GroupKeystore {
  /** btn publisher state — absent for hibe-only groups. */
  stateBytes?: Uint8Array;
  /** btn kits; index 0 is the current self-kit. Empty for hibe-only groups. */
  kits: Uint8Array[];
  /** hibe material when `<group>.hibe.mpk` exists in the keystore. */
  hibe?: HibeGroupMaterial;
  /** Precomputed hibe decrypt candidates (held sk, derived-down, superseded
   * `.previous` keys, msk-minted current + prior paths), try-first order. */
  hibeKits?: Uint8Array[];
  /** jwe reader keys: the raw 32-byte X25519 privates, current
   * (`<group>.jwe.mykey`) first, then any rotation-archived
   * `.jwe.mykey.revoked.<ts>` keys newest first — so pre-rotation entries
   * stay readable, mirroring btn's `kits` list. The async read path derives
   * each public half to open. */
  jweKeys?: Uint8Array[];
}

/** Load a group's btn reader kits: the active `<group>.btn.mykit` first,
 * then both rotation-archive families — modern `.btn.mykit.retired.<epoch>`
 * (what Python's tn.admin.rotate and the Rust runtime write since 0.4.3a1)
 * before legacy `.btn.mykit.revoked.<ts>` (0.4.2-line keystores, and still
 * what {@link commitGroupKeys} produces) — so pre-rotation records stay
 * decryptable across implementations. Each family is ordered by its own
 * numeric index descending (newest kit tried first), mirroring the Rust
 * reference `collect_btn_kit_bytes_with_storage` (runtime/cipher_build.rs)
 * and Python's `BtnGroupCipher.load`. Returns an empty list when the group
 * holds no btn kit. Shared by `loadKeystore` and the sealed-object decrypt
 * walk (`src/seal.ts`), which needs the same multi-kit candidate list
 * against a bare recipient directory. */
export function loadBtnKits(keystorePath: string, group: string): Uint8Array[] {
  const kits: Uint8Array[] = [];
  const selfKitPath = join(keystorePath, `${group}.btn.mykit`);
  if (existsSync(selfKitPath)) {
    kits.push(new Uint8Array(readFileSync(selfKitPath)));
  }
  const retiredPrefix = `${group}.btn.mykit.retired.`;
  const revokedPrefix = `${group}.btn.mykit.revoked.`;
  const retired: { name: string; index: number }[] = [];
  const revoked: { name: string; index: number }[] = [];
  for (const entry of readdirSync(keystorePath)) {
    if (entry.startsWith(retiredPrefix)) {
      retired.push({ name: entry, index: archiveIndex(entry.slice(retiredPrefix.length)) });
    } else if (entry.startsWith(revokedPrefix)) {
      revoked.push({ name: entry, index: archiveIndex(entry.slice(revokedPrefix.length)) });
    }
  }
  for (const family of [retired, revoked]) {
    family.sort(newestFirst);
    for (const { name } of family) {
      kits.push(new Uint8Array(readFileSync(join(keystorePath, name))));
    }
  }
  return kits;
}

/** Numeric archive index from a filename suffix. A suffix that isn't a clean
 * number (e.g. a torn `.tmp` leftover of an atomic write) maps to -Infinity
 * so it sorts LAST in its family instead of crashing the load — the decrypt
 * walk skips any kit that fails to parse, so offering a dud costs one failed
 * trial, while dropping a readable kit would lose historical rows. */
function archiveIndex(suffix: string): number {
  return /^\d+$/.test(suffix) ? Number(suffix) : Number.NEGATIVE_INFINITY;
}

/** Sort comparator: larger archive index first. Explicit three-way compare
 * (not subtraction) so two -Infinity fallbacks compare equal instead of NaN. */
function newestFirst(a: { index: number }, b: { index: number }): number {
  return b.index > a.index ? 1 : b.index < a.index ? -1 : 0;
}

/** Load a group's jwe reader keys: the active `<group>.jwe.mykey` first,
 * then every rotation-archived `.jwe.mykey.revoked.<ts>` newest first.
 * Returns an empty list when the group holds no jwe reader material. */
export function loadJweKeys(keystorePath: string, group: string): Uint8Array[] {
  const keys: Uint8Array[] = [];
  const current = join(keystorePath, `${group}.jwe.mykey`);
  if (existsSync(current)) keys.push(new Uint8Array(readFileSync(current)));
  const revoked = readdirSync(keystorePath)
    .filter((f: string) => f.startsWith(`${group}.jwe.mykey.revoked.`))
    .sort()
    .reverse();
  for (const f of revoked) keys.push(new Uint8Array(readFileSync(join(keystorePath, f))));
  return keys;
}

/** Atomically write bytes: write to `<path>.tmp`, then rename over the target.
 * The rename is the commit point — a crash leaves either the old file or the
 * new one, never a torn/partial write. (libuv's rename replaces an existing
 * target on POSIX and Windows alike.) */
export function atomicWriteSync(path: string, data: Uint8Array): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, data);
  renameSync(tmp, path);
}

/**
 * Crash-safe commit of a group's btn key material (state and/or self-kit),
 * mirroring Python's `BtnKeystore` promote dance. The new generation is staged
 * to `.pending` (durable) BEFORE the active files are touched, the superseded
 * active file(s) are archived as loadable `.revoked.<ts>` (so historical reads
 * still span the rotation), and finally `.pending` is promoted to active. A
 * crash anywhere is repaired by {@link recoverInterruptedPromotes} on the next
 * load — the new bytes survive in `.pending` until the swap commits, so the
 * publisher can never be left with no writable state.
 */
export function commitGroupKeys(
  keystorePath: string,
  group: string,
  opts: { stateBytes?: Uint8Array; selfKit?: Uint8Array; archiveTs: string },
): void {
  const items: { active: string; pending: string; data: Uint8Array }[] = [];
  if (opts.stateBytes !== undefined) {
    const active = join(keystorePath, `${group}.btn.state`);
    items.push({ active, pending: `${active}.pending`, data: opts.stateBytes });
  }
  if (opts.selfKit !== undefined) {
    const active = join(keystorePath, `${group}.btn.mykit`);
    items.push({ active, pending: `${active}.pending`, data: opts.selfKit });
  }
  // 1. Stage the new bytes to `.pending` (durable before we disturb active).
  for (const it of items) atomicWriteSync(it.pending, it.data);
  // 2. Archive each superseded active file as `.revoked.<ts>` (best-effort: a
  //    lock or open handle must not block the rotation, and the new generation
  //    is already safe in `.pending`).
  for (const it of items) {
    if (existsSync(it.active)) {
      try {
        renameSync(it.active, `${it.active}.revoked.${opts.archiveTs}`);
      } catch {
        /* best-effort archive */
      }
    }
  }
  // 3. Promote `.pending` -> active.
  for (const it of items) {
    rmSync(it.active, { force: true });
    renameSync(it.pending, it.active);
  }
}

/** Recover one group's interrupted promote (see {@link recoverInterruptedPromotes}). */
function recoverGroupPromote(keystorePath: string, group: string): boolean {
  const stateActive = join(keystorePath, `${group}.btn.state`);
  const kitActive = join(keystorePath, `${group}.btn.mykit`);
  const statePending = `${stateActive}.pending`;
  const kitPending = `${kitActive}.pending`;
  const pendState = existsSync(statePending);
  const pendKit = existsSync(kitPending);
  if (!pendState && !pendKit) return false; // no interrupted promote

  // Roll back ONLY when the active pair is fully intact — the one state that
  // proves the promote never began replacing it.
  if (existsSync(stateActive) && existsSync(kitActive)) {
    if (pendState) rmSync(statePending, { force: true });
    if (pendKit) rmSync(kitPending, { force: true });
    return true;
  }

  // Otherwise a promote was interrupted mid-swap: land each surviving pending
  // file onto its active path (roll forward). Deleting it would strand the
  // publisher with no writable state.
  if (pendState) {
    rmSync(stateActive, { force: true });
    renameSync(statePending, stateActive);
  }
  if (pendKit) {
    rmSync(kitActive, { force: true });
    renameSync(kitPending, kitActive);
  }
  return true;
}

/**
 * Repair any rotation that crashed during {@link commitGroupKeys}'s promote
 * dance. Scans the keystore for `<group>.btn.state[.pending]` to find every
 * group (a mid-promote crash may have left only `.pending` on disk, with no
 * active state to discover), then rolls each interrupted promote forward or
 * back. Idempotent; safe to call on every load.
 */
export function recoverInterruptedPromotes(keystorePath: string): void {
  if (!existsSync(keystorePath)) return;
  const groups = new Set<string>();
  for (const entry of readdirSync(keystorePath)) {
    const m = entry.match(/^(.+)\.btn\.state(?:\.pending)?$/);
    if (m && m[1]) groups.add(m[1]);
  }
  for (const g of groups) recoverGroupPromote(keystorePath, g);
}

export function loadKeystore(keystorePath: string): LoadedKeystore {
  const privatePath = join(keystorePath, "local.private");
  const indexPath = join(keystorePath, "index_master.key");

  const seed = new Uint8Array(readFileSync(privatePath));
  if (seed.length !== 32) {
    throw new Error(`local.private must be 32 bytes, got ${seed.length}`);
  }
  const device = DeviceKey.fromSeed(seed);

  const indexMaster = new Uint8Array(readFileSync(indexPath));
  if (indexMaster.length !== 32) {
    throw new Error(`index_master.key must be 32 bytes, got ${indexMaster.length}`);
  }

  // Repair any rotation that crashed mid-promote BEFORE discovering groups —
  // a crash can leave a group with only `.pending` files and no active state.
  recoverInterruptedPromotes(keystorePath);

  const groups = new Map<string, GroupKeystore>();
  const groupNames = new Set<string>();
  for (const entry of readdirSync(keystorePath)) {
    const m = entry.match(/^(.+)\.btn\.state$/);
    if (m && m[1]) groupNames.add(m[1]);
  }
  for (const name of groupNames) {
    const stateBytes = new Uint8Array(readFileSync(join(keystorePath, `${name}.btn.state`)));
    // Active self-kit + rotation-preserved kits (`.retired.<epoch>` then
    // legacy `.revoked.<ts>`, each newest first).
    const kits = loadBtnKits(keystorePath, name);
    groups.set(name, { stateBytes, kits });
  }

  // hibe groups: discovered by their `<group>.hibe.mpk` file. A group can
  // carry BOTH btn and hibe material (own ceremony + absorbed grant) — the
  // hibe side is attached to the existing entry rather than replacing it.
  for (const entry of readdirSync(keystorePath)) {
    const m = entry.match(/^(.+)\.hibe\.mpk$/);
    if (!m || !m[1]) continue;
    const name = m[1];
    const mat = loadHibeGroup(keystorePath, name);
    if (mat === null) continue;
    const existing = groups.get(name) ?? { kits: [] };
    existing.hibe = mat;
    existing.hibeKits = hibeCandidateKeys(mat);
    groups.set(name, existing);
  }

  // jwe groups: the reader's X25519 privates — the active `<group>.jwe.mykey`
  // plus rotation-archived `.revoked.<ts>` keys. A group can hold jwe material
  // alongside btn/hibe (own ceremony + absorbed reader key).
  const jweNames = new Set<string>();
  for (const entry of readdirSync(keystorePath)) {
    const m = entry.match(/^(.+)\.jwe\.mykey(?:\.revoked\..+)?$/);
    if (m && m[1]) jweNames.add(m[1]);
  }
  for (const name of jweNames) {
    const keys = loadJweKeys(keystorePath, name);
    if (keys.length === 0) continue;
    const existing = groups.get(name) ?? { kits: [] };
    existing.jweKeys = keys;
    groups.set(name, existing);
  }

  return { device, indexMaster, groups };
}

/** Write (or overwrite) a group's btn state to the keystore. */
export function writeGroupState(keystorePath: string, groupName: string, state: Uint8Array): void {
  writeFileSync(join(keystorePath, `${groupName}.btn.state`), state);
}

/** Write a group's self-kit bytes. */
export function writeGroupMyKit(keystorePath: string, groupName: string, kit: Uint8Array): void {
  writeFileSync(join(keystorePath, `${groupName}.btn.mykit`), kit);
}
