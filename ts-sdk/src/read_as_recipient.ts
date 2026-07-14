// readAsRecipient — decrypt a foreign publisher's ndjson log using a kit
// dropped into a local keystore directory by `client.absorb()`.
//
// Mirrors Python's `tn.read_as_recipient(log_path, keystore_dir, group=)`.
// Closes the cross-binding gap surfaced by the cash-register Stage 6
// survey (TS had no equivalent verb; cross-publisher reads on TS had no
// documented path). Pairs with the auto-routing path in `client.read`.
//
// Dispatches on the kit files present in `keystorePath`:
//
//   <group>.btn.mykit   → btn cipher (subset-difference broadcast)
//   <group>.hibe.sk     → hibe cipher (BBG hierarchical IBE reader key)
//   <group>.jwe.mykey   → JWE cipher  (async JOSE — read via readAsync)
//
// The keystore can hold keys for the SAME group name under several ciphers
// at once (e.g. the reader's own btn ceremony plus an absorbed hibe
// grant). The log line doesn't say which cipher sealed it, so every
// candidate is tried per entry — same posture as Python's
// tn.reader.read_as_recipient. This synchronous foreign-read path covers btn
// and hibe; jwe groups (async JOSE) are opened through readAsync.

import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";

import { verifyChainLink } from "./core/chain.js";
import { aadBytesFor, decryptGroup, decryptGroupAsync, type GroupKits } from "./core/decrypt.js";
import { TrustError } from "./core/trust.js";
import { hibeCandidateKeys, loadHibeGroup } from "./runtime/hibe_group.js";
import { loadBtnKits, loadJweKeys } from "./runtime/keystore.js";
import {
  assertForeignPublisherTrusted,
  foreignReadTrustedPublishers,
  verifyForeignRowIntegrity,
} from "./foreign_read_security.js";
import { discoverRecipientGroups } from "./recipient_group_discovery.js";

export interface ReadAsRecipientOptions {
  /** Group name to decrypt. Omit to discover every locally keyed group. */
  group?: string;
  /** Verify per-row signatures (slower but catches forgery). Default: true. */
  verifySignatures?: boolean;
  /**
   * Require the first entry of each event_type chain to anchor at ZERO_HASH,
   * catching a front-truncation. Off by default — a foreign read is often a
   * partial slice that legitimately starts mid-chain. See
   * {@link verifyChainLink}.
   */
  expectGenesis?: boolean;
  /** Explicitly trusted writer DIDs; defaults to installed verified publishers. */
  trustedPublisherDids?: string[];
  /** Explicit weakening: decrypt rows whose writer has not been admitted. */
  unsafeAllowUnverifiedPublisher?: boolean;
}

export interface ForeignReadEntry {
  envelope: Record<string, unknown>;
  plaintext: Record<string, Record<string, unknown>>;
  valid: { signature: boolean; rowHash: boolean; chain: boolean };
}

/**
 * Iterate decrypted entries from `logPath` using a kit found in
 * `keystorePath`. Use this when you absorbed a kit_bundle from a foreign
 * publisher and now want to read THEIR log file — your runtime, if you
 * have one, is bound to your own ceremony's btn state and would raise
 * "kit not entitled" because every envelope was produced under the
 * publisher's state, not yours.
 *
 * Yields the same shape as Python's `tn.read_as_recipient` and
 * `client.read({raw: true})`: `envelope`, `plaintext[group]`, and a
 * `valid` block with per-row sig + chain booleans.
 *
 * When `group` is omitted, every group with local reader material is tried.
 * Passing `group` explicitly narrows decryption to that one group.
 */
/** Assemble btn + hibe reader-kit candidates a keystore holds for a foreign
 *  group's log (each is tried per line; the first that opens wins). The btn
 *  candidate carries the FULL kit list — the active `<group>.btn.mykit` plus
 *  both rotation-archive families (`.retired.<epoch>`, legacy
 *  `.revoked.<ts>`) — so rows sealed before a publisher rotation still open,
 *  mirroring Python's `BtnGroupCipher.load` and the sealed-object walk in
 *  `src/seal.ts`. */
function btnHibeCandidates(keystorePath: string, group: string): GroupKits[] {
  const candidates: GroupKits[] = [];
  const btnKits = loadBtnKits(keystorePath, group);
  if (btnKits.length > 0) {
    candidates.push({ cipher: "btn", kits: btnKits });
  }
  const mat = loadHibeGroup(keystorePath, group);
  if (mat !== null) {
    const kits = hibeCandidateKeys(mat);
    if (kits.length > 0) candidates.push({ cipher: "hibe", kits, mpk: mat.mpk });
  }
  return candidates;
}

/** The jwe reader keys (`<group>.jwe.mykey` plus rotation-archived
 *  `.revoked.<ts>` priors) as a GroupKits, or null if none are present. */
function jweReaderKit(keystorePath: string, group: string): GroupKits | null {
  const keys = loadJweKeys(keystorePath, group);
  return keys.length > 0 ? { cipher: "jwe", kits: keys } : null;
}

function selectedGroups(keystorePath: string, group?: string): string[] {
  const groups = group === undefined ? discoverRecipientGroups(keystorePath) : [group];
  if (groups.length === 0) throw new Error(`readAsRecipient: no reader keys in ${keystorePath}`);
  return groups;
}

function candidateMap(
  keystorePath: string,
  groups: string[],
  includeJwe: boolean,
): Map<string, GroupKits[]> {
  const out = new Map<string, GroupKits[]>();
  for (const group of groups) {
    const candidates = btnHibeCandidates(keystorePath, group);
    const jwe = jweReaderKit(keystorePath, group);
    if (includeJwe && jwe !== null) candidates.push(jwe);
    if (!includeJwe && jwe !== null) {
      throw new Error("readAsRecipient cannot open JWE; use readAsRecipientAsync");
    }
    if (candidates.length === 0) {
      throw new Error(`readAsRecipient: no recipient kit for group ${JSON.stringify(group)}`);
    }
    out.set(group, candidates);
  }
  return out;
}

function ciphertext(env: Record<string, unknown>, group: string): Uint8Array | null {
  const block = env[group];
  if (block === null || typeof block !== "object" || Array.isArray(block)) return null;
  const value = (block as Record<string, unknown>)["ciphertext"];
  return typeof value === "string" ? new Uint8Array(Buffer.from(value, "base64")) : null;
}

function requiredEventType(env: Record<string, unknown>): string {
  const value = env["event_type"];
  if (typeof value !== "string") {
    throw new TrustError("statement_invalid", "foreign row event_type must be a string");
  }
  return value;
}

function decryptSelected(
  env: Record<string, unknown>,
  candidates: Map<string, GroupKits[]>,
): Record<string, Record<string, unknown>> {
  const plaintext: Record<string, Record<string, unknown>> = {};
  for (const [group, kitsList] of candidates) {
    const ct = ciphertext(env, group);
    if (ct === null) continue;
    let result: Record<string, unknown> = { $no_read_key: true };
    for (const kits of kitsList) {
      result = decryptGroup({ ct, aad: aadBytesFor(env, group) }, kits) as Record<string, unknown>;
      if (!("$no_read_key" in result) && !("$unsupported_cipher" in result)) break;
    }
    plaintext[group] = result;
  }
  return plaintext;
}

async function decryptSelectedAsync(
  env: Record<string, unknown>,
  candidates: Map<string, GroupKits[]>,
): Promise<Record<string, Record<string, unknown>>> {
  const plaintext: Record<string, Record<string, unknown>> = {};
  for (const [group, kitsList] of candidates) {
    const ct = ciphertext(env, group);
    if (ct === null) continue;
    let result: Record<string, unknown> = { $no_read_key: true };
    for (const kits of kitsList) {
      result = (await decryptGroupAsync({ ct, aad: aadBytesFor(env, group) }, kits)) as Record<
        string,
        unknown
      >;
      if (!("$no_read_key" in result) && !("$unsupported_cipher" in result)) break;
    }
    plaintext[group] = result;
  }
  return plaintext;
}

export function* readAsRecipient(
  logPath: string,
  keystorePath: string,
  opts: ReadAsRecipientOptions = {},
): Generator<ForeignReadEntry, void, void> {
  const groups = selectedGroups(keystorePath, opts.group);
  const verifySigs = opts.verifySignatures ?? true;
  const expectGenesis = opts.expectGenesis ?? false;
  const trusted = foreignReadTrustedPublishers(keystorePath, opts);
  const candidates = candidateMap(keystorePath, groups, false);

  const text = readFileSync(logPath, "utf8");
  const prevHashByType = new Map<string, string>();

  for (const rawLine of text.split(/\r?\n/)) {
    const s = rawLine.trim();
    if (!s) continue;
    let env: Record<string, unknown>;
    try {
      env = JSON.parse(s) as Record<string, unknown>;
    } catch {
      throw new Error(`readAsRecipient: invalid JSON line: ${rawLine.slice(0, 120)}`);
    }

    const eventType = requiredEventType(env);
    assertForeignPublisherTrusted(env, trusted);

    // Per-event-type chain check: each event_type maintains its own
    // prev_hash continuity. Mirrors Python's reader.read_as_recipient.
    const envPrev = env["prev_hash"];
    const envRow = env["row_hash"];
    const chainOk = verifyChainLink(
      prevHashByType,
      eventType,
      typeof envPrev === "string" ? envPrev : "",
      typeof envRow === "string" ? envRow : "",
      expectGenesis,
    );

    const plaintext = decryptSelected(env, candidates);

    // Signature verification (optional but on by default).
    const integrity = verifyForeignRowIntegrity(env);
    const sigOk = verifySigs ? integrity.signature : true;

    yield {
      envelope: env,
      plaintext,
      valid: { signature: sigOk, rowHash: integrity.rowHash, chain: chainOk },
    };
  }
}

/**
 * Async sibling of {@link readAsRecipient} that also decrypts `cipher: jwe`
 * foreign logs (panva/jose is async). Dispatches on the reader kit files a
 * keystore holds — `.btn.mykit` (btn), `.hibe.sk` (hibe), `.jwe.mykey` (jwe) —
 * and tries each per line, so a party who absorbed any of them can read the
 * publisher's log. This is the path an absorbed jwe recipient uses.
 */
export async function* readAsRecipientAsync(
  logPath: string,
  keystorePath: string,
  opts: ReadAsRecipientOptions = {},
): AsyncGenerator<ForeignReadEntry, void, void> {
  const groups = selectedGroups(keystorePath, opts.group);
  const verifySigs = opts.verifySignatures ?? true;
  const expectGenesis = opts.expectGenesis ?? false;
  const trusted = foreignReadTrustedPublishers(keystorePath, opts);
  const candidates = candidateMap(keystorePath, groups, true);

  const text = readFileSync(logPath, "utf8");
  const prevHashByType = new Map<string, string>();
  for (const rawLine of text.split(/\r?\n/)) {
    const s = rawLine.trim();
    if (!s) continue;
    let env: Record<string, unknown>;
    try {
      env = JSON.parse(s) as Record<string, unknown>;
    } catch {
      throw new Error(`readAsRecipientAsync: invalid JSON line: ${rawLine.slice(0, 120)}`);
    }
    const eventType = requiredEventType(env);
    assertForeignPublisherTrusted(env, trusted);
    const envPrev = env["prev_hash"];
    const envRow = env["row_hash"];
    const chainOk = verifyChainLink(
      prevHashByType,
      eventType,
      typeof envPrev === "string" ? envPrev : "",
      typeof envRow === "string" ? envRow : "",
      expectGenesis,
    );

    const plaintext = await decryptSelectedAsync(env, candidates);

    const integrity = verifyForeignRowIntegrity(env);
    const sigOk = verifySigs ? integrity.signature : true;

    yield {
      envelope: env,
      plaintext,
      valid: { signature: sigOk, rowHash: integrity.rowHash, chain: chainOk },
    };
  }
}
