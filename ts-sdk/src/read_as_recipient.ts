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

import { existsSync, readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { join } from "node:path";

import { verifyChainLink } from "./core/chain.js";
import { aadBytesFor, decryptGroup, decryptGroupAsync, type GroupKits } from "./core/decrypt.js";
import { hibeCandidateKeys, loadHibeGroup } from "./runtime/hibe_group.js";
import { loadBtnKits, loadJweKeys } from "./runtime/keystore.js";
import { signatureFromB64, verify } from "./core/signing.js";
import { asDid, asSignatureB64 } from "./core/types.js";

export interface ReadAsRecipientOptions {
  /** Group name to decrypt. Default: "default". */
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
}

export interface ForeignReadEntry {
  envelope: Record<string, unknown>;
  plaintext: Record<string, Record<string, unknown>>;
  valid: { signature: boolean; chain: boolean };
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
 * Decryption happens only for `group` (default `"default"`). Other groups
 * the publisher used appear in `envelope` but not `plaintext`.
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
  const hibeSkPath = join(keystorePath, `${group}.hibe.sk`);
  const btnKits = loadBtnKits(keystorePath, group);
  if (btnKits.length > 0) {
    candidates.push({ cipher: "btn", kits: btnKits });
  }
  if (existsSync(hibeSkPath)) {
    const mat = loadHibeGroup(keystorePath, group);
    if (mat !== null)
      candidates.push({ cipher: "hibe", kits: hibeCandidateKeys(mat), mpk: mat.mpk });
  }
  return candidates;
}

/** The jwe reader keys (`<group>.jwe.mykey` plus rotation-archived
 *  `.revoked.<ts>` priors) as a GroupKits, or null if none are present. */
function jweReaderKit(keystorePath: string, group: string): GroupKits | null {
  const keys = loadJweKeys(keystorePath, group);
  return keys.length > 0 ? { cipher: "jwe", kits: keys } : null;
}

/** Verify a foreign envelope's Ed25519 signature over its row_hash. */
function verifyForeignSig(env: Record<string, unknown>): boolean {
  const envDid = env["device_identity"];
  const envSig = env["signature"];
  const envRow = env["row_hash"];
  if (typeof envDid !== "string" || typeof envSig !== "string" || typeof envRow !== "string") {
    return false;
  }
  try {
    return verify(
      asDid(envDid),
      new Uint8Array(Buffer.from(envRow, "utf8")),
      signatureFromB64(asSignatureB64(envSig)),
    );
  } catch {
    return false;
  }
}

export function* readAsRecipient(
  logPath: string,
  keystorePath: string,
  opts: ReadAsRecipientOptions = {},
): Generator<ForeignReadEntry, void, void> {
  const group = opts.group ?? "default";
  const verifySigs = opts.verifySignatures ?? true;
  const expectGenesis = opts.expectGenesis ?? false;

  // jwe is async-only, so this sync path rejects a jwe-only keystore.
  const candidates = btnHibeCandidates(keystorePath, group);
  if (candidates.length === 0) {
    if (jweReaderKit(keystorePath, group) !== null) {
      throw new Error(
        `readAsRecipient is synchronous and cannot open jwe groups (the JOSE ` +
          `library is async). Use readAsRecipientAsync() (or tn.readAsync({asRecipient})).`,
      );
    }
    throw new Error(
      `readAsRecipient: no recipient kit for group ${JSON.stringify(group)} ` +
        `in ${keystorePath}. Looked for ${group}.btn.mykit (btn), ` +
        `${group}.hibe.sk (hibe), and ${group}.jwe.mykey (jwe). If you ` +
        `absorbed a kit_bundle, the kit lands in your ceremony's keystore ` +
        `(cfg.keystorePath) — point keystorePath there.`,
    );
  }

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

    const eventType = env["event_type"];
    if (typeof eventType !== "string") continue;

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

    // Decrypt the requested group, if its ciphertext is present.
    const plaintext: Record<string, Record<string, unknown>> = {};
    const gBlock = env[group];
    if (gBlock && typeof gBlock === "object" && !Array.isArray(gBlock)) {
      const gObj = gBlock as Record<string, unknown>;
      const ct = gObj["ciphertext"];
      if (typeof ct === "string") {
        const ctBytes = new Uint8Array(Buffer.from(ct, "base64"));
        const aadBytes = aadBytesFor(env, group);
        // Try each cipher's kit set; keep the first real plaintext. When
        // nothing opens, surface the last marker ($no_read_key etc.).
        let result: Record<string, unknown> | undefined;
        for (const kits of candidates) {
          const attempt = decryptGroup({ ct: ctBytes, aad: aadBytes }, kits) as Record<
            string,
            unknown
          >;
          result = attempt;
          if (!("$no_read_key" in attempt) && !("$unsupported_cipher" in attempt)) break;
        }
        plaintext[group] = result ?? { $no_read_key: true };
      }
    }

    // Signature verification (optional but on by default).
    const sigOk = verifySigs ? verifyForeignSig(env) : true;

    yield {
      envelope: env,
      plaintext,
      valid: { signature: sigOk, chain: chainOk },
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
  const group = opts.group ?? "default";
  const verifySigs = opts.verifySignatures ?? true;
  const expectGenesis = opts.expectGenesis ?? false;

  const candidates = btnHibeCandidates(keystorePath, group);
  const jweKit = jweReaderKit(keystorePath, group);
  if (jweKit !== null) candidates.push(jweKit);
  if (candidates.length === 0) {
    throw new Error(
      `readAsRecipientAsync: no recipient kit for group ${JSON.stringify(group)} in ` +
        `${keystorePath}. Looked for ${group}.btn.mykit (btn), ${group}.hibe.sk (hibe), ` +
        `and ${group}.jwe.mykey (jwe). Absorb a kit for this group first.`,
    );
  }

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
    const eventType = env["event_type"];
    if (typeof eventType !== "string") continue;
    const envPrev = env["prev_hash"];
    const envRow = env["row_hash"];
    const chainOk = verifyChainLink(
      prevHashByType,
      eventType,
      typeof envPrev === "string" ? envPrev : "",
      typeof envRow === "string" ? envRow : "",
      expectGenesis,
    );

    const plaintext: Record<string, Record<string, unknown>> = {};
    const gBlock = env[group];
    if (gBlock && typeof gBlock === "object" && !Array.isArray(gBlock)) {
      const ct = (gBlock as Record<string, unknown>)["ciphertext"];
      if (typeof ct === "string") {
        const ctBytes = new Uint8Array(Buffer.from(ct, "base64"));
        const aadBytes = aadBytesFor(env, group);
        let result: Record<string, unknown> | undefined;
        for (const kits of candidates) {
          const attempt = (await decryptGroupAsync({ ct: ctBytes, aad: aadBytes }, kits)) as Record<
            string,
            unknown
          >;
          result = attempt;
          if (!("$no_read_key" in attempt) && !("$unsupported_cipher" in attempt)) break;
        }
        plaintext[group] = result ?? { $no_read_key: true };
      }
    }

    const sigOk = verifySigs ? verifyForeignSig(env) : true;

    yield { envelope: env, plaintext, valid: { signature: sigOk, chain: chainOk } };
  }
}
