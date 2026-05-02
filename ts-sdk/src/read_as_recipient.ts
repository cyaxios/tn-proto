// readAsRecipient — decrypt a foreign publisher's ndjson log using a kit
// dropped into a local keystore directory by `client.absorb()`.
//
// Mirrors Python's `tn.read_as_recipient(log_path, keystore_dir, group=)`.
// Closes the cross-binding gap surfaced by the cash-register Stage 6
// survey (TS had no equivalent verb; cross-publisher reads on TS had no
// documented path). Pairs with the auto-routing path in `client.read`.
//
// Dispatches on the kit file present in `keystorePath`:
//
//   <group>.btn.mykit   → btn cipher (subset-difference broadcast)
//   <group>.jwe.mykey   → JWE cipher  (NOT YET IMPLEMENTED in TS)
//
// btn is the shipping default cipher and the one this verb supports
// today. JWE-keystore reads should fall back to spinning up a TNClient
// against a yaml that declares the JWE group.

import { existsSync, readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { join } from "node:path";

import { decryptGroup } from "./core/decrypt.js";
import { signatureFromB64, verify } from "./core/signing.js";
import { asDid, asSignatureB64 } from "./core/types.js";

export interface ReadAsRecipientOptions {
  /** Group name to decrypt. Default: "default". */
  group?: string;
  /** Verify per-row signatures (slower but catches forgery). Default: true. */
  verifySignatures?: boolean;
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
export function* readAsRecipient(
  logPath: string,
  keystorePath: string,
  opts: ReadAsRecipientOptions = {},
): Generator<ForeignReadEntry, void, void> {
  const group = opts.group ?? "default";
  const verifySigs = opts.verifySignatures ?? true;

  const btnKitPath = join(keystorePath, `${group}.btn.mykit`);
  const jweKeyPath = join(keystorePath, `${group}.jwe.mykey`);
  if (!existsSync(btnKitPath)) {
    if (existsSync(jweKeyPath)) {
      throw new Error(
        `readAsRecipient: cipher=jwe is not implemented in the TS SDK. ` +
          `For JWE foreign reads, use the Python tn-protocol package or ` +
          `wait for the upcoming TS JWE port.`,
      );
    }
    throw new Error(
      `readAsRecipient: no recipient kit for group ${JSON.stringify(group)} ` +
        `in ${keystorePath}. Looked for ${group}.btn.mykit (btn) and ` +
        `${group}.jwe.mykey (jwe). If you absorbed a kit_bundle, the kit ` +
        `lands in your ceremony's keystore (cfg.keystorePath) — point ` +
        `keystorePath there.`,
    );
  }
  const kit = new Uint8Array(readFileSync(btnKitPath));

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
    const last = prevHashByType.get(eventType);
    const envPrev = env["prev_hash"];
    const envRow = env["row_hash"];
    const chainOk = (last === undefined) || (typeof envPrev === "string" && envPrev === last);
    if (typeof envRow === "string") prevHashByType.set(eventType, envRow);

    // Decrypt the requested group, if its ciphertext is present.
    const plaintext: Record<string, Record<string, unknown>> = {};
    const gBlock = env[group];
    if (gBlock && typeof gBlock === "object" && !Array.isArray(gBlock)) {
      const gObj = gBlock as Record<string, unknown>;
      const ct = gObj["ciphertext"];
      if (typeof ct === "string") {
        const ctBytes = new Uint8Array(Buffer.from(ct, "base64"));
        plaintext[group] = decryptGroup(
          { ct: ctBytes },
          { cipher: "btn", kits: [kit] },
        ) as Record<string, unknown>;
      }
    }

    // Signature verification (optional but on by default).
    let sigOk = true;
    if (verifySigs) {
      const envDid = env["did"];
      const envSig = env["signature"];
      if (typeof envDid !== "string" || typeof envSig !== "string" || typeof envRow !== "string") {
        sigOk = false;
      } else {
        try {
          const sig = signatureFromB64(asSignatureB64(envSig));
          sigOk = verify(asDid(envDid), new Uint8Array(Buffer.from(envRow, "utf8")), sig);
        } catch {
          sigOk = false;
        }
      }
    }

    yield {
      envelope: env,
      plaintext,
      valid: { signature: sigOk, chain: chainOk },
    };
  }
}
