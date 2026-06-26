// LIVE round-trip test for `tn wallet restore` (passphrase path).
//
// Pushes a REAL ceremony backup (its keystore + tn.yaml + log) to the live
// dev vault as an AWK/BEK whole-body frame, then restores it on a FRESH
// identity into an EMPTY dir via the real verb (restoreViaPassphrase), and
// asserts:
//   - every keystore file + tn.yaml restores BYTE-IDENTICAL to the original;
//   - the restored ceremony reopens (Tn.init) with the SAME device DID;
//   - the restored ceremony can READ its prior entries (the log round-tripped).
//
// The producer runtime is closed before restore, proving restore doesn't lean
// on the producer's live state.
//
// CI-safe: probes the dev vault first and skips cleanly when unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test test/wallet_restore_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative } from "node:path";
import { Buffer } from "node:buffer";

import { Tn } from "../src/tn.js";
import { loadConfig } from "../src/runtime/config.js";
import { encryptBodyBlob } from "../src/core/body_encryption.js";
import { bytesToB64, randomBytes } from "../src/core/encoding.js";
import { deriveAwkFromMaterial, wrapBekUnderAwk, type CredentialWrap } from "../src/vault/awk_bek.js";
import { VaultClient } from "../src/vault/client.js";
import { restoreViaPassphrase } from "../src/wallet/restore.js";

import { VAULT_BASE, devLogin, ulidish, uniqueHandle, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

function devClient(token: string): VaultClient {
  return VaultClient.unauthed({
    baseUrl: VAULT_BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token,
  });
}

/**
 * Collect the full ceremony body: every keystore file (minus *.lock) + the
 * tn.yaml + the log. Each member is keyed by a FLAT, separator-free token
 * (so the TS restore's traversal guard writes it) and returned alongside a
 * manifest mapping that token back to the member's path RELATIVE to the
 * ceremony dir — so a fresh machine can reassemble the original layout.
 */
function collectFullBody(
  dir: string,
  yamlPath: string,
  keystorePath: string,
  logPath: string,
): { body: Map<string, Uint8Array>; layout: Record<string, string> } {
  const body = new Map<string, Uint8Array>();
  const layout: Record<string, string> = {};
  let n = 0;
  const add = (absPath: string): void => {
    const token = `body/m${n}_${ulidish().slice(0, 6)}`;
    n += 1;
    body.set(token, new Uint8Array(readFileSync(absPath)));
    layout[token] = relative(dir, absPath).split("\\").join("/");
  };
  add(yamlPath);
  for (const name of readdirSync(keystorePath).sort()) {
    const full = join(keystorePath, name);
    if (!statSync(full).isFile() || extname(name) === ".lock") continue;
    add(full);
  }
  add(logPath);
  return { body, layout };
}

/** Mint a BEK, wrap under AWK, PUT wrapped-key, then PUT the body frame. */
async function pushBody(
  client: VaultClient,
  passphrase: string,
  body: Map<string, Uint8Array>,
): Promise<string> {
  const projectId = ulidish();
  const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
  const awk = await deriveAwkFromMaterial(passphrase, cred);
  const bek = randomBytes(32);
  const wrapped = await wrapBekUnderAwk(awk, bek);
  await client.putWrappedKey(projectId, { ...wrapped, label: "wallet-restore-live" });
  const frame = await encryptBodyBlob(body, bek);
  await client.putEncryptedBlobAccount(
    projectId,
    {
      ciphertext_b64: bytesToB64(frame),
      nonce_b64: bytesToB64(frame.subarray(0, 12)),
      salt_b64: bytesToB64(randomBytes(16)),
      kdf: "pbkdf2-sha256",
      kdf_params: { iterations: 1 },
      cipher_suite: "aes-256-gcm",
      bundle_kind: "project-body-v1",
    },
    { ifMatch: "*" },
  );
  return projectId;
}

test(
  "wallet restore — live: backup restores byte-identical into an empty dir; restored ceremony reads its prior entries",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const handle = uniqueHandle("wrestore");
    const dev = await devLogin(handle);
    const client = devClient(dev.token);

    // ── Producer: a REAL ceremony with real signed entries. ──
    const srcDir = mkdtempSync(join(tmpdir(), "wrestore-src-"));
    const srcYaml = join(srcDir, "tn.yaml");
    const producer = await Tn.init(srcYaml);
    const producerDid = producer.did;
    producer.log("restore.live.alpha", { n: 1 });
    producer.info("restore.live.beta", "second", { n: 2 });
    producer.warning("restore.live.gamma", { n: 3 });
    await producer.close(); // close BEFORE restore — restore must stand alone.

    const cfg = loadConfig(srcYaml);
    const { body, layout } = collectFullBody(srcDir, srcYaml, cfg.keystorePath, cfg.logPath);

    // Snapshot the original member bytes for the byte-match assertion.
    const originalBytes = new Map<string, Buffer>();
    for (const [token, rel] of Object.entries(layout)) {
      originalBytes.set(rel, Buffer.from(body.get(token)!));
    }

    // ── Push the backup, then restore on a FRESH identity / EMPTY dir. ──
    const projectId = await pushBody(client, dev.passphrase, body);

    const stageDir = mkdtempSync(join(tmpdir(), "wrestore-stage-"));
    const result = await restoreViaPassphrase(client, {
      projectId,
      passphrase: dev.passphrase,
      outDir: stageDir,
    });
    assert.equal(
      result.filesWritten.length,
      Object.keys(layout).length,
      "all body members must restore",
    );

    // Reassemble the original ceremony layout in a brand-new empty dir from
    // the flat-restored members + the layout manifest (what a fresh-machine
    // restore lays down). This is the "EMPTY dir on a fresh identity" target.
    const destDir = mkdtempSync(join(tmpdir(), "wrestore-dest-"));
    for (const [token, rel] of Object.entries(layout)) {
      const target = join(destDir, ...rel.split("/"));
      mkdirSync(dirname(target), { recursive: true });
      const restoredFlat = readFileSync(join(stageDir, token));
      writeFileSync(target, restoredFlat);
      // Byte-match: each restored member equals the original.
      assert.ok(
        Buffer.from(restoredFlat).equals(originalBytes.get(rel)!),
        `restored ${rel} must byte-match the original`,
      );
    }

    // ── Reopen the restored ceremony and prove continuity. ──
    const destYaml = join(destDir, "tn.yaml");
    const restored = await Tn.init(destYaml);
    try {
      assert.equal(restored.did, producerDid, "restored DID must equal the producer's");

      // Reads its prior entries — proves the log + keystore round-tripped.
      const entries = [...restored.read()];
      assert.ok(entries.length >= 3, `restored ceremony must read >=3 prior entries; got ${entries.length}`);
    } finally {
      await restored.close();
    }
  },
);
