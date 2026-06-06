// LIVE round-trip test for the `tn wallet sync` body push <-> restore.
//
// This closes the loop the mock-fetch `cli_wallet_sync.test.ts` cannot:
// a real PUSH of an AWK/BEK whole-body frame to the live dev vault, then a
// real PULL via the verb's restore path (restoreViaPassphrase), asserting
// pushed body bytes == restored body bytes — the plumb_awk_bek.mts MATCH bar.
//
// It mirrors the verb's SUPPORTED push model (wallet_sync.ts::pushCeremonyBody
// / project_minter.js): mint a fresh BEK, derive the AWK from the account
// passphrase + credential, wrap the BEK under the AWK, PUT the wrapped-key
// FIRST (ownership check ordering), then PUT the no-AAD `nonce||ct` body frame
// with If-Match: *. The restore half is the real `restoreViaPassphrase` verb.
//
// CI-safe: probes the dev vault first and skips cleanly when unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test test/wallet_sync_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";

import { encryptBodyBlob } from "../src/core/body_encryption.js";
import { bytesToB64, randomBytes } from "../src/core/encoding.js";
import {
  AwkBekError,
  deriveAwkFromMaterial,
  wrapBekUnderAwk,
  type CredentialWrap,
} from "../src/vault/awk_bek.js";
import { VaultClient } from "../src/vault/client.js";
import { RestoreError, restoreViaPassphrase } from "../src/wallet/restore.js";

import { VAULT_BASE, devLogin, ulidish, uniqueHandle, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

/** Build an authed VaultClient bearing the dev-login JWT (no DID dance). */
function devClient(token: string): VaultClient {
  return VaultClient.unauthed({
    baseUrl: VAULT_BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token,
  });
}

/**
 * Mint a project BEK, wrap it under the account AWK, PUT the wrapped-key,
 * then encrypt + PUT the body frame (If-Match: *). Mirrors the verb's
 * mint path. Returns the project id and the exact body Map that was sealed.
 */
async function pushBody(
  client: VaultClient,
  passphrase: string,
  body: Map<string, Uint8Array>,
): Promise<{ projectId: string }> {
  const projectId = ulidish();
  const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
  const awk = await deriveAwkFromMaterial(passphrase, cred);
  const bek = randomBytes(32);
  const wrapped = await wrapBekUnderAwk(awk, bek);
  await client.putWrappedKey(projectId, { ...wrapped, label: "wallet-sync-live" });

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
  return { projectId };
}

test(
  "wallet sync — live body round-trip: pushed bytes == restored bytes (MATCH)",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const handle = uniqueHandle("wsync");
    const dev = await devLogin(handle);
    const client = devClient(dev.token);

    // A multi-member body. The TS restore (restore.ts::writeRestoredBytes)
    // lays each frame member out at its flat name and refuses any name with a
    // path separator (its traversal guard), so we use the flat member names
    // the TS verb's restore can actually round-trip — the plumb_awk_bek.mts
    // shape. (The Python restore additionally rebuilds nested `body/...`
    // subpaths; that TS/Python divergence is noted in the report, not under
    // test here.) Each member still stands in for a real keystore artifact.
    const yamlBytes = new TextEncoder().encode(
      `ceremony:\n  id: live_${ulidish()}\n  mode: linked\n`,
    );
    const keyPriv = randomBytes(32);
    const keyPub = new TextEncoder().encode("PUB:" + ulidish());
    const body = new Map<string, Uint8Array>([
      ["tn.yaml", yamlBytes],
      ["local.private", keyPriv],
      ["local.public", keyPub],
    ]);

    const { projectId } = await pushBody(client, dev.passphrase, body);

    // Restore via the REAL verb (= Python _restore_via_passphrase).
    const outDir = mkdtempSync(join(tmpdir(), "wsync-restore-"));
    const result = await restoreViaPassphrase(client, {
      projectId,
      passphrase: dev.passphrase,
      outDir,
    });

    // Every body member round-trips byte-for-byte (the MATCH bar).
    assert.ok(result.filesWritten.length >= 3, `expected >=3 files; got ${result.filesWritten.length}`);

    const restoredYaml = readFileSync(join(outDir, "tn.yaml"));
    assert.ok(Buffer.from(restoredYaml).equals(Buffer.from(yamlBytes)), "tn.yaml bytes must MATCH");

    const restoredPriv = readFileSync(join(outDir, "local.private"));
    assert.ok(Buffer.from(restoredPriv).equals(Buffer.from(keyPriv)), "local.private bytes must MATCH");

    const restoredPub = readFileSync(join(outDir, "local.public"));
    assert.ok(Buffer.from(restoredPub).equals(Buffer.from(keyPub)), "local.public bytes must MATCH");
  },
);

test(
  "wallet sync — FAIL: wrong passphrase fails the BEK unwrap (no garbage restore)",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const handle = uniqueHandle("wsync-bad");
    const dev = await devLogin(handle);
    const client = devClient(dev.token);

    const body = new Map<string, Uint8Array>([
      ["tn.yaml", new TextEncoder().encode("ceremony:\n  id: live_bad\n")],
      ["local.private", randomBytes(32)],
    ]);
    const { projectId } = await pushBody(client, dev.passphrase, body);

    // Restore with a DIFFERENT passphrase: the AWK (and thus BEK) unwrap must
    // fail the GCM tag — never silently return garbage or the wrong plaintext.
    const outDir = mkdtempSync(join(tmpdir(), "wsync-badpass-"));
    let caught: Error | null = null;
    try {
      await restoreViaPassphrase(client, {
        projectId,
        passphrase: dev.passphrase + "-WRONG",
        outDir,
      });
    } catch (e) {
      caught = e as Error;
    }
    assert.ok(caught, "wrong passphrase must throw, not write a partial restore");
    assert.ok(
      caught instanceof AwkBekError || caught instanceof RestoreError,
      `expected AwkBekError/RestoreError; got ${caught?.constructor.name}: ${caught?.message}`,
    );
  },
);
