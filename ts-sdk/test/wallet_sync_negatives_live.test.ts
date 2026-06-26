// LIVE DAY-1 NEGATIVE-path tests for the AWK/BEK backup <-> restore loop,
// against the real dev vault (34987).
//
// Scenario D — the failure modes that must NOT silently corrupt a single
// operator's wallet:
//
//   D1. WRONG PASSPHRASE -> restore fails cleanly with NO partial write.
//       The BEK unwrap (or the body GCM tag) must reject; the output dir is
//       left EMPTY — never a half-written keystore the operator might trust.
//       (wallet_sync_live asserts the throw; here we additionally pin the
//       no-partial-write guarantee by asserting the out dir is empty.)
//
//   D2. CONCURRENT PUSH (stale If-Match) -> the conflict is SURFACED, not a
//       silent overwrite. After a first push (generation 1) and a correct
//       second push (-> generation 2), a writer still holding the stale
//       generation-1 token gets a 412 VaultError. We also document that
//       If-Match: "*" is create-or-OVERWRITE (no guard) — so a real
//       optimistic-concurrency push MUST send the numeric generation.
//
// CI-safe: probes the vault first, skips cleanly when unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test test/wallet_sync_negatives_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { encryptBodyBlob } from "../src/core/body_encryption.js";
import { bytesToB64, randomBytes } from "../src/core/encoding.js";
import {
  AwkBekError,
  deriveAwkFromMaterial,
  wrapBekUnderAwk,
  type CredentialWrap,
} from "../src/vault/awk_bek.js";
import { VaultClient, VaultError } from "../src/vault/client.js";
import { RestoreError, restoreViaPassphrase } from "../src/wallet/restore.js";

import { VAULT_BASE, devLogin, ulidish, uniqueHandle, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

function devClient(token: string): VaultClient {
  return VaultClient.unauthed({
    baseUrl: VAULT_BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token,
  });
}

/** Mint a BEK, wrap under the AWK, PUT wrapped-key, return the projectId. */
async function mintProject(
  client: VaultClient,
  passphrase: string,
): Promise<{ projectId: string; bek: Uint8Array }> {
  const projectId = ulidish();
  const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
  const awk = await deriveAwkFromMaterial(passphrase, cred);
  const bek = randomBytes(32);
  await client.putWrappedKey(projectId, {
    ...(await wrapBekUnderAwk(awk, bek)),
    label: "negatives-live",
  });
  return { projectId, bek };
}

/** Build the blob-account PUT body (incl. the route-required nonce_b64). */
function blobBody(frame: Uint8Array): Record<string, unknown> {
  return {
    ciphertext_b64: bytesToB64(frame),
    nonce_b64: bytesToB64(frame.subarray(0, 12)),
    salt_b64: bytesToB64(randomBytes(16)),
    kdf: "pbkdf2-sha256",
    kdf_params: { iterations: 1 },
    cipher_suite: "aes-256-gcm",
    bundle_kind: "project-body-v1",
  };
}

test(
  "negatives — D1: wrong passphrase fails restore cleanly with NO partial write (out dir stays empty)",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const dev = await devLogin(uniqueHandle("neg-pass"));
    const client = devClient(dev.token);

    const { projectId, bek } = await mintProject(client, dev.passphrase);
    const body = new Map<string, Uint8Array>([
      ["body/tn.yaml", new TextEncoder().encode("ceremony:\n  id: neg\n")],
      ["body/local.private", randomBytes(32)],
    ]);
    const frame = await encryptBodyBlob(body, bek);
    await client.putEncryptedBlobAccount(projectId, blobBody(frame), { ifMatch: "*" });

    const outDir = mkdtempSync(join(tmpdir(), "neg-badpass-"));
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

    assert.ok(caught, "wrong passphrase must throw");
    assert.ok(
      caught instanceof AwkBekError || caught instanceof RestoreError,
      `expected AwkBekError/RestoreError; got ${caught?.constructor.name}: ${caught?.message}`,
    );
    // No partial write: the restore must not have laid down any keystore
    // bytes the operator could mistake for a good wallet.
    assert.deepEqual(
      readdirSync(outDir),
      [],
      "a failed restore must leave the output dir EMPTY (no partial keystore)",
    );
  },
);

test(
  "negatives — D2: a stale If-Match push is rejected with 412 (conflict surfaced, not a silent overwrite)",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const dev = await devLogin(uniqueHandle("neg-conflict"));
    const client = devClient(dev.token);
    const { projectId, bek } = await mintProject(client, dev.passphrase);

    // First push -> generation 1.
    const r1 = await client.putEncryptedBlobAccount(
      projectId,
      blobBody(await encryptBodyBlob(new Map([["body/v", new Uint8Array([1])]]), bek)),
      { ifMatch: "*" },
    );
    assert.equal(r1["generation"], 1, "first push should land generation 1");

    // A correct second push at If-Match: 1 advances -> generation 2.
    const r2 = await client.putEncryptedBlobAccount(
      projectId,
      blobBody(await encryptBodyBlob(new Map([["body/v", new Uint8Array([2])]]), bek)),
      { ifMatch: "1" },
    );
    assert.equal(r2["generation"], 2, "correct-generation push should advance to 2");

    // A concurrent writer STILL holding the stale generation-1 token: the
    // server must reject with 412, surfacing the conflict — NOT silently
    // overwrite the generation-2 body.
    let caught: VaultError | null = null;
    try {
      await client.putEncryptedBlobAccount(
        projectId,
        blobBody(await encryptBodyBlob(new Map([["body/v", new Uint8Array([3])]]), bek)),
        { ifMatch: "1" },
      );
    } catch (e) {
      caught = e as VaultError;
    }
    assert.ok(caught, "a stale-generation push must be rejected, not silently applied");
    assert.ok(caught instanceof VaultError, `expected VaultError; got ${caught?.constructor.name}`);
    assert.equal(caught!.status, 412, "stale If-Match must surface as HTTP 412 (precondition failed)");

    // The losing write must NOT have advanced the body: still generation 2.
    const blob = await client.getEncryptedBlob(projectId);
    assert.equal(
      blob["generation"],
      2,
      "the rejected push must not have mutated the body (generation unchanged)",
    );
  },
);
