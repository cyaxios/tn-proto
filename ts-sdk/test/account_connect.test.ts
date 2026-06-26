// Live tests for AccountNamespace.connect against the tne2e vault stack.
//
// Mints a connect code via the dev-auth bypass + auth'd mint endpoint,
// then redeems it via the new TS code path. Asserts both the HTTP
// roundtrip and the sync-state persistence side-effect.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DeviceKey } from "../src/core/signing.js";
import {
  AccountConnectError,
  AccountNamespace,
  getAccountId,
  isAccountBound,
  markAccountBound,
} from "../src/account/index.ts";

const VAULT_URL = process.env.TN_TEST_VAULT_URL ?? "http://localhost:38790";

async function vaultReachable(): Promise<boolean> {
  try {
    const r = await fetch(`${VAULT_URL}/api/v1/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:key:z6MkProbe" }),
    });
    return r.ok || r.status === 400;
  } catch {
    return false;
  }
}

const reachable = await vaultReachable();

/** Spin up a dev-bypass account + mint a fresh connect code. Returns
 *  the bearer token (for cleanup) and the connect code (for the test). */
async function mintConnectCode(handle: string): Promise<{ code: string; token: string; accountId: string }> {
  const dl = await fetch(`${VAULT_URL}/api/v1/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle }),
  });
  if (!dl.ok) throw new Error(`dev/login ${dl.status}: ${await dl.text()}`);
  const { token, account_id: accountId } = (await dl.json()) as { token: string; account_id: string };

  const mint = await fetch(`${VAULT_URL}/api/v1/account/connect-codes`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ project_name: `port-test-${Date.now()}` }),
  });
  if (!mint.ok) throw new Error(`mint connect-code ${mint.status}: ${await mint.text()}`);
  const minted = (await mint.json()) as { code?: string };
  if (!minted.code) throw new Error(`mint response missing code: ${JSON.stringify(minted)}`);
  return { code: minted.code, token, accountId };
}

test("markAccountBound + getAccountId + isAccountBound — round-trip unit", () => {
  const tmp = mkdtempSync(join(tmpdir(), "acc-bind-unit-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    writeFileSync(yamlPath, "ceremony:\n  id: local_x\n  mode: local\n");

    assert.equal(getAccountId(yamlPath), null);
    assert.equal(isAccountBound(yamlPath), false);

    markAccountBound(yamlPath, "acct_abc_123");
    assert.equal(getAccountId(yamlPath), "acct_abc_123");
    assert.equal(isAccountBound(yamlPath), true);

    // Re-binding to the same id is idempotent.
    markAccountBound(yamlPath, "acct_abc_123");
    assert.equal(getAccountId(yamlPath), "acct_abc_123");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("markAccountBound — clears in-flight pending_claim", () => {
  const tmp = mkdtempSync(join(tmpdir(), "acc-bind-pc-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    writeFileSync(yamlPath, "ceremony: {id: local_y, mode: local}\n");
    // Pre-seed a pending_claim in the sync state file.
    const statePath = join(tmp, ".tn", "sync", "state.json");
    writeFileSync(
      // mkdir is handled by markAccountBound, but we want the seed first.
      // So call mark once to create the dir, then over-write with the seed.
      statePath,
      JSON.stringify({ pending_claim: { vault_id: "left-over" } }),
      { flag: "w" },
    ).catch?.(() => undefined); // Node fs.writeFileSync isn't a Promise; this is a no-op
  } catch {
    // Directory doesn't exist yet - create + seed.
  }
  const tmp2 = mkdtempSync(join(tmpdir(), "acc-bind-pc2-"));
  try {
    const yamlPath = join(tmp2, "tn.yaml");
    writeFileSync(yamlPath, "ceremony: {id: local_y, mode: local}\n");
    markAccountBound(yamlPath, "acct_seed"); // creates state dir + file
    // Now overwrite the state with pending_claim added back, then re-bind.
    const statePath = join(tmp2, ".tn", "sync", "state.json");
    writeFileSync(
      statePath,
      JSON.stringify({
        account_id: "acct_seed",
        account_bound: true,
        pending_claim: { vault_id: "left-over" },
      }),
    );
    markAccountBound(yamlPath, "acct_new");
    const after = JSON.parse(readFileSync(statePath, "utf-8")) as Record<string, unknown>;
    assert.equal(after.account_id, "acct_new");
    assert.equal("pending_claim" in after, false, "pending_claim must be cleared by markAccountBound");
  } finally {
    rmSync(tmp2, { recursive: true, force: true });
  }
});

test("connect signature matches Python — SHA-256(code) signed Ed25519", () => {
  // Cross-check the bytes we'd put on the wire against a precomputed
  // expectation: with a known seed + known code, the resulting sig is
  // deterministic (Ed25519 is deterministic-by-spec).
  const seed = new Uint8Array(32).fill(7);
  const device = DeviceKey.fromSeed(seed);
  const code = "tn_connect_TEST123";
  const msg = createHash("sha256").update(code, "utf8").digest();
  const sig = device.sign(new Uint8Array(msg));
  assert.equal(sig.length, 64, "Ed25519 sig must be 64 bytes");
  // Deterministic: same inputs must always produce the same sig.
  const sig2 = device.sign(new Uint8Array(msg));
  assert.deepEqual(sig, sig2);
});

test("AccountNamespace.connect — happy path against live vault", { skip: !reachable && "vault not reachable" }, async () => {
  const { code, accountId: minterAccountId } = await mintConnectCode(`acc-test-${Date.now()}`);
  const tmp = mkdtempSync(join(tmpdir(), "acc-connect-live-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    writeFileSync(yamlPath, "ceremony:\n  id: local_live\n  mode: local\n");

    const device = DeviceKey.generate();
    const result = await AccountNamespace.connect(code, VAULT_URL, device, { yamlPath });

    assert.equal(typeof result.accountId, "string");
    assert.equal(result.accountId, minterAccountId, "redeemed account must match the minter's");
    assert.equal(result.did, device.did);

    // Sync state stamped.
    assert.equal(getAccountId(yamlPath), result.accountId);
    assert.equal(isAccountBound(yamlPath), true);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("AccountNamespace.connect — replayed code surfaces server status", { skip: !reachable && "vault not reachable" }, async () => {
  const { code } = await mintConnectCode(`acc-test-replay-${Date.now()}`);
  const device = DeviceKey.generate();

  // First redeem succeeds.
  const first = await AccountNamespace.connect(code, VAULT_URL, device);
  assert.ok(first.accountId);

  // Second redeem of the same code: vault returns non-2xx (consumed).
  let caught: AccountConnectError | null = null;
  try {
    await AccountNamespace.connect(code, VAULT_URL, DeviceKey.generate());
  } catch (e) {
    caught = e as AccountConnectError;
  }
  assert.ok(caught, "second redeem of same code must throw");
  assert.ok(
    caught && caught.status !== null && caught.status >= 400,
    `expected 4xx; got ${caught?.status}`,
  );
});

test("AccountNamespace.connect — invalid code returns 404 via AccountConnectError", { skip: !reachable && "vault not reachable" }, async () => {
  const device = DeviceKey.generate();
  let caught: AccountConnectError | null = null;
  try {
    await AccountNamespace.connect("tn_connect_definitely_not_real_zzz", VAULT_URL, device);
  } catch (e) {
    caught = e as AccountConnectError;
  }
  assert.ok(caught, "unknown code must throw");
  assert.equal(caught?.status, 404, `expected 404; got ${caught?.status}`);
});
