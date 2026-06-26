// Tests for redeemAwkPickup (src/vault/awk_pickup.ts).
//
// Strategy: inject a `fetchImpl` that handles all three network calls
// that flow through (challenge, verify, awk-pickups GET). The test
// also temporarily swaps globalThis.fetch so challengeVerify's internal
// _httpPost calls hit the same stub.
//
// Run:
//   node --import tsx --import ./test/_setup_wasm.mjs --test "test/awk_pickup.test.ts"

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { test } from "node:test";

import { DeviceKey } from "../src/core/signing.ts";
import { sealBekForRecipient } from "../src/core/recipient_seal.ts";
import { FileCredentialStore, awkKeyName } from "../src/vault/credential_store.ts";
import { awkPickupAad, redeemAwkPickup } from "../src/vault/awk_pickup.ts";

const VAULT_BASE = "http://vault.test";
const ACCOUNT_ID = "acct_test_123";
const KEY_ID_B64 = "aGVsbG93b3JsZA"; // arbitrary base64-ish string
const NONCE = "test-nonce-abc";
const TOKEN = "jwt-test-token";

/**
 * Build a fetch stub that handles:
 *   POST /api/v1/auth/challenge  → { nonce }
 *   POST /api/v1/auth/verify     → { token }
 *   GET  /api/v1/account/awk-pickups/:keyId → { wrap, account_id }
 *
 * `pickupStatus` lets tests inject a non-200 for the GET.
 * `pickupBody` overrides the response body for the GET.
 */
function makeFetchStub(
  wrap: unknown,
  opts: { pickupStatus?: number; pickupBody?: unknown } = {},
): typeof fetch {
  const pickupStatus = opts.pickupStatus ?? 200;
  const pickupBody = opts.pickupBody ?? { wrap, account_id: ACCOUNT_ID };

  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);

    if (u.endsWith("/api/v1/auth/challenge")) {
      return new Response(JSON.stringify({ nonce: NONCE }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (u.endsWith("/api/v1/auth/verify")) {
      return new Response(JSON.stringify({ token: TOKEN }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (u.includes("/api/v1/account/awk-pickups/")) {
      // Verify the Authorization header was forwarded.
      const auth = (init?.headers as Record<string, string> | undefined)?.Authorization ?? "";
      if (!auth.startsWith("Bearer ")) {
        return new Response("missing bearer", { status: 401 });
      }
      return new Response(JSON.stringify(pickupBody), {
        status: pickupStatus,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response("unexpected url: " + u, { status: 500 });
  }) as unknown as typeof fetch;
}

test("redeemAwkPickup — happy path: stores the unsealed AWK in a FileCredentialStore", async () => {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const did = DeviceKey.fromSeed(seed).did;

  // The awk bytes we want the device to receive.
  const awk = new Uint8Array(32);
  crypto.getRandomValues(awk);

  // Seal the AWK for this device's DID, using the account AAD.
  const aad = awkPickupAad(ACCOUNT_ID);
  const wrap = await sealBekForRecipient(awk, did, aad);

  const tmp = mkdtempSync(join(tmpdir(), `awk-pickup-${randomUUID()}-`));
  try {
    const store = new FileCredentialStore(join(tmp, "credentials.json"));
    const fetchStub = makeFetchStub(wrap);

    const result = await redeemAwkPickup({
      vaultBase: VAULT_BASE,
      deviceSeed: seed,
      accountId: ACCOUNT_ID,
      keyIdB64: KEY_ID_B64,
      store,
      fetchImpl: fetchStub,
    });

    assert.equal(result, true, "redeemAwkPickup should return true on success");

    const cached = store.get(awkKeyName(ACCOUNT_ID));
    assert.ok(cached !== null, "AWK must be cached in the store");
    assert.equal(cached.length, 32, "cached AWK must be 32 bytes");
    assert.deepEqual(
      Array.from(cached),
      Array.from(awk),
      "cached AWK must equal the original AWK bytes",
    );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("redeemAwkPickup — 404 from vault returns false and stores nothing", async () => {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);

  const tmp = mkdtempSync(join(tmpdir(), `awk-pickup-404-${randomUUID()}-`));
  try {
    const store = new FileCredentialStore(join(tmp, "credentials.json"));
    // wrap doesn't matter since the GET returns 404
    const fetchStub = makeFetchStub({}, { pickupStatus: 404 });

    const result = await redeemAwkPickup({
      vaultBase: VAULT_BASE,
      deviceSeed: seed,
      accountId: ACCOUNT_ID,
      keyIdB64: KEY_ID_B64,
      store,
      fetchImpl: fetchStub,
    });

    assert.equal(result, false, "redeemAwkPickup should return false on 404");
    assert.equal(
      store.get(awkKeyName(ACCOUNT_ID)),
      null,
      "nothing should be cached when the pickup fails",
    );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
