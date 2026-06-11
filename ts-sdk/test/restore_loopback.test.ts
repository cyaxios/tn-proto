import { test } from "node:test";
import { strict as assert } from "node:assert";

import { LoopbackReceiver } from "../src/wallet/restore_loopback.js";

// Port parity with python/tn/wallet_restore_loopback.py: the receiver binds
// 127.0.0.1, enforces the state nonce, requires the 4 token fields, and
// echoes CORS for the configured vault origin.

const VAULT_ORIGIN = "http://localhost:38790";

async function post(url: string, body: unknown, origin = VAULT_ORIGIN): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify(body),
  });
}

test("delivers a valid token to waitForToken + echoes CORS", async () => {
  const rx = await LoopbackReceiver.start({ state: "S-NONCE", allowOrigin: VAULT_ORIGIN });
  try {
    assert.match(rx.callbackUrl, /^http:\/\/127\.0\.0\.1:\d+\/cb$/);
    const tokenPromise = rx.waitForToken({ timeoutMs: 5000 });
    const resp = await post(rx.callbackUrl, {
      state: "S-NONCE",
      vault_jwt: "jwt.abc",
      account_id: "01ACCT",
      project_id: "proj_1",
      raw_bek_b64: "AAAA",
      package_did: null,
    });
    assert.equal(resp.status, 200);
    assert.equal(resp.headers.get("access-control-allow-origin"), VAULT_ORIGIN);
    const token = await tokenPromise;
    assert.equal(token.vaultJwt, "jwt.abc");
    assert.equal(token.accountId, "01ACCT");
    assert.equal(token.projectId, "proj_1");
    assert.equal(token.rawBekB64, "AAAA");
  } finally {
    rx.shutdown();
  }
});

test("rejects a state mismatch (stale/cross-run token)", async () => {
  const rx = await LoopbackReceiver.start({ state: "RIGHT", allowOrigin: VAULT_ORIGIN });
  try {
    const resp = await post(rx.callbackUrl, {
      state: "WRONG",
      vault_jwt: "j",
      account_id: "a",
      project_id: "p",
      raw_bek_b64: "b",
    });
    assert.equal(resp.status, 400);
    assert.match(await resp.text(), /state mismatch/);
  } finally {
    rx.shutdown();
  }
});

test("rejects a token missing required fields", async () => {
  const rx = await LoopbackReceiver.start({ state: "S", allowOrigin: VAULT_ORIGIN });
  try {
    const resp = await post(rx.callbackUrl, { state: "S", vault_jwt: "j" });
    assert.equal(resp.status, 400);
    assert.match(await resp.text(), /missing fields/);
  } finally {
    rx.shutdown();
  }
});

test("OPTIONS preflight returns 204 with CORS headers", async () => {
  const rx = await LoopbackReceiver.start({ state: "S", allowOrigin: VAULT_ORIGIN });
  try {
    const resp = await fetch(rx.callbackUrl, {
      method: "OPTIONS",
      headers: { Origin: VAULT_ORIGIN },
    });
    assert.equal(resp.status, 204);
    assert.equal(resp.headers.get("access-control-allow-origin"), VAULT_ORIGIN);
    assert.match(resp.headers.get("access-control-allow-methods") ?? "", /POST/);
  } finally {
    rx.shutdown();
  }
});

test("GET /cb is 405 POST-only", async () => {
  const rx = await LoopbackReceiver.start({ state: "S" });
  try {
    const resp = await fetch(rx.callbackUrl, { method: "GET" });
    assert.equal(resp.status, 405);
  } finally {
    rx.shutdown();
  }
});

test("waitForToken rejects on timeout", async () => {
  const rx = await LoopbackReceiver.start({ state: "S" });
  try {
    await assert.rejects(rx.waitForToken({ timeoutMs: 200 }), /no transfer token received/);
  } finally {
    rx.shutdown();
  }
});
