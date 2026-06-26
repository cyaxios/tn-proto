// LIVE e2e for the two things that actually matter and that mock tests can't
// catch: (1) `tn auth login` can START — the device/code route returns a real
// user_code + verification URL (this is the route that 405'd in prod because it
// was undeployed); (2) a fresh ceremony's encrypted backup ACTUALLY uploads to
// the vault and a claim URL comes back.
//
// Target vault: TN_VAULT_URL or PLUMB_VAULT, else the dev vault. CI-safe: probes
// the device route first and skips cleanly when it's not live (so an undeployed
// vault SKIPS rather than silently passing — and a deploy you mean to verify is
// run with TN_VAULT_URL=https://vault.tn-proto.org).
//
// Run against prod:
//   TN_VAULT_URL=https://vault.tn-proto.org node --import tsx \
//     --import ./test/_setup_wasm.mjs --test test/auth_backup_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { webcrypto } from "node:crypto";

import { DeviceKey } from "../src/core/signing.js";
import { requestDeviceCode } from "../src/auth/device_flow.js";
import { Tn } from "../src/tn.js";
import { VAULT_BASE } from "./_vault_live.ts";

const BASE = (process.env.TN_VAULT_URL ?? VAULT_BASE).replace(/\/+$/, "");

/** Live iff POST /device/code is actually served (a 4xx validation answer, not
 *  404/405 = undeployed, not a connection error = vault down). */
async function deviceRouteLive(base: string): Promise<boolean> {
  try {
    const r = await fetch(`${base}/api/v1/device/code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:key:zProbe", signature_b64: "x" }),
    });
    return r.status !== 404 && r.status !== 405;
  } catch {
    return false;
  }
}

const live = await deviceRouteLive(BASE);
const skip = live ? false : `device route not live at ${BASE}`;

test("live: device/code returns a real user_code + verification URL", { skip }, async () => {
  const seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);
  const key = DeviceKey.fromSeed(seed);

  const dc = await requestDeviceCode(BASE, key, key.did);
  assert.match(dc.userCode, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/, `user_code shape: ${dc.userCode}`);
  assert.ok(dc.verificationUri.endsWith("/device"), `verification_uri: ${dc.verificationUri}`);
  assert.ok(dc.deviceCode.length > 0, "device_code present");
  assert.ok(
    dc.verificationUriComplete.includes(dc.userCode),
    `complete URL carries the code: ${dc.verificationUriComplete}`,
  );
});

test("live: a fresh ceremony uploads an encrypted backup + returns a claim URL", { skip }, async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const res = await tn.initUpload({ vaultBase: BASE });
    assert.ok(res.vaultId && res.vaultId.length > 0, "vault_id returned by the vault");
    assert.ok(res.expiresAt && res.expiresAt.length > 0, "expires_at returned");
    assert.ok(res.claimUrl.includes("/claim/"), `claim URL: ${res.claimUrl}`);
    assert.ok(res.claimUrl.includes("#k="), "claim URL carries the BEK fragment");
  } finally {
    await tn.close();
  }
});
