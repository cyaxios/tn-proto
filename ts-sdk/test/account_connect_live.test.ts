// LIVE round-trip test for `tn account connect` against the dev vault on
// 34987 (TN_DEV_AUTH_BYPASS=1).
//
// Connect-codes route (tn_proto_web/src/routes_account_connect.py):
//   mint   — POST /api/v1/account/connect-codes          (auth'd, dev JWT)
//   redeem — POST /api/v1/account/connect-codes/redeem    (UNAUTH; sig is the auth)
//
// The redeem proof-of-key is the client signing SHA-256(code) with its device
// Ed25519 key — the code IS the challenge, the signature IS the response, one
// round-trip. This drives the REAL TS redeem path (AccountNamespace.connect)
// and asserts: ok + account binding (redeemed account == minter's account, did
// echoed) + sync-state persistence (account_id + account_bound in
// .tn/sync/state.json). FAIL cases: invalid code (404), replayed code (>=400).
//
// CI-safe: probes the dev vault first and skips cleanly when unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test test/account_connect_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DeviceKey } from "../src/core/signing.js";
import {
  AccountConnectError,
  AccountNamespace,
  getAccountId,
  isAccountBound,
} from "../src/account/index.ts";

import { VAULT_BASE, mintConnectCode, uniqueHandle, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

test(
  "account connect — live: redeem a minted code binds the DID to the minter's account + stamps sync-state",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const { code, accountId: minterAccountId, projectName } = await mintConnectCode(
      uniqueHandle("connect"),
    );

    const tmp = mkdtempSync(join(tmpdir(), "connect-live-"));
    try {
      const yamlPath = join(tmp, "tn.yaml");
      writeFileSync(yamlPath, "ceremony:\n  id: connect_live\n  mode: local\n");

      const device = DeviceKey.generate();
      const result = await AccountNamespace.connect(code, VAULT_BASE, device, { yamlPath });

      // Binding: redeemed account == minter's, DID echoed, project echoed.
      assert.equal(typeof result.accountId, "string");
      assert.equal(result.accountId, minterAccountId, "redeemed account must equal the minter's");
      assert.equal(result.did, device.did, "response must echo the redeemer DID");
      assert.equal(result.projectName, projectName, "project_name must round-trip");
      assert.ok(typeof result.projectId === "string" && result.projectId.length > 0, "project_id present");

      // sync-state persisted (Python mark_account_bound parity).
      assert.equal(getAccountId(yamlPath), result.accountId, "sync-state account_id stamped");
      assert.equal(isAccountBound(yamlPath), true, "sync-state account_bound=true");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);

test(
  "account connect — FAIL: invalid code returns 404 via AccountConnectError",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const device = DeviceKey.generate();
    let caught: AccountConnectError | null = null;
    try {
      await AccountNamespace.connect("tn_connect_definitely_not_real_zzz", VAULT_BASE, device);
    } catch (e) {
      caught = e as AccountConnectError;
    }
    assert.ok(caught, "unknown code must throw");
    assert.equal(caught?.status, 404, `expected 404; got ${caught?.status}`);
  },
);

test(
  "account connect — FAIL: replayed (already-consumed) code is rejected",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const { code } = await mintConnectCode(uniqueHandle("connect-replay"));

    // First redeem consumes the single-use code.
    const first = await AccountNamespace.connect(code, VAULT_BASE, DeviceKey.generate());
    assert.ok(first.accountId, "first redeem must succeed");

    // Second redeem of the same code: vault returns non-2xx (409 consumed).
    let caught: AccountConnectError | null = null;
    try {
      await AccountNamespace.connect(code, VAULT_BASE, DeviceKey.generate());
    } catch (e) {
      caught = e as AccountConnectError;
    }
    assert.ok(caught, "second redeem of the same code must throw");
    assert.ok(
      caught && caught.status !== null && caught.status >= 400,
      `expected >=400 on replay; got ${caught?.status}`,
    );
  },
);
