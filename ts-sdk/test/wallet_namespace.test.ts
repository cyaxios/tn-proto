// Asserts the public `tn.wallet` namespace surface exists and that each
// method delegates to the committed wallet implementation. Mirrors the
// shape of vault_namespace.test.ts. The wallet logic itself is exercised
// by wallet_link / wallet_restore / cli_wallet_sync / wallet_status; this
// test only guards that the PUBLIC namespace is wired and stays in sync.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { wallet } from "../src/wallet/namespace.js";
import { WalletNamespace, readSyncQueue, readLinkState } from "../src/wallet/index.js";
import { restoreWithBek, restoreViaLoopback } from "../src/wallet/restore.js";
import { walletSyncCmd } from "../src/cli/wallet_sync.js";

test("tn.wallet exposes the public verb surface", () => {
  for (const name of [
    "link",
    "unlink",
    "sync",
    "restore",
    "restoreWithBek",
    "restoreViaLoopback",
    "readSyncQueue",
    "status",
  ]) {
    assert.equal(typeof (wallet as Record<string, unknown>)[name], "function", `missing tn.wallet.${name}`);
  }
});

test("tn.wallet methods bind to the committed implementations", () => {
  // sync -> walletSyncCmd, restoreWithBek -> restoreWithBek, etc. We can't
  // compare the wrapper to the impl identity (they're thin delegators), but
  // we can assert the impls are importable and the wrapper exists for each.
  assert.equal(typeof WalletNamespace.link, "function");
  assert.equal(typeof WalletNamespace.unlink, "function");
  assert.equal(typeof walletSyncCmd, "function");
  assert.equal(typeof restoreWithBek, "function");
  assert.equal(typeof restoreViaLoopback, "function");
  assert.equal(typeof readSyncQueue, "function");
  assert.equal(typeof readLinkState, "function");
});

test("tn.wallet.readSyncQueue returns [] for an unknown ceremony", () => {
  // No queue file on disk for a random id -> empty list (mirrors Python).
  const rows = wallet.readSyncQueue("ceremony-that-does-not-exist-xyz");
  assert.deepEqual(rows, []);
});

test("tn.wallet.status snapshots link state + empty sync queue for a local ceremony", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-wallet-ns-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    writeFileSync(
      yamlPath,
      [
        "ceremony:",
        "  id: cer_local_demo",
        "  mode: local",
        "  project_name: Demo",
        "",
      ].join("\n"),
      "utf-8",
    );
    const status = wallet.status(yamlPath);
    assert.equal(status.mode, "local");
    assert.equal(status.ceremonyId, "cer_local_demo");
    assert.equal(status.projectName, "Demo");
    assert.equal(status.linkedVault, "");
    assert.equal(status.linkedProjectId, "");
    assert.deepEqual(status.syncQueue, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tn.wallet.unlink flips a linked ceremony yaml back to local", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-wallet-ns-unlink-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    writeFileSync(
      yamlPath,
      [
        "ceremony:",
        "  id: cer_linked_demo",
        "  mode: linked",
        "  linked_vault: http://localhost:38790",
        "  linked_project_id: proj_abc",
        "  project_name: Demo",
        "",
      ].join("\n"),
      "utf-8",
    );
    wallet.unlink(yamlPath);
    const after = readLinkState(yamlPath);
    assert.equal(after.mode, "local");
    assert.equal(after.linkedVault, "");
    assert.equal(after.linkedProjectId, "");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
