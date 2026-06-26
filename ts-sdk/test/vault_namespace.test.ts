import { test } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Tn } from "../src/tn.js";
import { loadConfig } from "../src/index.js";
import { resolveAdminLogPath } from "../src/admin/log.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { asRowHash } from "../src/core/types.js";
import type { EmitReceipt } from "../src/core/results.js";
import type { NodeRuntime } from "../src/runtime/node_runtime.js";
import { VaultNamespace } from "../src/vault/index.js";

test("tn.vault.link delegates to NodeRuntime.vaultLink", async () => {
  const receipt: EmitReceipt = {
    eventId: "evt-link",
    rowHash: asRowHash("sha256:" + "1".repeat(64)),
    sequence: 7,
  };
  const calls: Array<unknown[]> = [];
  const fakeRuntime = {
    vaultLink(vaultDid: string, projectId: string): EmitReceipt {
      calls.push(["vaultLink", vaultDid, projectId]);
      return receipt;
    },
    emit(): never {
      throw new Error("VaultNamespace.link must not use generic emit");
    },
  } as unknown as NodeRuntime;

  const ns = new VaultNamespace(fakeRuntime);
  const result = await ns.link("did:key:zVault", "proj_123");

  assert.equal(result, receipt);
  assert.deepEqual(calls, [["vaultLink", "did:key:zVault", "proj_123"]]);
});

test("tn.vault.unlink delegates to NodeRuntime.vaultUnlink with reason", async () => {
  const receipt: EmitReceipt = {
    eventId: "evt-unlink",
    rowHash: asRowHash("sha256:" + "2".repeat(64)),
    sequence: 8,
  };
  const calls: Array<unknown[]> = [];
  const fakeRuntime = {
    vaultUnlink(vaultDid: string, projectId: string, reason?: string): EmitReceipt {
      calls.push(["vaultUnlink", vaultDid, projectId, reason]);
      return receipt;
    },
    emit(): never {
      throw new Error("VaultNamespace.unlink must not use generic emit");
    },
  } as unknown as NodeRuntime;

  const ns = new VaultNamespace(fakeRuntime);
  const result = await ns.unlink("did:key:zVault", "proj_123", "test");

  assert.equal(result, receipt);
  assert.deepEqual(calls, [["vaultUnlink", "did:key:zVault", "proj_123", "test"]]);
});

test("tn.vault.link emits tn.vault.linked and returns an EmitReceipt", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const r = await tn.vault.link("did:key:zVault", "proj_123");
    assert.equal(typeof r.eventId, "string");
    assert.equal(typeof r.rowHash, "string");
  } finally {
    await tn.close();
  }
});

test("tn.vault.unlink emits tn.vault.unlinked", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await tn.vault.link("did:key:zVault", "proj_123");
    const r = await tn.vault.unlink("did:key:zVault", "proj_123", "test");
    assert.equal(typeof r.eventId, "string");
  } finally {
    await tn.close();
  }
});

test("tn.vault.setLinkState flips ceremony.mode in the yaml (local <-> linked)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    // Fresh ephemeral ceremony starts local.
    assert.equal(loadConfig(tn.yamlPath).mode, "local");

    // linked requires a vault URL (Python's loader rejects mode:linked
    // without linked_vault).
    await tn.vault.setLinkState("linked", { linkedVault: "https://vault.example" });
    const linked = loadConfig(tn.yamlPath);
    assert.equal(linked.mode, "linked");
    assert.equal(linked.vault.url, "https://vault.example");

    await tn.vault.setLinkState("unlinked");
    assert.equal(loadConfig(tn.yamlPath).mode, "local");
  } finally {
    await tn.close();
  }
});

// Helper: read the vault_links recorded in the persisted admin LKV file (the
// on-disk materialized cache). vaultLink/vaultUnlink must call the cache's
// refresh() post-emit so this file is current immediately — without it the LKV
// stays stale until some later state()/recipients() read trips the
// log-advanced tripwire and re-persists. Mirrors Python's post-emit
// `tn._refresh_admin_cache_if_present()` contract. Both SDKs self-heal on
// READ, so the observable gap the fix closes is exactly this: the persisted
// snapshot a cross-process / direct LKV reader sees right after the emit.
function lkvVaultLinks(yamlPath: string): Array<Record<string, unknown>> {
  const lkv = join(dirname(yamlPath), ".tn", "admin", "admin.lkv.json");
  const doc = JSON.parse(readFileSync(lkv, "utf8")) as Record<string, unknown>;
  const state = (doc["state"] ?? {}) as Record<string, unknown>;
  const links = state["vaultLinks"];
  return Array.isArray(links) ? (links as Array<Record<string, unknown>>) : [];
}

test("tn.vault.link refreshes the admin cache: persisted LKV reflects the link without a manual read/refresh (parity with Python)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    // Prime the admin cache BEFORE linking so the runtime holds a live
    // AdminStateCache instance (mirrors a long-lived process that already
    // queried tn.admin.state()) and persists an LKV with zero links.
    const before = tn.admin.state();
    assert.equal(before.vaultLinks.length, 0, "no links before linking");

    await tn.vault.link("did:key:zVault", "proj_123");

    // Read the persisted LKV directly — NOT through state()/recipients(),
    // which would self-heal and mask a missing post-emit refresh.
    const active = lkvVaultLinks(tn.yamlPath).filter(
      (l) => l["vaultDid"] === "did:key:zVault" && l["projectId"] === "proj_123" && l["unlinkedAt"] === null,
    );
    assert.equal(active.length, 1, "persisted LKV reflects the new vault link without a manual refresh");
  } finally {
    await tn.close();
  }
});

test("tn.vault.unlink refreshes the admin cache: persisted LKV reflects the unlink without a manual read/refresh (parity with Python)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await tn.vault.link("did:key:zVault", "proj_123");
    // Prime the cache against the linked state so the unlink below must
    // explicitly refresh + re-persist the LKV to become visible there.
    const linked = tn.admin.state();
    assert.equal(
      linked.vaultLinks.filter((l) => l.unlinkedAt === null).length,
      1,
      "one active link before unlinking",
    );

    await tn.vault.unlink("did:key:zVault", "proj_123", "test");

    const stillActive = lkvVaultLinks(tn.yamlPath).filter(
      (l) => l["vaultDid"] === "did:key:zVault" && l["projectId"] === "proj_123" && l["unlinkedAt"] === null,
    );
    assert.equal(stillActive.length, 0, "persisted LKV reflects the unlink without a manual refresh");
  } finally {
    await tn.close();
  }
});

test("tn.vault.link is idempotent: re-linking the same target emits no second event (parity with Python)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await tn.vault.link("did:key:zVault", "proj_123");
    await tn.vault.link("did:key:zVault", "proj_123"); // no-op per Python _vault_link_impl
    const adminPath = resolveAdminLogPath(tn.config() as CeremonyConfig);
    const lines = readFileSync(adminPath, "utf8").trim().split("\n").filter(Boolean);
    const linked = lines.filter((l) => l.includes('"tn.vault.linked"')).length;
    assert.equal(linked, 1, "only one tn.vault.linked after re-linking the same (vaultDid, projectId)");
  } finally {
    await tn.close();
  }
});
