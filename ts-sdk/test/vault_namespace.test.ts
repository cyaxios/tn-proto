import { test } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
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
