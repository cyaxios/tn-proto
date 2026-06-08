import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Tn } from "../src/tn.js";
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

test("tn.vault.setLinkState throws a clear not-implemented error", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await assert.rejects(
      () => tn.vault.setLinkState("linked"),
      (err: Error) => {
        assert.ok(err.message.includes("not yet ported from Python"), err.message);
        return true;
      },
    );
  } finally {
    await tn.close();
  }
});
