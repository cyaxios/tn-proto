import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Tn } from "../src/tn.js";
import { loadConfig } from "../src/index.js";

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
