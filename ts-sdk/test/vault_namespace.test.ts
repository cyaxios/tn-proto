import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Tn } from "../src/tn.js";

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
