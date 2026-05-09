import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../src/tn.js";

test("tn.admin.addRecipient returns AddRecipientResult", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-admin-test-"));
  try {
    const result = await tn.admin.addRecipient("default", {
      outKitPath: join(tmp, "kit.btn.mykit"),
    });
    assert.equal(typeof result.leafIndex, "number");
    assert.equal(typeof result.kitPath, "string");
    assert.equal(typeof result.kitSha256, "string");
    assert.equal(result.kitSha256.length, 64); // sha256 hex
    assert.equal(typeof result.mintedAt, "string");
    assert.equal(result.cipher, "btn");
    assert.equal(result.group, "default");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.admin.recipients returns RecipientEntry[]", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const recipients = tn.admin.recipients("default");
    assert.ok(Array.isArray(recipients));
  } finally {
    await tn.close();
  }
});

test("tn.admin.state returns AdminState", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const state = tn.admin.state();
    assert.ok(state);
    assert.ok(Array.isArray(state.groups));
    assert.ok(Array.isArray(state.recipients));
  } finally {
    await tn.close();
  }
});

test("tn.admin.rotate(group) succeeds on btn — bumps generation, swaps state", async () => {
  // 0.4.0a3+: TS BTN rotation is implemented. mints a fresh BtnPublisher,
  // swaps the on-disk state + self-kit, bumps groups.<g>.index_epoch in
  // the yaml, and emits tn.rotation.completed. Verify the result shape +
  // that it doesn't reject.
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const result = await tn.admin.rotate("default");
    assert.equal(result.cipher, "btn");
    assert.equal(result.group, "default");
    assert.ok(result.generation >= 1, `generation should be >= 1, got ${result.generation}`);
    assert.match(
      result.previousKitSha256,
      /^sha256:/,
      "previousKitSha256 should be sha256-prefixed",
    );
    assert.match(result.newKitSha256, /^sha256:/, "newKitSha256 should be sha256-prefixed");
    assert.notEqual(
      result.previousKitSha256,
      result.newKitSha256,
      "rotation must produce new key material (different sha)",
    );
  } finally {
    await tn.close();
  }
});

test("tn.admin.rotate(group) rejects unknown group", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await assert.rejects(tn.admin.rotate("nonexistent"), /unknown group/);
  } finally {
    await tn.close();
  }
});
