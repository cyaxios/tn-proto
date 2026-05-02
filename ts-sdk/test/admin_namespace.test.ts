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

test("tn.admin.rotate throws on btn cipher (not supported)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await assert.rejects(
      tn.admin.rotate("default"),
      /btn cipher does not support in-band rotation/,
    );
  } finally {
    await tn.close();
  }
});
