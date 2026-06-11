// Polymorphic `recipient` field on tn.admin.{addRecipient,revokeRecipient}.
// Mirrors python/tests/test_admin_unified_api.py polymorphic tests.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../src/tn.js";
import {
  did,
  leafIndex,
  publicKeyBytes,
  resolveRecipient,
} from "../src/admin/recipient.js";

test("tn.admin.addRecipient accepts recipient as DID string", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-recipient-test-"));
  try {
    const result = await tn.admin.addRecipient("default", {
      recipient: "did:key:zAlice",
      outKitPath: join(tmp, "alice.btn.mykit"),
    });
    assert.equal(result.recipientDid, "did:key:zAlice");
    assert.equal(typeof result.leafIndex, "number");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.admin.addRecipient accepts recipient via branded did() helper", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-recipient-test-"));
  try {
    const result = await tn.admin.addRecipient("default", {
      recipient: did("did:key:zBranded"),
      outKitPath: join(tmp, "branded.btn.mykit"),
    });
    assert.equal(result.recipientDid, "did:key:zBranded");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.admin.revokeRecipient on btn accepts recipient as DID string (closes backlog #14)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-recipient-test-"));
  try {
    await tn.admin.addRecipient("default", {
      recipient: "did:key:zCarol",
      outKitPath: join(tmp, "carol.btn.mykit"),
    });
    const result = await tn.admin.revokeRecipient("default", {
      recipient: "did:key:zCarol",
    });
    assert.equal(result.cipher, "btn");
    assert.equal(result.recipientDid, "did:key:zCarol");
    assert.equal(typeof result.leafIndex, "number");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.admin.revokeRecipient accepts recipient as AddRecipientResult (round-trip)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-recipient-test-"));
  try {
    const add = await tn.admin.addRecipient("default", {
      recipient: "did:key:zDave",
      outKitPath: join(tmp, "dave.btn.mykit"),
    });
    const result = await tn.admin.revokeRecipient("default", { recipient: add });
    assert.equal(result.leafIndex, add.leafIndex);
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.admin.revokeRecipient accepts recipient as int leaf via leafIndex() brand", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-recipient-test-"));
  try {
    const add = await tn.admin.addRecipient("default", {
      recipient: "did:key:zErin",
      outKitPath: join(tmp, "erin.btn.mykit"),
    });
    const result = await tn.admin.revokeRecipient("default", {
      recipient: leafIndex(add.leafIndex),
    });
    assert.equal(result.leafIndex, add.leafIndex);
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("resolveRecipient: rejects non-DID string", () => {
  assert.throws(() => resolveRecipient("not-a-did"), /DID/);
});

test("resolveRecipient: rejects 31-byte public key", () => {
  assert.throws(() => resolveRecipient(new Uint8Array(31)), /32-byte/);
});

test("resolveRecipient: rejects negative leaf", () => {
  assert.throws(() => resolveRecipient(-1), /non-negative/);
});

test("resolveRecipient: rejects boolean", () => {
  // @ts-expect-error — boolean isn't in the union; runtime check still fires.
  assert.throws(() => resolveRecipient(true), /boolean/);
});

test("resolveRecipient: dict with x25519PubB64 decodes to bytes", () => {
  const pub = new Uint8Array(32).fill(0xab);
  const b64 = Buffer.from(pub).toString("base64");
  const out = resolveRecipient({ recipientDid: "did:key:zXyz", x25519PubB64: b64 });
  assert.equal(out.recipientDid, "did:key:zXyz");
  assert.deepEqual(out.publicKey, pub);
});

test("resolveRecipient: empty dict throws", () => {
  assert.throws(() => resolveRecipient({} as Record<string, never>), /at least one/);
});

test("publicKeyBytes(): rejects wrong-length input", () => {
  assert.throws(() => publicKeyBytes(new Uint8Array(16)), /32-byte/);
});

test("did(): rejects non-DID input", () => {
  assert.throws(() => did("hello"), /DID/);
});

test("leafIndex(): rejects float input", () => {
  assert.throws(() => leafIndex(1.5), /non-negative integer/);
});
