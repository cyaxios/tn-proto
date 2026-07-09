import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import {
  createJweGroup,
  jweAddRecipient,
  jweRecipients,
  jweRevokeRecipient,
  jweRotateGroup,
} from "../src/runtime/jwe_group.js";

const DID_SELF = "did:key:z6MkSelfJweLifecycle0000000000000000000";
const DID_BOB = "did:key:z6MkBobJweLifecycle00000000000000000000";

test("jwe add/revoke/rotate require an existing recipients file", () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-missing-recipients-"));
  const bobPub = x25519.getPublicKey(x25519.utils.randomPrivateKey());
  try {
    assert.throws(() => jweAddRecipient(work, "missing", DID_BOB, bobPub), /recipients file/i);
    assert.throws(() => jweRevokeRecipient(work, "missing", DID_BOB), /recipients file/i);
    assert.throws(
      () => jweRotateGroup(work, "missing", DID_SELF, "20260101T000000Z"),
      /recipients file/i,
    );
    assert.equal(existsSync(join(work, "missing.jwe.recipients")), false);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("jwe recipient documents and public keys are validated before mutation", () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-recipient-validation-"));
  const bobPub = x25519.getPublicKey(x25519.utils.randomPrivateKey());
  const recipientsPath = join(work, "g.jwe.recipients");
  try {
    writeFileSync(
      recipientsPath,
      JSON.stringify([
        { recipient_identity: DID_SELF, pub_b64: Buffer.from([1, 2, 3]).toString("base64") },
      ]),
      "utf8",
    );
    assert.throws(() => jweRecipients(work, "g"), /recipient public key/i);
    assert.throws(() => jweAddRecipient(work, "g", DID_BOB, bobPub), /recipient public key/i);

    writeFileSync(recipientsPath, JSON.stringify({ recipient_identity: DID_SELF }), "utf8");
    assert.throws(() => jweRevokeRecipient(work, "g", DID_SELF), /recipients.*array/i);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("createJweGroup refuses to overwrite existing group material", () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-create-no-overwrite-"));
  try {
    createJweGroup(work, "g", DID_SELF);
    const originalSender = readFileSync(join(work, "g.jwe.sender"));
    const originalMyKey = readFileSync(join(work, "g.jwe.mykey"));
    const originalRecipients = readFileSync(join(work, "g.jwe.recipients"), "utf8");

    assert.throws(() => createJweGroup(work, "g", DID_BOB), /already exists/i);
    assert.deepEqual(readFileSync(join(work, "g.jwe.sender")), originalSender);
    assert.deepEqual(readFileSync(join(work, "g.jwe.mykey")), originalMyKey);
    assert.equal(readFileSync(join(work, "g.jwe.recipients"), "utf8"), originalRecipients);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("jwe rotate stages new material before archiving active files", () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-rotate-stage-first-"));
  try {
    createJweGroup(work, "g", DID_SELF);
    mkdirSync(join(work, "g.jwe.sender.tmp"));
    mkdirSync(join(work, "g.jwe.sender.pending.tmp"));

    assert.throws(() => jweRotateGroup(work, "g", DID_SELF, "20260101T000000Z"));

    assert.equal(existsSync(join(work, "g.jwe.sender")), true);
    assert.equal(existsSync(join(work, "g.jwe.mykey")), true);
    assert.equal(existsSync(join(work, "g.jwe.recipients")), true);
    assert.deepEqual(
      readdirSync(work).filter((entry) => entry.includes(".revoked.")),
      [],
      "active files were archived before replacement material was staged",
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
