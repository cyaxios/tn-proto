// jwe recipient admin in the TS runtime: add a recipient (by DID + raw X25519
// public key), confirm they can decrypt a subsequent seal, then revoke and
// confirm they cannot open a later seal. Mirrors Python jwe add/revoke.
import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { AdminNamespace } from "../src/admin/index.js";
import { jweDecrypt, okpPrivateJwk } from "../src/core/jwe.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";

/** Pull group `g`'s raw ciphertext bytes from a decoded envelope. */
function groupCt(env: Record<string, unknown>, g: string): Uint8Array {
  const block = env[g] as { ciphertext?: string } | undefined;
  return new Uint8Array(Buffer.from(String(block?.ciphertext ?? ""), "base64"));
}

test("jwe admin: added recipient can decrypt, revoked recipient cannot", async () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-admin-"));
  const rt = NodeRuntime.init(join(work, "tn.yaml"), { cipher: "jwe" });
  const admin = new AdminNamespace(rt);

  // A recipient we control end-to-end.
  const bobPriv = x25519.utils.randomPrivateKey();
  const bobPub = x25519.getPublicKey(bobPriv);
  const bobJwk = okpPrivateJwk(bobPub, bobPriv);
  const bobDid = "did:key:z6MkBobJweRecipientTest0000000000000000000";

  // Raw DID-plus-key enrollment is the explicitly unverified path.
  const added = await admin.addRecipient("default", {
    recipientDid: bobDid,
    publicKey: bobPub,
    unsafeUnverified: true,
  });
  assert.equal(added.cipher, "jwe");
  assert.equal(added.recipientDid, bobDid);
  assert.equal(added.kitPath, null, "jwe recipients carry no kit");

  // Seal after add — bob's key opens the default group.
  await rt.emitAsync("info", "order.created", { amount: 100, currency: "USD" });
  let bobOpenedAfterAdd = false;
  for await (const e of rt.readAsync()) {
    if (e.envelope["event_type"] !== "order.created") continue;
    const pt = await jweDecrypt(bobJwk, groupCt(e.envelope, "default"));
    if (pt) bobOpenedAfterAdd = true;
  }
  assert.ok(bobOpenedAfterAdd, "added recipient could not decrypt");

  // Revoke bob, seal again — bob's key opens the pre-revocation seal but NOT the new one.
  await admin.revokeRecipient("default", { recipientDid: bobDid });
  const rec2 = await rt.emitAsync("info", "order.created", { amount: 200, currency: "EUR" });
  assert.ok(rec2.eventId);

  let bobOpenedNew = false;
  let sawPostRevoke = false;
  for await (const e of rt.readAsync()) {
    if (e.envelope["event_type"] !== "order.created") continue;
    const body = e.plaintext["default"] as Record<string, unknown>;
    if (Number(body["amount"]) !== 200) continue; // the post-revoke seal
    sawPostRevoke = true;
    const pt = await jweDecrypt(bobJwk, groupCt(e.envelope, "default"));
    if (pt) bobOpenedNew = true;
    // publisher still reads it fine
    assert.equal(body["currency"], "EUR");
  }
  assert.ok(sawPostRevoke, "post-revoke seal not found");
  assert.equal(bobOpenedNew, false, "revoked recipient still decrypts new seals");
});

test("ensureGroup(jwe) adds a jwe group to a btn ceremony (mixed, both open)", async () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-mixed-"));
  const rt = NodeRuntime.init(join(work, "tn.yaml")); // default btn ceremony
  const admin = new AdminNamespace(rt);
  await admin.ensureGroup("secrets", { cipher: "jwe", fields: ["ssn"] });

  await rt.emitAsync("info", "kyc.done", { ssn: "123-45-6789", note: "ok" });
  let opened = false;
  for await (const e of rt.readAsync()) {
    if (e.envelope["event_type"] !== "kyc.done") continue;
    // The JWE group and BTN default group both decrypt through the same read.
    assert.deepEqual(e.plaintext["secrets"], { ssn: "123-45-6789" });
    assert.deepEqual(e.plaintext["default"], { note: "ok" });
    opened = true;
  }
  assert.ok(opened, "mixed btn+jwe entry not read");
});
