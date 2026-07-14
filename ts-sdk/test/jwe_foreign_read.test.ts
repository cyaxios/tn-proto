// Cross-party jwe: a publisher adds a recipient, emits, and the recipient reads
// the publisher's log with an absorbed key via the async foreign-read path
// (readAsRecipientAsync). Also proves the cipher-agnostic kit_bundle absorb
// installs a jwe reader key, so the recipient's keystore is set up by absorb.
import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { AdminNamespace } from "../src/admin/index.js";
import { readAsRecipientAsync } from "../src/read_as_recipient.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";

test("recipient reads a publisher's jwe log via readAsRecipientAsync", async () => {
  const aDir = mkdtempSync(join(tmpdir(), "jwe-pub-"));
  const rtA = NodeRuntime.init(join(aDir, "tn.yaml"), { cipher: "jwe" });

  // A mints B's recipient keypair and enrolls B by public key (the raw
  // DID-plus-key path, which is explicitly unverified).
  const bPriv = x25519.utils.randomPrivateKey();
  await new AdminNamespace(rtA).addRecipient("default", {
    recipientDid: "did:key:z6MkBobForeignRead000000000000000000000000",
    publicKey: x25519.getPublicKey(bPriv),
    unsafeUnverified: true,
  });
  await rtA.emitAsync("info", "shared.record", { secret: "for-bob", amount: 500 });

  // B's keystore holds B's reader key — exactly what _absorbKitBundle installs
  // from a kit_bundle body (`body/default.jwe.mykey`).
  const bKeys = mkdtempSync(join(tmpdir(), "jwe-recip-"));
  writeFileSync(join(bKeys, "default.jwe.mykey"), Buffer.from(bPriv));

  const aLog = join(aDir, ".tn", "tn", "logs", "tn.ndjson");
  const opened: Record<string, unknown>[] = [];
  for await (const e of readAsRecipientAsync(aLog, bKeys, {
    group: "default",
    unsafeAllowUnverifiedPublisher: true,
  })) {
    if (e.envelope["event_type"] !== "shared.record") continue;
    assert.equal(e.valid.signature, true);
    assert.equal(e.valid.chain, true);
    opened.push(e.plaintext["default"]);
  }
  assert.equal(opened.length, 1, "recipient did not read the publisher's entry");
  assert.deepEqual(opened[0], { secret: "for-bob", amount: 500 });
});

test("absorbPkg installs a jwe reader key from a kit_bundle body", async () => {
  // Publisher A with a jwe ceremony (A is its own recipient: A.jwe.mykey exists).
  const aDir = mkdtempSync(join(tmpdir(), "jwe-exp-"));
  const rtA = NodeRuntime.init(join(aDir, "tn.yaml"), { cipher: "jwe" });
  await rtA.emitAsync("info", "e", { a: 1 });

  // A exports a kit_bundle addressed to the exact device that absorbs it.
  const bDir = mkdtempSync(join(tmpdir(), "jwe-abs-"));
  mkdirSync(join(bDir, ".tn", "tn", "keys"), { recursive: true });
  // Minimal B ceremony to host the absorb (btn default is fine as the shell).
  const rtB = NodeRuntime.init(join(bDir, "tn.yaml"), {
    cipher: "btn",
    devicePrivateBytes: undefined,
  } as { cipher: "btn" });
  const bundlePath = join(mkdtempSync(join(tmpdir(), "jwe-bundle-")), "kit.tnpkg");
  rtA.exportPkg({ kind: "kit_bundle", toDid: rtB.did }, bundlePath);
  const receipt = rtB.absorbPkg(bundlePath);
  assert.ok(receipt.acceptedCount >= 1, `absorb installed nothing: ${JSON.stringify(receipt)}`);
  assert.equal(receipt.verifiedPublisherDid, rtA.did);
});
