// Alice s09 — multi-recipient access-control proof.
//
// This is the canonical test that the broadcast-encryption value prop works:
//   - Bob gets a kit for Alice's `default` group → can decrypt default fields.
//   - Bob has NO kit for Alice's `private` group → cannot decrypt private fields.
//
// Setup:
//   1. Alice's ceremony has two groups: `default` and `private` (yaml-driven).
//   2. Alice emits events that route fields to both groups.
//   3. Alice mints a kit for Bob scoped to `default` only (via addRecipient).
//   4. Bob reads Alice's log:
//      a. readAsRecipient({group:"default"}) → plaintext decrypts cleanly.
//      b. readAsRecipient({group:"private"}) → throws "no recipient kit" (Bob
//         has no private.btn.mykit in his keystore directory).

import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { DeviceKey, readAsRecipient } from "../../../src/index.js";
import { BtnPublisher } from "../../../src/raw.js";
import { NodeRuntime } from "../../../src/index.js";

// A fixed Bob DID for the kit issuance attestation.
const BOB_DID = "did:key:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBobBobB";

interface S09Ceremony {
  aliceYamlPath: string;
  aliceKeystorePath: string;
  aliceLogPath: string;
  bobKeystorePath: string;
  cleanup: () => void;
}

function makeS09Ceremony(): S09Ceremony {
  const root = mkdtempSync(join(tmpdir(), "tn-s09-"));
  const aliceDir = join(root, "alice");
  const aliceKeys = join(aliceDir, ".tn/keys");
  const aliceLogs = join(aliceDir, ".tn/logs");
  const bobKeystorePath = join(root, "bob-keystore");

  mkdirSync(aliceKeys, { recursive: true });
  mkdirSync(aliceLogs, { recursive: true });
  mkdirSync(bobKeystorePath, { recursive: true });

  // Alice's device key.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 13;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(aliceKeys, "local.private"), Buffer.from(seed));
  writeFileSync(join(aliceKeys, "local.public"), dk.did, "utf8");

  // Index master.
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i++) indexMaster[i] = (i * 9 + 1) & 0xff;
  writeFileSync(join(aliceKeys, "index_master.key"), Buffer.from(indexMaster));

  // BtnPublisher for each group: default and private.
  for (let g = 0; g < 2; g++) {
    const gname = g === 0 ? "default" : "private";
    const btnSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) btnSeed[i] = (i * 3 + 5 + g * 23) & 0xff;
    const pub = new BtnPublisher(btnSeed);
    const kit = pub.mint();
    writeFileSync(join(aliceKeys, `${gname}.btn.state`), Buffer.from(pub.toBytes()));
    writeFileSync(join(aliceKeys, `${gname}.btn.mykit`), Buffer.from(kit));
  }

  const aliceDid = dk.did;
  const yaml = [
    "ceremony:",
    "  id: s09_multi_recipient",
    "  mode: local",
    "  cipher: btn",
    "logs:",
    "  path: ./.tn/logs/tn.ndjson",
    "keystore:",
    "  path: ./.tn/keys",
    "me:",
    `  did: ${aliceDid}`,
    "public_fields:",
    "- timestamp",
    "- event_id",
    "- event_type",
    "- level",
    "default_policy: private",
    "groups:",
    "  default:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${aliceDid}`,
    "  private:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${aliceDid}`,
    "    fields:",
    "    - secret_token",
    "    - account_id",
    "fields: {}",
    "",
  ].join("\n");

  const aliceYamlPath = join(aliceDir, "tn.yaml");
  writeFileSync(aliceYamlPath, yaml, "utf8");

  return {
    aliceYamlPath,
    aliceKeystorePath: aliceKeys,
    aliceLogPath: join(aliceLogs, "tn.ndjson"),
    bobKeystorePath,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

test("alice/s09_multi_recipient — Bob decrypts default group; CANNOT decrypt private group", () => {
  const ceremony = makeS09Ceremony();
  try {
    const rt = NodeRuntime.init(ceremony.aliceYamlPath);

    // Alice emits 5 events. Each event has fields routed to:
    //   - `default` group: shared_field (no explicit route → falls to default)
    //   - `private` group: secret_token, account_id
    for (let i = 0; i < 5; i++) {
      rt.emit("info", "user.action", {
        shared_field: `public-${i}`,
        secret_token: `tok-${i}`,
        account_id: `acct-${i}`,
      });
    }

    // Alice mints a kit for Bob scoped to `default` ONLY.
    const bobDefaultKitPath = join(ceremony.bobKeystorePath, "default.btn.mykit");
    rt.addRecipient("default", bobDefaultKitPath, BOB_DID);

    // Note: Alice does NOT mint a kit for Bob in the `private` group.
    // ceremony.bobKeystorePath has ONLY `default.btn.mykit`.

    const aliceLogPath = ceremony.aliceLogPath;

    // 1. Bob reads with his `default` kit → plaintext decrypts cleanly.
    const defaultEntries = Array.from(
      readAsRecipient(aliceLogPath, ceremony.bobKeystorePath, {
        group: "default",
        verifySignatures: true,
      }),
    ).filter((e) => e.envelope["event_type"] === "user.action");

    assert.equal(
      defaultEntries.length,
      5,
      `expected 5 user.action entries for Bob/default, got ${defaultEntries.length}`,
    );

    for (let i = 0; i < defaultEntries.length; i++) {
      const e = defaultEntries[i]!;
      const pt = e.plaintext["default"] as Record<string, unknown> | undefined;
      assert.ok(
        pt !== undefined,
        `plaintext["default"] missing at index ${i}`,
      );
      assert.ok(
        !("$no_read_key" in (pt ?? {})),
        `Bob got $no_read_key on default group at index ${i} — expected decryption to succeed`,
      );
      assert.equal(
        pt?.["shared_field"],
        `public-${i}`,
        `shared_field mismatch at index ${i}: expected "public-${i}", got ${JSON.stringify(pt?.["shared_field"])}`,
      );
      assert.ok(
        e.valid.signature,
        `signature verification failed for default-group entry at index ${i}`,
      );
    }

    // 2. Bob tries to read `private` group → throws because he has no
    //    private.btn.mykit in his keystore directory.
    assert.throws(
      () => {
        const gen = readAsRecipient(aliceLogPath, ceremony.bobKeystorePath, {
          group: "private",
          verifySignatures: false,
        });
        // Consume the generator to trigger the error.
        Array.from(gen);
      },
      (err: unknown) => {
        assert.ok(err instanceof Error, "expected an Error to be thrown");
        assert.ok(
          err.message.toLowerCase().includes("no recipient kit"),
          `expected "no recipient kit" in error message, got: ${err.message}`,
        );
        return true;
      },
      "readAsRecipient should throw 'no recipient kit' when Bob has no private group kit",
    );
  } finally {
    ceremony.cleanup();
  }
});
