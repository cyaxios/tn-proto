// Group names that collide with Object.prototype members ("toString",
// "constructor", "hasOwnProperty", ...) must behave like any other name.
// The yaml mutation helpers in NodeRuntime index parsed-yaml mappings with
// bare property access, and on a plain object `groups["toString"]` resolves
// the inherited Function when no own key exists — truthy and non-nullish —
// so `??=` / `if (!...)` guards treat the group as already present: the
// `groups.<name>` block is never written (the group silently vanishes on
// the next load) and mutations land on the shared prototype member instead
// of the document. Python has no such limit (dict keys are exact), so a
// Python-authored ceremony can legitimately carry such a group name and the
// TS side must load and route it. The sealed-object walk in src/seal.ts has
// its own own-property hardening; this file pins the runtime/persistence
// side: ensure_group -> re-init -> add_recipient -> emit/read, plus the
// config loader over a hand-written yaml.
import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";
import { parse as parseYaml } from "yaml";

import { AdminNamespace } from "../src/admin/index.js";
import { jweDecrypt, okpPrivateJwk } from "../src/core/jwe.js";
import { loadConfig } from "../src/runtime/config.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";

/** Pull group `g`'s raw ciphertext bytes from a decoded envelope. */
function groupCt(env: Record<string, unknown>, g: string): Uint8Array {
  const block = env[g] as { ciphertext?: string } | undefined;
  return new Uint8Array(Buffer.from(String(block?.ciphertext ?? ""), "base64"));
}

/** Own-property read of the `groups:` block in the on-disk yaml. */
function yamlGroups(yamlPath: string): Record<string, Record<string, unknown>> {
  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown>;
  return (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
}

test('ensureGroup("toString") persists, survives re-init, routes addRecipient + emit', async () => {
  const work = mkdtempSync(join(tmpdir(), "proto-name-"));
  const yamlPath = join(work, "tn.yaml");
  const rt = NodeRuntime.init(yamlPath, { cipher: "jwe" });
  const admin = new AdminNamespace(rt);
  await admin.ensureGroup("toString", { cipher: "jwe", fields: ["body"] });

  // The groups.toString block must land in the yaml as an OWN key.
  const persisted = yamlGroups(yamlPath);
  assert.ok(
    Object.hasOwn(persisted, "toString"),
    "groups.toString block was not persisted to the yaml",
  );
  assert.equal(persisted["toString"]!.cipher, "jwe");
  assert.deepEqual(persisted["toString"]!.fields, ["body"]);

  // ...and never as properties smeared onto the shared prototype member.
  assert.ok(
    !Object.hasOwn(Object.prototype.toString, "fields") &&
      !Object.hasOwn(Object.prototype.toString, "recipients"),
    "ensureGroup mutated Object.prototype.toString instead of the yaml doc",
  );

  // A fresh load (new process would behave the same) sees the group and its
  // cipher, so admin routing takes the jwe branch instead of defaulting to
  // btn and throwing "not a btn publisher".
  const rt2 = NodeRuntime.init(yamlPath);
  const gcfg = rt2.config.groups.get("toString");
  assert.ok(gcfg, "config.groups lost the toString group after re-init");
  assert.equal(gcfg.cipher, "jwe");

  const admin2 = new AdminNamespace(rt2);
  const bobPriv = x25519.utils.randomPrivateKey();
  const bobPub = x25519.getPublicKey(bobPriv);
  const bobJwk = okpPrivateJwk(bobPub, bobPriv);
  const bobDid = "did:key:z6MkBobProtoNameGroupTest000000000000000000";
  const added = await admin2.addRecipient("toString", {
    recipientDid: bobDid,
    publicKey: bobPub,
    unsafeUnverified: true, // raw DID-plus-key path (no enrollment proof)
  });
  assert.equal(added.cipher, "jwe");

  // addRecipient's yaml read-modify-write must keep the group an own key
  // and append the recipient there.
  const afterAdd = yamlGroups(yamlPath)["toString"];
  assert.ok(afterAdd, "addRecipient dropped the groups.toString block");
  const dids = (afterAdd.recipients as Array<Record<string, unknown>>).map(
    (r) => r.recipient_identity,
  );
  assert.ok(dids.includes(bobDid), `recipients ${JSON.stringify(dids)} missing ${bobDid}`);

  // Round-trip: `body` routes into the toString group, the rest into
  // default; publisher and the added recipient can both open it.
  await rt2.emitAsync("info", "kyc.done", { body: "sealed-for-toString", note: "ok" });
  let opened = false;
  for await (const e of rt2.readAsync()) {
    if (e.envelope["event_type"] !== "kyc.done") continue;
    assert.deepEqual(e.plaintext["toString"], { body: "sealed-for-toString" });
    assert.deepEqual(e.plaintext["default"], { note: "ok" });
    const pt = await jweDecrypt(bobJwk, groupCt(e.envelope, "toString"));
    assert.ok(pt, "added recipient could not decrypt the toString group");
    opened = true;
  }
  assert.ok(opened, "kyc.done entry not read back");

  // Rotate goes through the same yaml read-modify-write: the block must
  // stay an own key, carry the bumped epoch, and reset to self-only.
  rt2.rotateGroupJwe("toString");
  const afterRotate = yamlGroups(yamlPath)["toString"];
  assert.ok(afterRotate, "rotate dropped the groups.toString block");
  assert.equal(afterRotate.group_epoch, 1);
  const postRotateDids = (afterRotate.recipients as Array<Record<string, unknown>>).map(
    (r) => r.recipient_identity,
  );
  assert.ok(!postRotateDids.includes(bobDid), "rotate kept the revoked recipient in yaml");

  rmSync(work, { recursive: true, force: true });
});

test("loadConfig routes groups named after Object.prototype members (Python-authored yaml)", () => {
  const work = mkdtempSync(join(tmpdir(), "proto-name-cfg-"));
  const yamlPath = join(work, "tn.yaml");
  writeFileSync(
    yamlPath,
    "ceremony:\n" +
      "  id: cer-proto\n" +
      "  mode: local\n" +
      "  cipher: jwe\n" +
      "device:\n" +
      "  device_identity: did:key:zDEV\n" +
      "groups:\n" +
      "  toString:\n" +
      "    policy: private\n" +
      "    cipher: jwe\n" +
      "    fields:\n" +
      "    - body\n" +
      "  constructor:\n" +
      "    policy: private\n" +
      "    cipher: btn\n" +
      "  hasOwnProperty:\n" +
      "    policy: private\n" +
      "    cipher: hibe\n",
    "utf8",
  );
  const cfg = loadConfig(yamlPath);
  assert.equal(cfg.groups.get("toString")?.cipher, "jwe");
  assert.equal(cfg.groups.get("constructor")?.cipher, "btn");
  assert.equal(cfg.groups.get("hasOwnProperty")?.cipher, "hibe");
  assert.deepEqual(cfg.fieldToGroups.get("body"), ["toString"]);
  rmSync(work, { recursive: true, force: true });
});
