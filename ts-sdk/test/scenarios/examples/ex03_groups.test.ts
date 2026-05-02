// Example ex03 — PII / internal group separation.
//
// Python original: python/examples/ex03_groups.py
//
// Story: Jamie accidentally emails a log to a partner. With group routing,
// the partner sees timestamps and event types but PII (email, IP) and
// internal fields (request_id, debug_trace) are opaque ciphertext without
// the matching reader kit.
//
// What this tests:
//   1. yaml-driven ceremony with three groups: default, pii, internal.
//   2. page.view event spans all three groups.
//   3. Publisher (holds all kits) decrypts all groups cleanly.
//   4. "Partner" (holds only default.btn.mykit) decrypts default group but
//      gets "no recipient kit" error when attempting pii or internal groups —
//      proving group-scoped access control works end-to-end.

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

import { DeviceKey, NodeRuntime, readAsRecipient } from "../../../src/index.js";
import { BtnPublisher } from "../../../src/raw.js";

const GROUP_NAMES = ["default", "pii", "internal"];

function makeEx03Ceremony(): {
  yamlPath: string;
  logPath: string;
  keystorePath: string;
  partnerKeystorePath: string;
  cleanup: () => void;
} {
  const root = mkdtempSync(join(tmpdir(), "tn-ex03-"));
  const keys = join(root, ".tn/keys");
  const logs = join(root, ".tn/logs");
  const partnerKeystorePath = join(root, "partner-keystore");

  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });
  mkdirSync(partnerKeystorePath, { recursive: true });

  // Device key.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 19;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");

  // Index master.
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i++) indexMaster[i] = (i * 13 + 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  // BtnPublisher per group.
  for (let g = 0; g < GROUP_NAMES.length; g++) {
    const gname = GROUP_NAMES[g]!;
    const btnSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) btnSeed[i] = (i * 7 + 11 + g * 19) & 0xff;
    const pub = new BtnPublisher(btnSeed);
    const kit = pub.mint();
    writeFileSync(join(keys, `${gname}.btn.state`), Buffer.from(pub.toBytes()));
    writeFileSync(join(keys, `${gname}.btn.mykit`), Buffer.from(kit));
  }

  const did = dk.did;
  const yaml = [
    "ceremony:",
    "  id: ex03_groups",
    "  mode: local",
    "  cipher: btn",
    "logs:",
    "  path: ./.tn/logs/tn.ndjson",
    "keystore:",
    "  path: ./.tn/keys",
    "me:",
    `  did: ${did}`,
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
    `    - did: ${did}`,
    "  pii:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${did}`,
    "    fields:",
    "    - email",
    "    - ip",
    "    - user_agent",
    "  internal:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${did}`,
    "    fields:",
    "    - request_id",
    "    - debug_trace",
    "fields: {}",
    "",
  ].join("\n");

  const yamlPath = join(root, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    logPath: join(logs, "tn.ndjson"),
    keystorePath: keys,
    partnerKeystorePath,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

test("ex03/publisher-reads-all-groups — page.view event decrypts pii, internal, and default", () => {
  const c = makeEx03Ceremony();
  try {
    const rt = NodeRuntime.init(c.yamlPath);

    // Mirror Python ex03: one page.view event spanning all three groups.
    rt.emit("info", "page.view", {
      path: "/checkout",           // → default (unmapped fields fall to default)
      referrer: "newsletter",      // → default
      email: "alice@example.com",  // → pii
      ip: "10.0.0.17",             // → pii
      user_agent: "Mozilla/5.0",   // → pii
      request_id: "req_abc123",    // → internal
      debug_trace: "cache_miss",   // → internal
    });

    const entries = Array.from(rt.read()).filter(
      (e) => e.envelope["event_type"] === "page.view",
    );

    assert.equal(entries.length, 1, `expected 1 page.view entry, got ${entries.length}`);

    const e = entries[0]!;

    // Verify all integrity checks pass.
    assert.ok(e.valid.signature, "signature verification failed");
    assert.ok(e.valid.chain, "chain continuity failed");
    assert.ok(e.valid.rowHash, "row_hash recomputation failed");

    // Publisher sees all groups cleanly.
    const def = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
    const pii = (e.plaintext["pii"] ?? {}) as Record<string, unknown>;
    const internal = (e.plaintext["internal"] ?? {}) as Record<string, unknown>;

    // default group: unmapped fields
    assert.equal(def["path"], "/checkout", `default.path mismatch: ${JSON.stringify(def["path"])}`);
    assert.equal(def["referrer"], "newsletter", `default.referrer mismatch: ${JSON.stringify(def["referrer"])}`);

    // pii group
    assert.equal(pii["email"], "alice@example.com", `pii.email mismatch: ${JSON.stringify(pii["email"])}`);
    assert.equal(pii["ip"], "10.0.0.17", `pii.ip mismatch: ${JSON.stringify(pii["ip"])}`);
    assert.equal(pii["user_agent"], "Mozilla/5.0", `pii.user_agent mismatch: ${JSON.stringify(pii["user_agent"])}`);

    // internal group
    assert.equal(internal["request_id"], "req_abc123", `internal.request_id mismatch`);
    assert.equal(internal["debug_trace"], "cache_miss", `internal.debug_trace mismatch`);

    // Verify PII fields do NOT appear in default group.
    assert.ok(!("email" in def), "email should NOT appear in default group");
    assert.ok(!("ip" in def), "ip should NOT appear in default group");
    assert.ok(!("request_id" in def), "request_id should NOT appear in default group");
  } finally {
    c.cleanup();
  }
});

test("ex03/partner-reads-default-only — partner holds only default kit, cannot access pii or internal", () => {
  const c = makeEx03Ceremony();
  try {
    const rt = NodeRuntime.init(c.yamlPath);

    // Emit the same page.view event.
    rt.emit("info", "page.view", {
      path: "/checkout",
      referrer: "newsletter",
      email: "alice@example.com",
      ip: "10.0.0.17",
      user_agent: "Mozilla/5.0",
      request_id: "req_abc123",
      debug_trace: "cache_miss",
    });

    // Partner only gets a copy of the `default` kit.
    const partnerKitPath = join(c.partnerKeystorePath, "default.btn.mykit");
    rt.addRecipient("default", partnerKitPath, "did:key:zPartnerPartnerPartner");

    // Partner can read `default` group.
    const defaultEntries = Array.from(
      readAsRecipient(c.logPath, c.partnerKeystorePath, {
        group: "default",
        verifySignatures: true,
      }),
    ).filter((e) => e.envelope["event_type"] === "page.view");

    assert.equal(
      defaultEntries.length,
      1,
      `expected 1 page.view entry for partner/default, got ${defaultEntries.length}`,
    );

    const defPt = defaultEntries[0]!.plaintext["default"] as Record<string, unknown> | undefined;
    assert.ok(defPt !== undefined, "partner should have plaintext['default']");
    assert.ok(!("$no_read_key" in (defPt ?? {})), "partner should decrypt default group successfully");
    assert.equal(defPt?.["path"], "/checkout", `partner default.path mismatch`);
    assert.ok(!("email" in (defPt ?? {})), "email should NOT be in default group plaintext");

    // Partner CANNOT read `pii` group — no pii.btn.mykit in their keystore.
    assert.throws(
      () => {
        Array.from(
          readAsRecipient(c.logPath, c.partnerKeystorePath, {
            group: "pii",
            verifySignatures: false,
          }),
        );
      },
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(
          err.message.toLowerCase().includes("no recipient kit"),
          `expected "no recipient kit" error for pii group, got: ${err.message}`,
        );
        return true;
      },
      "partner should get 'no recipient kit' when accessing pii group",
    );

    // Partner CANNOT read `internal` group either.
    assert.throws(
      () => {
        Array.from(
          readAsRecipient(c.logPath, c.partnerKeystorePath, {
            group: "internal",
            verifySignatures: false,
          }),
        );
      },
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(
          err.message.toLowerCase().includes("no recipient kit"),
          `expected "no recipient kit" error for internal group, got: ${err.message}`,
        );
        return true;
      },
      "partner should get 'no recipient kit' when accessing internal group",
    );
  } finally {
    c.cleanup();
  }
});
