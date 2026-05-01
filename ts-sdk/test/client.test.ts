// TNClient acceptance test — parity target for SDK matrix.
//
// Mirrors tn-protocol/crypto/tn-core/tests/runtime_emit.rs::
//   log_level_wrappers_emit_with_expected_level
// and python/tests/test_logger.py's level-wrapper assertions.

import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { canonicalize, DeviceKey, primitives, TNClient } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";

function makeCeremony(): { yamlPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-client-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = i + 11;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 13) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  const yaml = `ceremony:\n  id: client_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${dk.did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - did: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("TNClient log-level wrappers emit with expected level", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);

    const cases: Array<{
      expectedLevel: string;
      eventType: string;
      call: (c: TNClient) => void;
    }> = [
      { expectedLevel: "", eventType: "evt.bare", call: (c) => void c.log("evt.bare", { n: 1 }) },
      {
        expectedLevel: "debug",
        eventType: "evt.debug",
        call: (c) => void c.debug("evt.debug", { n: 1 }),
      },
      {
        expectedLevel: "info",
        eventType: "evt.info",
        call: (c) => void c.info("evt.info", { n: 1 }),
      },
      {
        expectedLevel: "warning",
        eventType: "evt.warning",
        call: (c) => void c.warning("evt.warning", { n: 1 }),
      },
      {
        expectedLevel: "error",
        eventType: "evt.error",
        call: (c) => void c.error("evt.error", { n: 1 }),
      },
    ];

    for (const { expectedLevel, eventType, call } of cases) {
      call(client);
      const contents = readFileSync(client.logPath, "utf8");
      const line = contents
        .split(/\r?\n/)
        .reverse()
        .find((l) => l.includes(`"event_type":"${eventType}"`));
      assert.ok(line, `emitted line for ${eventType} should be present`);
      const env = JSON.parse(line!) as Record<string, unknown>;
      assert.equal(
        env["level"],
        expectedLevel,
        `wrapper for ${eventType} set wrong level`,
      );
    }

    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.read yields an entry the client just emitted", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    // log/info/warning/error/debug return void (parity with Python).
    // Use `emit(level, ...)` when a receipt is needed.
    const receipt = client.emit("info", "order.created", { amount: 99, status: "paid" });
    assert.match(receipt.rowHash, /^sha256:[0-9a-f]{64}$/);

    const entries = Array.from(client.read({ raw: true }));
    const biz = entries.find((e) => e.envelope["event_type"] === "order.created");
    assert.ok(biz, "just-emitted entry must be readable");
    assert.equal(biz!.plaintext["default"]!["amount"], 99);
    assert.equal(biz!.valid.signature, true);
    assert.equal(biz!.valid.rowHash, true);
    assert.equal(biz!.valid.chain, true);

    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient admin verbs round-trip a recipient", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const dir = join(tmpdir(), `tn-client-kit-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    try {
      const kitPath = join(dir, "default.btn.mykit");
      const leaf = client.adminAddRecipient("default", kitPath, "did:key:z6MkFakeReader");
      assert.equal(typeof leaf, "number");
      assert.ok(leaf >= 0, "leaf index should be non-negative");

      client.adminRevokeRecipient("default", leaf);
      assert.equal(client.adminRevokedCount("default"), 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.vaultLink emits a signed tn.vault.linked event", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const receipt = client.vaultLink("did:key:z6MkVault", "proj-alpha");
    assert.match(receipt.rowHash, /^sha256:[0-9a-f]{64}$/);

    const entries = Array.from(client.read({ raw: true }));
    const linked = entries.find((e) => e.envelope["event_type"] === "tn.vault.linked");
    assert.ok(linked, "tn.vault.linked event must be present");

    client.close();
  } finally {
    cleanup();
  }
});

// ----- B3: read() edge cases ----------------------------------------------

test("TNClient.read yields nothing on an empty log", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    // Overwrite the log file with empty bytes immediately after init.
    writeFileSync(client.logPath, "");
    const entries = Array.from(client.read({ raw: true }));
    assert.equal(entries.length, 0, "empty log must yield zero entries");
    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.read skips blank lines without throwing", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    client.info("blankline.test", { k: 1 });
    // Append some blank lines; reader must tolerate them.
    writeFileSync(client.logPath, "\n\n\n", { flag: "a" });
    const entries = Array.from(client.read({ raw: true }));
    const blank = entries.find((e) => e.envelope["event_type"] === "blankline.test");
    assert.ok(blank, "emitted entry must still be readable past blank lines");
    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.read surfaces parse errors on a corrupted line", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    client.info("corruption.before", { k: 1 });
    writeFileSync(client.logPath, "not-json-at-all\n", { flag: "a" });
    // Reading through the corrupted line must throw so callers cannot silently
    // skip tampered content. Matches Python `tn.read()` strict-by-default behavior.
    assert.throws(() => Array.from(client.read({ raw: true })), /parse|JSON|unexpected/i);
    client.close();
  } finally {
    cleanup();
  }
});

// ----- B3: primitives byte-compare against Python canonical ----------------
//
// The TS SDK and Python SDK must produce byte-identical canonical
// serialization; any drift silently breaks row_hash + index_token parity.
// Golden vectors here match python/tests/test_canonical.py assertions.

test("canonicalize matches Python canonical bytes for primitives", () => {
  const td = new TextDecoder("utf-8");
  assert.equal(
    td.decode(canonicalize({ n: 1, s: "hello", b: true, nil: null })),
    '{"b":true,"n":1,"nil":null,"s":"hello"}',
  );
  assert.equal(td.decode(canonicalize([3, 1, 2])), "[3,1,2]");
  assert.equal(
    td.decode(canonicalize({ z: { b: 2, a: 1 }, a: { y: 1, x: 2 } })),
    '{"a":{"x":2,"y":1},"z":{"a":1,"b":2}}',
  );
});

test("canonicalize is insertion-order independent", () => {
  const fwd = canonicalize({ a: 1, b: 2, c: 3 });
  const rev = canonicalize({ c: 3, b: 2, a: 1 });
  assert.deepEqual(fwd, rev);
});

test("canonicalize rejects NaN/inf floats", () => {
  assert.throws(() => canonicalize(Number.NaN), /NaN|finite|invalid/i);
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY), /inf|finite|invalid/i);
  assert.throws(() => canonicalize(Number.NEGATIVE_INFINITY), /inf|finite|invalid/i);
});

// ----- A leftovers: recipients() + adminState() ---------------------------

test("TNClient.recipients yields active entry after add, removes it after revoke", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      const kit1 = join(dir, "default.btn.mykit");
      const kit2 = join(dir, "default_bob.btn.mykit");
      const aliceLeaf = client.adminAddRecipient("default", kit1, "did:key:zAlice");
      const bobLeaf = client.adminAddRecipient("default", kit2, "did:key:zBob");

      const active = client.recipients("default");
      assert.equal(active.length, 2, "two minted recipients should be active");
      const sortedDids = active.map((r) => r.recipientDid).sort();
      assert.deepEqual(sortedDids, ["did:key:zAlice", "did:key:zBob"]);
      for (const r of active) {
        assert.equal(r.revoked, false);
        assert.equal(r.revokedAt, null);
        assert.match(r.kitSha256!, /^sha256:[0-9a-f]{64}$/);
        assert.ok(r.mintedAt, "mintedAt must propagate from envelope timestamp");
      }

      client.adminRevokeRecipient("default", aliceLeaf);
      const afterRevoke = client.recipients("default");
      assert.equal(afterRevoke.length, 1, "revoked recipient must drop from active list");
      assert.equal(afterRevoke[0]!.leafIndex, bobLeaf);
      assert.equal(afterRevoke[0]!.revoked, false);

      const all = client.recipients("default", { includeRevoked: true });
      assert.equal(all.length, 2, "includeRevoked must surface the revoked entry");
      const revoked = all.find((r) => r.leafIndex === aliceLeaf);
      assert.ok(revoked, "alice must be present with includeRevoked");
      assert.equal(revoked!.revoked, true);
      assert.ok(revoked!.revokedAt, "revokedAt must be set");

      // Sort order: active leaves first (ascending), then revoked (ascending).
      assert.equal(all[0]!.leafIndex, bobLeaf);
      assert.equal(all[1]!.leafIndex, aliceLeaf);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.recipients filters by group name", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      client.adminAddRecipient("default", join(dir, "default.btn.mykit"), "did:key:zX");
      const others = client.recipients("does-not-exist");
      assert.deepEqual(others, [], "unknown group must return empty list");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.adminState rolls up ceremony, recipients, and vault links", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      const kit = join(dir, "default.btn.mykit");
      const leaf = client.adminAddRecipient("default", kit, "did:key:zRoster");
      client.vaultLink("did:key:zVault", "proj-42");

      const state = client.adminState();

      assert.ok(state.ceremony, "ceremony fallback must populate from config");
      assert.equal(state.ceremony!.cipher, "btn");
      assert.equal(state.ceremony!.deviceDid, client.did);

      const rec = state.recipients.find((r) => r.leafIndex === leaf);
      assert.ok(rec, "minted recipient must appear in adminState");
      assert.equal(rec!.activeStatus, "active");
      assert.equal(rec!.recipientDid, "did:key:zRoster");
      assert.equal(rec!.group, "default");

      const link = state.vaultLinks.find((v) => v.vaultDid === "did:key:zVault");
      assert.ok(link, "vault.linked must roll up");
      assert.equal(link!.projectId, "proj-42");
      assert.equal(link!.unlinkedAt, null);

      // Filter by group: ceremony stays, recipients narrow.
      const onlyDefault = client.adminState("default");
      assert.equal(onlyDefault.recipients.length, state.recipients.length);
      const otherGroup = client.adminState("ghost-group");
      assert.equal(otherGroup.recipients.length, 0);
      assert.ok(otherGroup.ceremony, "ceremony record is not filtered by group");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.adminState marks recipients revoked after revoke", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      const kit = join(dir, "default.btn.mykit");
      const leaf = client.adminAddRecipient("default", kit, "did:key:zRevMe");
      client.adminRevokeRecipient("default", leaf);

      const state = client.adminState();
      const rec = state.recipients.find((r) => r.leafIndex === leaf);
      assert.ok(rec, "revoked recipient must still appear in adminState");
      assert.equal(rec!.activeStatus, "revoked");
      assert.ok(rec!.revokedAt, "revokedAt timestamp must propagate");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    client.close();
  } finally {
    cleanup();
  }
});

// ----- primitives sub-namespace -------------------------------------------

test("primitives namespace exposes canonicalize and DeviceKey alongside top-level", () => {
  // Top-level re-export must keep working (back-compat).
  const td = new TextDecoder("utf-8");
  assert.equal(td.decode(canonicalize({ a: 1 })), '{"a":1}');

  // Same surface must be reachable via primitives.* — the matrix target.
  assert.equal(typeof primitives.canonicalize, "function");
  assert.equal(typeof primitives.DeviceKey.fromSeed, "function");
  assert.equal(td.decode(primitives.canonicalize({ a: 1 })), '{"a":1}');

  // Sanity: top-level and namespaced refs are the same function reference,
  // so behavior cannot drift between the two paths.
  assert.strictEqual(primitives.canonicalize, canonicalize);
  assert.strictEqual(primitives.DeviceKey, DeviceKey);
});

// ----- emitWith / emitOverrideSign / setSigning ---------------------------

test("TNClient.emitWith honors timestamp + eventId overrides", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const ts = "2026-04-24T12:00:00.000000+00:00";
    const eid = "deadbeef-dead-beef-dead-beefdeadbeef";

    const receipt = client.emitWith("info", "evt.deterministic", { k: 1 }, {
      timestamp: ts,
      eventId: eid,
    });
    assert.equal(receipt.eventId, eid);

    const entries = Array.from(client.read({ raw: true }));
    const e = entries.find((x) => x.envelope["event_id"] === eid);
    assert.ok(e, "entry with overridden event_id must be readable");
    assert.equal(e!.envelope["timestamp"], ts);
    assert.equal(e!.valid.signature, true, "row_hash must be signature-valid");

    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.emitOverrideSign(false) writes an unsigned entry", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    client.emitOverrideSign("info", "evt.unsigned", { n: 1 }, false);

    const entries = Array.from(client.read({ raw: true }));
    const e = entries.find((x) => x.envelope["event_type"] === "evt.unsigned");
    assert.ok(e, "unsigned entry must still be readable");
    assert.equal(e!.envelope["signature"], "", "signature field must be empty");
    assert.equal(e!.valid.signature, false);
    assert.equal(e!.valid.rowHash, true);
    assert.equal(e!.valid.chain, true);

    client.close();
  } finally {
    cleanup();
  }
});

test("TNClient.setSigning(false) makes subsequent emits unsigned", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    try {
      TNClient.setSigning(false);
      client.info("evt.session.skip", { n: 1 });
    } finally {
      TNClient.setSigning(null);
    }
    client.info("evt.session.signed", { n: 2 });

    const entries = Array.from(client.read({ raw: true }));
    const skipped = entries.find((x) => x.envelope["event_type"] === "evt.session.skip");
    const signed = entries.find((x) => x.envelope["event_type"] === "evt.session.signed");
    assert.ok(skipped && signed, "both entries must be readable");
    assert.equal(skipped!.envelope["signature"], "");
    assert.notEqual(signed!.envelope["signature"], "");
    assert.equal(signed!.valid.signature, true);

    client.close();
  } finally {
    cleanup();
  }
});

test("emitOverrideSign per-call wins over session-level setSigning", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    try {
      TNClient.setSigning(false);
      client.emitOverrideSign("info", "evt.percall.win", { n: 1 }, true);
    } finally {
      TNClient.setSigning(null);
    }

    const entries = Array.from(client.read({ raw: true }));
    const e = entries.find((x) => x.envelope["event_type"] === "evt.percall.win");
    assert.ok(e, "entry must be readable");
    assert.notEqual(e!.envelope["signature"], "");
    assert.equal(e!.valid.signature, true);

    client.close();
  } finally {
    cleanup();
  }
});

// ----- B3: log-level wrappers produce valid-signed entries end to end ------

test("every log-level wrapper produces a signature-valid readable entry", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    client.log("evt.bare", { k: 1 });
    client.debug("evt.dbg", { k: 2 });
    client.info("evt.inf", { k: 3 });
    client.warning("evt.warn", { k: 4 });
    client.error("evt.err", { k: 5 });

    const entries = Array.from(client.read({ raw: true }));
    const wanted = ["evt.bare", "evt.dbg", "evt.inf", "evt.warn", "evt.err"];
    for (const et of wanted) {
      const e = entries.find((x) => x.envelope["event_type"] === et);
      assert.ok(e, `entry for ${et} must be readable`);
      assert.equal(e!.valid.signature, true, `${et} signature must verify`);
      assert.equal(e!.valid.rowHash, true, `${et} row_hash must verify`);
      assert.equal(e!.valid.chain, true, `${et} chain must verify`);
    }
    client.close();
  } finally {
    cleanup();
  }
});

// ----- B4: positional `message` ergonomic (parity with Python) ------------

test("log/info/warning/error/debug accept a positional message string", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);

    // Form 1: just a message string -> {message: <str>}
    client.info("evt.msg.only", "name = hi");
    // Form 2: message + extra fields -> {message: ..., port: 8080}
    client.info("evt.msg.plus", "starting", { port: 8080 });
    // Form 3: just an object -> fields directly (no `message` key)
    client.info("evt.kw.only", { foo: "bar" });
    // Form 4: void return type — no truthy receipt to consume.
    const ret = client.info("evt.void", "x");
    assert.equal(ret, undefined, "log-level wrappers must return void");

    const entries = Array.from(client.read({ raw: true }));
    const find = (et: string) => entries.find((x) => x.envelope["event_type"] === et)!;

    const msgOnly = find("evt.msg.only");
    assert.equal(msgOnly.plaintext["default"]!["message"], "name = hi");

    const msgPlus = find("evt.msg.plus");
    assert.equal(msgPlus.plaintext["default"]!["message"], "starting");
    assert.equal(msgPlus.plaintext["default"]!["port"], 8080);

    const kwOnly = find("evt.kw.only");
    assert.equal(kwOnly.plaintext["default"]!["foo"], "bar");
    assert.equal(
      kwOnly.plaintext["default"]!["message"],
      undefined,
      "object-form must NOT inject a message key",
    );

    client.close();
  } finally {
    cleanup();
  }
});
