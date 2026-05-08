// Tn acceptance test — parity target for SDK matrix.
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

import { canonicalize, DeviceKey, primitives } from "../src/index.js";
import { Entry, VerifyError } from "../src/Entry.js";
import { Tn } from "../src/tn.js";
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

  const yaml = `ceremony:\n  id: client_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${dk.did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\n- group\n- leaf_index\n- recipient_did\n- kit_sha256\n- cipher\n- vault_did\n- project_id\n- linked_at\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - did: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function readEnvs(tn: Tn): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const env of tn.read({ raw: true, allRuns: true })) {
    out.push(env as Record<string, unknown>);
  }
  return out;
}

function readEntries(tn: Tn): Entry[] {
  const out: Entry[] = [];
  for (const e of tn.read({ allRuns: true })) {
    if (e instanceof Entry) out.push(e);
  }
  return out;
}

test("log-level wrappers emit with expected level", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);

    const cases: Array<{
      expectedLevel: string;
      eventType: string;
      call: (c: Tn) => void;
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
      call(tn);
      const contents = readFileSync(tn.logPath, "utf8");
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

    await tn.close();
  } finally {
    cleanup();
  }
});

test("read yields an entry the client just emitted", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    // log/info/warning/error/debug return EmitReceipt.
    const receipt = tn.emit("info", "order.created", { amount: 99, status: "paid" });
    assert.match(receipt.rowHash, /^sha256:[0-9a-f]{64}$/);

    const entries = readEntries(tn);
    const biz = entries.find((e) => e.event_type === "order.created");
    assert.ok(biz, "just-emitted entry must be readable");
    assert.equal(biz!.fields["amount"], 99);

    // verify=true must succeed on a clean log.
    let n = 0;
    for (const _ of tn.read({ verify: true, allRuns: true })) {
      n += 1;
      void _;
    }
    assert.ok(n >= 1);

    await tn.close();
  } finally {
    cleanup();
  }
});

test("admin verbs round-trip a recipient", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const dir = join(tmpdir(), `tn-client-kit-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    try {
      const kitPath = join(dir, "default.btn.mykit");
      const res = await tn.admin.addRecipient("default", { outKitPath: kitPath, recipientDid: "did:key:z6MkFakeReader" });
      const leaf = res.leafIndex;
      assert.equal(typeof leaf, "number");
      assert.ok(leaf >= 0, "leaf index should be non-negative");

      await tn.admin.revokeRecipient("default", { leafIndex: leaf });
      assert.equal(tn.admin.revokedCount("default"), 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    await tn.close();
  } finally {
    cleanup();
  }
});

test("vault.link emits a signed tn.vault.linked event", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const receipt = await tn.vault.link("did:key:z6MkVault", "proj-alpha");
    assert.match(receipt.rowHash, /^sha256:[0-9a-f]{64}$/);

    const entries = readEntries(tn);
    const linked = entries.find((e) => e.event_type === "tn.vault.linked");
    assert.ok(linked, "tn.vault.linked event must be present");

    await tn.close();
  } finally {
    cleanup();
  }
});

// ----- B3: read() edge cases ----------------------------------------------

test("read yields nothing on an empty log", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    writeFileSync(tn.logPath, "");
    const entries = readEnvs(tn);
    assert.equal(entries.length, 0, "empty log must yield zero entries");
    await tn.close();
  } finally {
    cleanup();
  }
});

test("read skips blank lines without throwing", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    tn.info("blankline.test", { k: 1 });
    writeFileSync(tn.logPath, "\n\n\n", { flag: "a" });
    const entries = readEnvs(tn);
    const blank = entries.find((e) => e["event_type"] === "blankline.test");
    assert.ok(blank, "emitted entry must still be readable past blank lines");
    await tn.close();
  } finally {
    cleanup();
  }
});

test("read surfaces parse errors on a corrupted line", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    tn.info("corruption.before", { k: 1 });
    writeFileSync(tn.logPath, "not-json-at-all\n", { flag: "a" });
    // Reading must throw so callers cannot silently skip tampered content.
    assert.throws(() => readEnvs(tn), /parse|JSON|unexpected|invalid/i);
    await tn.close();
  } finally {
    cleanup();
  }
});

// ----- B3: primitives byte-compare ----------------------------------------

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

test("recipients yields active entry after add, removes it after revoke", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      const kit1 = join(dir, "default.btn.mykit");
      const kit2 = join(dir, "default_bob.btn.mykit");
      const resAlice = await tn.admin.addRecipient("default", { outKitPath: kit1, recipientDid: "did:key:zAlice" });
      const resBob = await tn.admin.addRecipient("default", { outKitPath: kit2, recipientDid: "did:key:zBob" });
      const aliceLeaf = resAlice.leafIndex;
      const bobLeaf = resBob.leafIndex;

      const active = tn.admin.recipients("default");
      assert.equal(active.length, 2, "two minted recipients should be active");
      const sortedDids = active.map((r) => r.recipientDid).sort();
      assert.deepEqual(sortedDids, ["did:key:zAlice", "did:key:zBob"]);
      for (const r of active) {
        assert.equal(r.revoked, false);
        assert.equal(r.revokedAt, null);
        assert.match(r.kitSha256!, /^sha256:[0-9a-f]{64}$/);
        assert.ok(r.mintedAt, "mintedAt must propagate from envelope timestamp");
      }

      await tn.admin.revokeRecipient("default", { leafIndex: aliceLeaf });
      const afterRevoke = tn.admin.recipients("default");
      assert.equal(afterRevoke.length, 1, "revoked recipient must drop from active list");
      assert.equal(afterRevoke[0]!.leafIndex, bobLeaf);
      assert.equal(afterRevoke[0]!.revoked, false);

      const all = tn.admin.recipients("default", { includeRevoked: true });
      assert.equal(all.length, 2, "includeRevoked must surface the revoked entry");
      const revoked = all.find((r) => r.leafIndex === aliceLeaf);
      assert.ok(revoked, "alice must be present with includeRevoked");
      assert.equal(revoked!.revoked, true);
      assert.ok(revoked!.revokedAt, "revokedAt must be set");

      const sorted = all.slice().sort((a, b) => a.leafIndex - b.leafIndex);
      assert.equal(sorted[0]!.leafIndex, aliceLeaf, "alice has lower leaf index");
      assert.equal(sorted[1]!.leafIndex, bobLeaf, "bob has higher leaf index");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    await tn.close();
  } finally {
    cleanup();
  }
});

test("recipients filters by group name", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      await tn.admin.addRecipient("default", { outKitPath: join(dir, "default.btn.mykit"), recipientDid: "did:key:zX" });
      const others = tn.admin.recipients("does-not-exist");
      assert.deepEqual(others, [], "unknown group must return empty list");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    await tn.close();
  } finally {
    cleanup();
  }
});

test("admin.state rolls up ceremony, recipients, and vault links", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      const kit = join(dir, "default.btn.mykit");
      const res = await tn.admin.addRecipient("default", { outKitPath: kit, recipientDid: "did:key:zRoster" });
      const leaf = res.leafIndex;
      await tn.vault.link("did:key:zVault", "proj-42");

      const state = tn.admin.state();

      assert.ok(state.ceremony, "ceremony must be auto-derived from config");
      assert.ok(state.ceremony!.ceremonyId, "ceremony id must be set");
      assert.equal(state.ceremony!.deviceDid, tn.did);

      const rec = state.recipients.find((r) => r.leafIndex === leaf);
      assert.ok(rec, "minted recipient must appear in adminState");
      assert.equal(rec!.activeStatus, "active");
      assert.equal(rec!.recipientDid, "did:key:zRoster");
      assert.equal(rec!.group, "default");

      const link = state.vaultLinks.find((v) => v.vaultDid === "did:key:zVault");
      assert.ok(link, "vault.linked must roll up");
      assert.equal(link!.projectId, "proj-42");
      assert.equal(link!.unlinkedAt, null);

      const onlyDefault = tn.admin.state("default");
      assert.equal(onlyDefault.recipients.length, state.recipients.length);
      const otherGroup = tn.admin.state("ghost-group");
      assert.equal(otherGroup.recipients.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    await tn.close();
  } finally {
    cleanup();
  }
});

test("admin.state marks recipients revoked after revoke", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const dir = mkdtempSync(join(tmpdir(), "tn-client-kits-"));
    try {
      const kit = join(dir, "default.btn.mykit");
      const res = await tn.admin.addRecipient("default", { outKitPath: kit, recipientDid: "did:key:zRevMe" });
      const leaf = res.leafIndex;
      await tn.admin.revokeRecipient("default", { leafIndex: leaf });

      const state = tn.admin.state();
      const rec = state.recipients.find((r) => r.leafIndex === leaf);
      assert.ok(rec, "revoked recipient must still appear in adminState");
      assert.equal(rec!.activeStatus, "revoked");
      assert.ok(rec!.revokedAt, "revokedAt timestamp must propagate");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    await tn.close();
  } finally {
    cleanup();
  }
});

// ----- primitives sub-namespace -------------------------------------------

test("primitives namespace exposes canonicalize and DeviceKey alongside top-level", () => {
  const td = new TextDecoder("utf-8");
  assert.equal(td.decode(canonicalize({ a: 1 })), '{"a":1}');

  assert.equal(typeof primitives.canonicalize, "function");
  assert.equal(typeof primitives.DeviceKey.fromSeed, "function");
  assert.equal(td.decode(primitives.canonicalize({ a: 1 })), '{"a":1}');

  assert.strictEqual(primitives.canonicalize, canonicalize);
  assert.strictEqual(primitives.DeviceKey, DeviceKey);
});

// ----- emitWith / emitOverrideSign / setSigning ---------------------------

test("Tn.emitWith honors timestamp + eventId overrides", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const ts = "2026-04-24T12:00:00.000000+00:00";
    const eid = "deadbeef-dead-beef-dead-beefdeadbeef";

    const receipt = tn.emitWith("info", "evt.deterministic", { k: 1 }, {
      timestamp: ts,
      eventId: eid,
    });
    assert.equal(receipt.eventId, eid);

    const envs = readEnvs(tn);
    const e = envs.find((x) => x["event_id"] === eid);
    assert.ok(e, "entry with overridden event_id must be readable");
    assert.equal(e!["timestamp"], ts);

    // Verify mode passes for clean entries.
    let count = 0;
    for (const _ of tn.read({ verify: true, allRuns: true })) {
      count += 1;
      void _;
    }
    assert.ok(count >= 1);

    await tn.close();
  } finally {
    cleanup();
  }
});

test("Tn.emitOverrideSign(false) writes an unsigned entry", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    tn.emitOverrideSign("info", "evt.unsigned", { n: 1 }, false);

    const envs = readEnvs(tn);
    const e = envs.find((x) => x["event_type"] === "evt.unsigned");
    assert.ok(e, "unsigned entry must still be readable");
    assert.equal(e!["signature"], "", "signature field must be empty");

    // verify=true should reject the unsigned row.
    assert.throws(
      () => {
        for (const _ of tn.read({ verify: true, allRuns: true })) {
          void _;
        }
      },
      (err: unknown) => err instanceof VerifyError,
    );

    await tn.close();
  } finally {
    cleanup();
  }
});

test("Tn.setSigning(false) makes subsequent emits unsigned", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    try {
      Tn.setSigning(false);
      tn.info("evt.session.skip", { n: 1 });
    } finally {
      Tn.setSigning(null);
    }
    tn.info("evt.session.signed", { n: 2 });

    const envs = readEnvs(tn);
    const skipped = envs.find((x) => x["event_type"] === "evt.session.skip");
    const signed = envs.find((x) => x["event_type"] === "evt.session.signed");
    assert.ok(skipped && signed, "both entries must be readable");
    assert.equal(skipped!["signature"], "");
    assert.notEqual(signed!["signature"], "");

    await tn.close();
  } finally {
    cleanup();
  }
});

test("Tn.emitOverrideSign per-call wins over session-level setSigning", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    try {
      Tn.setSigning(false);
      tn.emitOverrideSign("info", "evt.percall.win", { n: 1 }, true);
    } finally {
      Tn.setSigning(null);
    }

    const envs = readEnvs(tn);
    const e = envs.find((x) => x["event_type"] === "evt.percall.win");
    assert.ok(e, "entry must be readable");
    assert.notEqual(e!["signature"], "");

    await tn.close();
  } finally {
    cleanup();
  }
});

// ----- B3: log-level wrappers produce valid-signed entries end to end ------

test("every log-level wrapper produces a signature-valid readable entry", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    tn.log("evt.bare", { k: 1 });
    tn.debug("evt.dbg", { k: 2 });
    tn.info("evt.inf", { k: 3 });
    tn.warning("evt.warn", { k: 4 });
    tn.error("evt.err", { k: 5 });

    const entries = readEntries(tn);
    const wanted = ["evt.bare", "evt.dbg", "evt.inf", "evt.warn", "evt.err"];
    for (const et of wanted) {
      const e = entries.find((x) => x.event_type === et);
      assert.ok(e, `entry for ${et} must be readable`);
    }

    // verify=true should succeed across the whole batch.
    let count = 0;
    for (const _ of tn.read({ verify: true, allRuns: true })) {
      count += 1;
      void _;
    }
    assert.ok(count >= wanted.length);

    await tn.close();
  } finally {
    cleanup();
  }
});

// ----- B4: positional `message` ergonomic ---------------------------------

test("log/info/warning/error/debug accept a positional message string", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);

    tn.info("evt.msg.only", "name = hi");
    tn.info("evt.msg.plus", "starting", { port: 8080 });
    tn.info("evt.kw.only", { foo: "bar" });
    const ret = tn.info("evt.void", "x");
    assert.ok(ret && typeof ret.rowHash === "string", "Tn log-level wrappers return EmitReceipt");

    const entries = readEntries(tn);
    const find = (et: string) => entries.find((x) => x.event_type === et)!;

    // The writer puts the positional message into the encrypted
    // plaintext payload under a `message` key for confidentiality, but
    // `Entry.fromRaw` hoists it out into the typed `entry.message`
    // slot so callers don't have to reach into `entry.fields`.
    // Mirrors Python's behavior.
    const msgOnly = find("evt.msg.only");
    assert.equal(msgOnly.message, "name = hi");
    assert.ok(!("message" in msgOnly.fields), "message should not leak into fields");

    const msgPlus = find("evt.msg.plus");
    assert.equal(msgPlus.message, "starting");
    assert.equal(msgPlus.fields["port"], 8080);
    assert.ok(!("message" in msgPlus.fields), "message should not leak into fields");

    const kwOnly = find("evt.kw.only");
    assert.equal(kwOnly.fields["foo"], "bar");
    assert.equal(kwOnly.message, null, "object-form must NOT inject a message");

    await tn.close();
  } finally {
    cleanup();
  }
});
