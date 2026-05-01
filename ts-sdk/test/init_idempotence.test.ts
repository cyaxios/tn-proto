// Mirror of the Python test_init_idempotence.py hardening for
// NodeRuntime.init.
//
// Three things we want:
//
// 1. Log scans walk both the main log and any PEL
//    (protocol_events_location) file(s). If someone ran a Python side
//    of this ceremony with admin events split out, the TS reader must
//    see them too, otherwise reconciliation will re-emit duplicate
//    tn.recipient.added rows on every init.
//
// 2. NodeRuntime.init reconciles yaml-declared recipients against
//    attested events. Adding a recipient DID to tn.yaml by hand
//    should cause the next init to mint a kit for that DID, write it
//    under <yamlDir>/.tn/outbox/, and emit tn.recipient.added. Third init
//    is a no-op.
//
// 3. NodeRuntime doesn't auto-create keys, so there is no clobber
//    path to guard against (init throws if the keystore is missing
//    parts). We just pin that expectation so a future refactor that
//    adds auto-create also adds a clobber guard.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
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

import { DeviceKey, NodeRuntime, scanAttestedGroups } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";

interface Ceremony {
  yamlPath: string;
  yamlDir: string;
  logPath: string;
  cleanup: () => void;
  dk: DeviceKey;
  bobDid: string;
}

function makeCeremony(withExtraRecipient: boolean = false): Ceremony {
  const dir = mkdtempSync(join(tmpdir(), "tn-init-s1-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 11 + 3) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 5) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 7 + 19) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const selfKit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(selfKit));
  pub.free();

  const bobDid = "did:key:z6MkfakeBobForTsInitIdempotenceTestxxxxxx";
  const recipients = withExtraRecipient
    ? `    - did: ${dk.did}\n    - did: ${bobDid}`
    : `    - did: ${dk.did}`;

  const yaml = `ceremony:
  id: init_idem
  mode: local
  cipher: btn
  protocol_events_location: ./.tn/logs/admin/{event_type}.ndjson
logs:
  path: ./.tn/logs/tn.ndjson
keystore:
  path: ./.tn/keys
me:
  did: ${dk.did}
public_fields:
- timestamp
- event_id
- event_type
- level
- group
- leaf_index
- recipient_did
- kit_sha256
- cipher
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
${recipients}
fields: {}
`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    yamlDir: dir,
    logPath: join(logs, "tn.ndjson"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
    dk,
    bobDid,
  };
}

function countEvents(paths: string[], eventType: string): number {
  let n = 0;
  for (const p of paths) {
    if (!existsSync(p)) continue;
    const text = readFileSync(p, "utf8");
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        const env = JSON.parse(line);
        if (env.event_type === eventType) n += 1;
      } catch {
        /* skip */
      }
    }
  }
  return n;
}

function scanRecords(paths: string[], eventType: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const p of paths) {
    if (!existsSync(p)) continue;
    const text = readFileSync(p, "utf8");
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        const env = JSON.parse(line);
        if (env.event_type === eventType) out.push(env);
      } catch {
        /* skip */
      }
    }
  }
  return out;
}

test("slice1.scan_covers_main_and_pel", () => {
  const c = makeCeremony(false);
  try {
    // Seed the main log by writing an envelope directly. Then simulate
    // a Python-side PEL by writing one more envelope to ./.tn/logs/admin/.
    const rt = NodeRuntime.init(c.yamlPath);
    rt.emit("info", "tn.group.added", {
      group: "default",
      cipher: "btn",
      publisher_did: c.dk.did,
      added_at: new Date().toISOString(),
    });

    // Write a synthetic second tn.group.added for group "extra" into
    // a PEL location. Simulates Python having routed admin events
    // there. The file contents only matter for regex/JSON parsing.
    const pelDir = join(c.yamlDir, ".tn/logs", "admin");
    mkdirSync(pelDir, { recursive: true });
    const pelFile = join(pelDir, "tn.group.added.ndjson");
    const fakeEnv = {
      did: c.dk.did,
      timestamp: "2026-04-23T20:00:00.000000Z",
      event_id: "00000000-0000-0000-0000-000000000099",
      event_type: "tn.group.added",
      level: "info",
      sequence: 1,
      prev_hash: "sha256:" + "0".repeat(64),
      row_hash: "sha256:" + "a".repeat(64),
      signature: "fake",
      group: "extra",
      cipher: "btn",
      publisher_did: c.dk.did,
      added_at: "2026-04-23T20:00:00.000000Z",
    };
    writeFileSync(pelFile, JSON.stringify(fakeEnv) + "\n");

    // The scan helper must walk BOTH the main log and the PEL tree.
    const seen = scanAttestedGroups(c.yamlPath);
    assert.ok(seen.has("default"), "scan did not find main-log attestation");
    assert.ok(
      seen.has("extra"),
      "scan did not find PEL attestation; found " + JSON.stringify([...seen]),
    );
  } finally {
    c.cleanup();
  }
});

test("slice2.init_provisions_missing_recipient", () => {
  const c = makeCeremony(true);
  try {
    const before = countEvents([c.logPath], "tn.recipient.added");

    // Init should pick up Bob and mint for him.
    NodeRuntime.init(c.yamlPath);

    const after = countEvents([c.logPath], "tn.recipient.added");
    assert.equal(
      after,
      before + 1,
      `expected +1 tn.recipient.added after init (before=${before}, after=${after})`,
    );

    const bobEvents = scanRecords([c.logPath], "tn.recipient.added").filter(
      (env) => env.recipient_did === c.bobDid,
    );
    assert.ok(bobEvents.length === 1, `no tn.recipient.added for ${c.bobDid}`);

    // Kit on disk under outbox/, hash matches the attested kit_sha256.
    const outboxDir = join(c.yamlDir, ".tn/outbox");
    assert.ok(existsSync(outboxDir), "outbox/ should be created");
    let matchedOnDisk = false;
    const expected = bobEvents[0]!.kit_sha256 as string;
    for (const fname of readdirSync(outboxDir)) {
      if (!fname.endsWith(".mykit")) continue;
      const raw = readFileSync(join(outboxDir, fname));
      const have = "sha256:" + createHash("sha256").update(raw).digest("hex");
      if (have === expected) matchedOnDisk = true;
    }
    assert.ok(matchedOnDisk, `no outbox kit hashes to ${expected}`);

    // Third init is a no-op. Idempotence.
    NodeRuntime.init(c.yamlPath);
    const after2 = countEvents([c.logPath], "tn.recipient.added");
    assert.equal(after2, after, "second init re-emitted recipient.added");
  } finally {
    c.cleanup();
  }
});

test("slice3a.init_auto_creates_fresh_ceremony", () => {
  // No yaml, no keystore. init should generate everything: device key,
  // btn publisher state + self-kit, index master, tn.yaml. Mirrors
  // Python tn.init's create_fresh path.
  const dir = mkdtempSync(join(tmpdir(), "tn-init-s3a-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    assert.equal(existsSync(yamlPath), false, "pre-check: no yaml");
    // FINDINGS #2 — keystore now lives under .tn/<yaml-stem>/keys/.
    // For tn.yaml the stem is "tn".
    assert.equal(existsSync(join(dir, ".tn/tn/keys")), false, "pre-check: no .tn/tn/keys/");

    const rt = NodeRuntime.init(yamlPath);

    assert.ok(existsSync(yamlPath), "yaml should have been created");
    const keys = join(dir, ".tn/tn/keys");
    assert.ok(existsSync(join(keys, "local.private")), "local.private missing");
    assert.ok(existsSync(join(keys, "local.public")), "local.public missing");
    assert.ok(existsSync(join(keys, "index_master.key")), "index_master.key missing");
    assert.ok(existsSync(join(keys, "default.btn.state")), "default.btn.state missing");
    assert.ok(existsSync(join(keys, "default.btn.mykit")), "default.btn.mykit missing");

    // Sizes are what we'd expect.
    assert.equal(readFileSync(join(keys, "local.private")).length, 32);
    assert.equal(readFileSync(join(keys, "index_master.key")).length, 32);

    // The DID written into the yaml matches the one NodeRuntime now holds.
    const yamlText = readFileSync(yamlPath, "utf8");
    assert.ok(yamlText.includes(rt.did), "yaml should name the generated DID under me.did");

    // Initial emit works end to end.
    const receipt = rt.emit("info", "order.created", { amount: 100 });
    assert.match(receipt.rowHash, /^sha256:[0-9a-f]{64}$/);

    // Second init over the same dir must be idempotent (load path, not
    // re-create).
    const rt2 = NodeRuntime.init(yamlPath);
    assert.equal(rt2.did, rt.did, "second init changed DID (re-created!)");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("slice3b.init_refuses_to_clobber_existing_keystore", () => {
  // If .tn/keys/local.private already exists but tn.yaml is missing, init
  // must refuse: generating a fresh device key would orphan every
  // prior log entry (wrong DID) and discard the old index master so
  // HMAC tokens stop matching. Mirror of Python's create_fresh guard.
  const dir = mkdtempSync(join(tmpdir(), "tn-init-s3b-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    // First init to create real keystore material.
    NodeRuntime.init(yamlPath);
    // FINDINGS #2 — keystore namespaced by yaml stem.
    assert.ok(existsSync(join(dir, ".tn/tn/keys", "local.private")));

    // Now delete the yaml while leaving the keystore.
    rmSync(yamlPath);

    // Re-init must refuse rather than silently generate a new DID.
    assert.throws(
      () => NodeRuntime.init(yamlPath),
      /local\.private|keystore|clobber|already/i,
      "init should refuse when keystore exists but yaml is missing",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
