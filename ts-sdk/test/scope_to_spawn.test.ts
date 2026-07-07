// tn.scopeTo(did).spawn() — per-DID scoped capability handle.
//
// The seeded `tn` is the project publisher and holds kits for every
// group. `tn.scopeTo(did).spawn()` returns a read-only capability handle
// that opens ONLY the groups where one of the scoped DIDs is a listed
// recipient, leaving every other group sealed. This is the mesh
// primitive: given a handed-in tn stream (bytes), surface exactly what
// those DIDs are entitled to and nothing else.

import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { DeviceKey } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";
import { Tn } from "../src/tn.js";

interface ScopeCeremony {
  yamlPath: string;
  publisherDid: string;
  cleanup: () => void;
}

// A publisher ceremony with two private groups whose recipient lists
// differ, so scoping has something to discriminate:
//   - `shared`: recipients = [publisher, readerDid]   fields = [note]
//   - `secret`: recipients = [publisher, tierDid]     fields = [ssn]
// The publisher keystore holds kits for both (it is a recipient of both),
// so any scoping is a capability FILTER, not a missing-key accident — the
// honest custodial property.
function makeScopeCeremony(readerDid: string, tierDid: string): ScopeCeremony {
  const dir = mkdtempSync(join(tmpdir(), "tn-scopeto-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = i + 2;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 3) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const groupNames = ["shared", "secret", "default"];
  for (let g = 0; g < groupNames.length; g += 1) {
    const gname = groupNames[g]!;
    const btnSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 7 + g * 13) & 0xff;
    const pub = new BtnPublisher(btnSeed);
    const kit = pub.mint();
    writeFileSync(join(keys, `${gname}.btn.state`), Buffer.from(pub.toBytes()));
    writeFileSync(join(keys, `${gname}.btn.mykit`), Buffer.from(kit));
  }

  const did = dk.did;
  const yaml = [
    "ceremony:",
    "  id: scope_to_spawn",
    "  mode: local",
    "  cipher: btn",
    "logs:",
    "  path: ./.tn/logs/tn.ndjson",
    "keystore:",
    "  path: ./.tn/keys",
    "device:",
    `  device_identity: ${did}`,
    "public_fields:",
    "- timestamp",
    "- event_id",
    "- event_type",
    "- level",
    "default_policy: private",
    "groups:",
    "  shared:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - recipient_identity: ${did}`,
    `    - recipient_identity: ${readerDid}`,
    "    fields:",
    "    - note",
    "  secret:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - recipient_identity: ${did}`,
    `    - recipient_identity: ${tierDid}`,
    "    fields:",
    "    - ssn",
    "  default:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - recipient_identity: ${did}`,
    "fields: {}",
    "",
  ].join("\n");
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    publisherDid: did,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function didFromSeedByte(b: number): string {
  const seed = new Uint8Array(32).fill(b & 0xff);
  return DeviceKey.fromSeed(seed).did;
}

const READER_DID = didFromSeedByte(0xa1);
const TIER_DID = didFromSeedByte(0xb2);
const STRANGER_DID = didFromSeedByte(0xc3);

test("scopeTo(did).spawn().read opens only the groups that DID is a recipient of", async () => {
  const ceremony = makeScopeCeremony(READER_DID, TIER_DID);
  try {
    const tn = await Tn.init(ceremony.yamlPath);
    tn.info("user.action", { note: "hello", ssn: "123-45-6789" });
    const message = readFileSync(tn.logPath, "utf8");

    const entries = [...tn.scopeTo(READER_DID).spawn().read(message)].filter(
      (e) => e.event_type === "user.action",
    );
    await tn.close();

    assert.equal(entries.length, 1, `expected 1 user.action entry, got ${entries.length}`);
    const e = entries[0]!;
    // `shared` lists READER_DID → note is visible.
    assert.equal(e.fields["note"], "hello", "reader is a recipient of `shared`; `note` should decrypt");
    // `secret` does NOT list READER_DID → ssn stays sealed.
    assert.ok(!("ssn" in e.fields), `reader is not a recipient of \`secret\`; ssn leaked: ${JSON.stringify(e.fields)}`);
    assert.ok(
      e.hidden_groups.includes("secret"),
      `expected 'secret' in hidden_groups, got ${JSON.stringify(e.hidden_groups)}`,
    );
  } finally {
    ceremony.cleanup();
  }
});

test("scopeTo(userDid, tierDid) unions capabilities — opens both DIDs' groups", async () => {
  const ceremony = makeScopeCeremony(READER_DID, TIER_DID);
  try {
    const tn = await Tn.init(ceremony.yamlPath);
    tn.info("user.action", { note: "hello", ssn: "123-45-6789" });
    const message = readFileSync(tn.logPath, "utf8");

    // The mesh shape: "that user's did plus its own did" → both groups.
    const entries = [...tn.scopeTo(READER_DID, TIER_DID).spawn().read(message)].filter(
      (e) => e.event_type === "user.action",
    );
    await tn.close();

    assert.equal(entries.length, 1);
    const e = entries[0]!;
    assert.equal(e.fields["note"], "hello", "READER_DID's group `shared` should open");
    assert.equal(e.fields["ssn"], "123-45-6789", "TIER_DID's group `secret` should open");
    // Both targeted groups opened. (`default` carries unrouted private
    // fields like run_id and lists only the publisher, so it legitimately
    // stays sealed — neither scoped DID is a recipient of it.)
    assert.ok(!e.hidden_groups.includes("shared"), "`shared` should be open for READER_DID");
    assert.ok(!e.hidden_groups.includes("secret"), "`secret` should be open for TIER_DID");
  } finally {
    ceremony.cleanup();
  }
});

test("scopeTo(strangerDid) — a DID that is a recipient of nothing opens nothing", async () => {
  const ceremony = makeScopeCeremony(READER_DID, TIER_DID);
  try {
    const tn = await Tn.init(ceremony.yamlPath);
    tn.info("user.action", { note: "hello", ssn: "123-45-6789" });
    const message = readFileSync(tn.logPath, "utf8");

    const scoped = tn.scopeTo(STRANGER_DID).spawn();
    assert.deepEqual(scoped.groups, [], "stranger resolves to no openable groups");

    const entries = [...scoped.read(message)].filter((e) => e.event_type === "user.action");
    await tn.close();

    assert.equal(entries.length, 1);
    const e = entries[0]!;
    assert.ok(!("note" in e.fields) && !("ssn" in e.fields), `stranger leaked fields: ${JSON.stringify(e.fields)}`);
    assert.ok(
      e.hidden_groups.includes("shared") && e.hidden_groups.includes("secret"),
      `both groups should be hidden, got ${JSON.stringify(e.hidden_groups)}`,
    );
  } finally {
    ceremony.cleanup();
  }
});

test("scopeTo(...).read accepts the stream as bytes, not just a file path", async () => {
  const ceremony = makeScopeCeremony(READER_DID, TIER_DID);
  try {
    const tn = await Tn.init(ceremony.yamlPath);
    tn.info("user.action", { note: "hello", ssn: "123-45-6789" });
    // Hand over the raw bytes a Worker / mesh would have received.
    const messageBytes = new Uint8Array(readFileSync(tn.logPath));

    const entries = [...tn.scopeTo(READER_DID).spawn().read(messageBytes)].filter(
      (e) => e.event_type === "user.action",
    );
    await tn.close();

    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.fields["note"], "hello", "bytes-in read should decrypt the same as string-in");
  } finally {
    ceremony.cleanup();
  }
});
