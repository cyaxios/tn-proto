// Multi-group field routing — TS mirror of Python's
// tests/test_multi_group_routing.py.
//
// A field listed under N groups in tn.yaml is encrypted into all N
// groups' payloads. Validation: a field routed to an unknown group, or
// a field listed in both `public_fields:` and a group, is rejected at
// load time. Legacy flat `fields:` still loads, with a deprecation
// warning.

import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { DeviceKey, NodeRuntime } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";
import { loadConfig } from "../src/runtime/config.js";

interface Ceremony {
  yamlPath: string;
  cleanup: () => void;
  did: string;
  dir: string;
}

function makeCeremony(opts: {
  groupNames: string[];
  yamlBody: (did: string) => string;
}): Ceremony {
  const dir = mkdtempSync(join(tmpdir(), "tn-multigroup-"));
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

  // Create a btn publisher for each group requested. Each gets its own
  // seed-derived state so payloads stay independent.
  for (let g = 0; g < opts.groupNames.length; g += 1) {
    const gname = opts.groupNames[g]!;
    const btnSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 7 + g * 13) & 0xff;
    const pub = new BtnPublisher(btnSeed);
    const kit = pub.mint();
    writeFileSync(join(keys, `${gname}.btn.state`), Buffer.from(pub.toBytes()));
    writeFileSync(join(keys, `${gname}.btn.mykit`), Buffer.from(kit));
  }

  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, opts.yamlBody(dk.did), "utf8");

  return {
    yamlPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
    did: dk.did,
    dir,
  };
}

function recipientLine(did: string): string {
  return `    recipients:\n    - did: ${did}\n`;
}

test("loadConfig inverts groups[<g>].fields into fieldToGroups", () => {
  const c = makeCeremony({
    groupNames: ["default", "a", "b"],
    yamlBody: (did) =>
      `ceremony:\n  id: mg_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n${recipientLine(did)}  a:\n    policy: private\n    cipher: btn\n${recipientLine(did)}    fields:\n    - email\n  b:\n    policy: private\n    cipher: btn\n${recipientLine(did)}    fields:\n    - email\nfields: {}\n`,
  });
  try {
    const cfg = loadConfig(c.yamlPath);
    assert.deepEqual(cfg.fieldToGroups.get("email"), ["a", "b"]);
  } finally {
    c.cleanup();
  }
});

test("emit encrypts a field into every group it's declared under", () => {
  const c = makeCeremony({
    groupNames: ["default", "a", "b"],
    yamlBody: (did) =>
      `ceremony:\n  id: mg_emit\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n${recipientLine(did)}  a:\n    policy: private\n    cipher: btn\n${recipientLine(did)}    fields:\n    - email\n  b:\n    policy: private\n    cipher: btn\n${recipientLine(did)}    fields:\n    - email\nfields: {}\n`,
  });
  try {
    const rt = NodeRuntime.init(c.yamlPath);
    rt.emit("info", "evt.multi", { email: "alice@example.com" });
    const entries = Array.from(rt.read());
    assert.equal(entries.length, 1);
    const e = entries[0]!;
    // Both groups got the value.
    assert.equal(e.plaintext["a"]?.email, "alice@example.com");
    assert.equal(e.plaintext["b"]?.email, "alice@example.com");
    // Each group's index token is independent (different group key).
    // Note the envelope uses camelCase `fieldHashes` (Python ndjson uses
    // `field_hashes`); the TS NodeRuntime keeps the JS-idiomatic shape.
    const aHashes = (e.envelope["a"] as { fieldHashes: Record<string, string> })
      .fieldHashes;
    const bHashes = (e.envelope["b"] as { fieldHashes: Record<string, string> })
      .fieldHashes;
    assert.notEqual(aHashes["email"], bHashes["email"]);
  } finally {
    c.cleanup();
  }
});

test("fieldToGroups list is sorted alphabetically (insertion-order independent)", () => {
  // Declaration order is "zeta" then "alpha" — fieldToGroups must
  // alphabetize so canonical encoding is stable across SDKs.
  const c = makeCeremony({
    groupNames: ["default", "zeta", "alpha"],
    yamlBody: (did) =>
      `ceremony:\n  id: mg_sort\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n${recipientLine(did)}  zeta:\n    policy: private\n    cipher: btn\n${recipientLine(did)}    fields:\n    - x\n  alpha:\n    policy: private\n    cipher: btn\n${recipientLine(did)}    fields:\n    - x\nfields: {}\n`,
  });
  try {
    const cfg = loadConfig(c.yamlPath);
    assert.deepEqual(cfg.fieldToGroups.get("x"), ["alpha", "zeta"]);
  } finally {
    c.cleanup();
  }
});

test("field routed to an unknown group raises at load", () => {
  // Use the legacy flat block to point at a non-existent group, since
  // the canonical groups[<g>].fields shape can't reference other groups.
  const c = makeCeremony({
    groupNames: ["default"],
    yamlBody: (did) =>
      `ceremony:\n  id: mg_unknown\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n${recipientLine(did)}fields:\n  x:\n    group: ghost_group\n`,
  });
  try {
    assert.throws(() => loadConfig(c.yamlPath), /unknown group/);
  } finally {
    c.cleanup();
  }
});

test("field in both public_fields and a group is rejected", () => {
  const c = makeCeremony({
    groupNames: ["default", "a"],
    yamlBody: (did) =>
      `ceremony:\n  id: mg_amb\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\n- email\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n${recipientLine(did)}  a:\n    policy: private\n    cipher: btn\n${recipientLine(did)}    fields:\n    - email\nfields: {}\n`,
  });
  try {
    assert.throws(() => loadConfig(c.yamlPath), /public_fields and a group/);
  } finally {
    c.cleanup();
  }
});

test("legacy flat fields: block still loads with a deprecation warning", () => {
  // Capture console.warn to verify the deprecation fires.
  const c = makeCeremony({
    groupNames: ["default", "secrets"],
    yamlBody: (did) =>
      `ceremony:\n  id: mg_legacy\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n${recipientLine(did)}  secrets:\n    policy: private\n    cipher: btn\n${recipientLine(did)}fields:\n  password:\n    group: secrets\n`,
  });
  try {
    const captured: string[] = [];
    const orig = console.warn;
    console.warn = (msg: string) => {
      captured.push(String(msg));
    };
    try {
      const cfg = loadConfig(c.yamlPath);
      assert.deepEqual(cfg.fieldToGroups.get("password"), ["secrets"]);
    } finally {
      console.warn = orig;
    }
    assert.equal(
      captured.some((m) => m.includes("deprecated")),
      true,
      `expected deprecation warning, got: ${JSON.stringify(captured)}`,
    );
  } finally {
    c.cleanup();
  }
});
