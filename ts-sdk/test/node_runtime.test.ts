import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { DeviceKey, NodeRuntime } from "../src/index.js";
import { createFreshCeremony } from "../src/runtime/node_runtime.js";
import { BtnPublisher } from "../src/raw.js";

function makeCeremony(): { yamlPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-runtime-"));
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

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 7) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  // The test asserts cross-init chain continuation ("seeds chain
  // from existing log"). Opt out of session-start rotation so the
  // prior session's events stay in the current file rather than
  // rolling to `<log>.1`.
  const yaml = `ceremony:\n  id: runtime_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\ndevice:\n  device_identity: ${dk.did}\nhandlers:\n- kind: file.rotating\n  path: ./.tn/logs/tn.ndjson\n  rotate_on_init: false\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - recipient_identity: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("NodeRuntime round-trips an encrypted entry", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const rt = NodeRuntime.init(yamlPath);
    const receipt = rt.emit("info", "order.created", { amount: 42, currency: "EUR" });
    assert.equal(typeof receipt.eventId, "string");
    assert.match(receipt.rowHash, /^sha256:[0-9a-f]{64}$/);
    assert.equal(receipt.sequence, 1);

    const entries = Array.from(rt.read());
    assert.equal(entries.length, 1);
    const e = entries[0]!;
    assert.equal(e.envelope.event_type, "order.created");
    assert.equal(e.envelope.sequence, 1);
    assert.equal(e.plaintext["default"]!.amount, 42);
    assert.equal(e.plaintext["default"]!.currency, "EUR");
    assert.equal(e.valid.signature, true, "signature should verify");
    assert.equal(e.valid.rowHash, true, "row_hash should recompute correctly");
    assert.equal(e.valid.chain, true, "chain should be intact");
  } finally {
    cleanup();
  }
});

test("NodeRuntime seeds chain from existing log", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    let rt = NodeRuntime.init(yamlPath);
    rt.emit("info", "order.created", { amount: 1 });
    rt.emit("info", "order.created", { amount: 2 });
    // New runtime reads the log and keeps the chain going.
    rt = NodeRuntime.init(yamlPath);
    const receipt = rt.emit("info", "order.created", { amount: 3 });
    assert.equal(receipt.sequence, 3);

    const entries = Array.from(rt.read());
    assert.equal(entries.length, 3);
    for (let i = 0; i < entries.length; i += 1) {
      assert.equal(entries[i]!.envelope.sequence, i + 1);
      assert.equal(entries[i]!.valid.chain, true);
      assert.equal(entries[i]!.valid.signature, true);
      assert.equal(entries[i]!.valid.rowHash, true);
    }
  } finally {
    cleanup();
  }
});

test("createFreshCeremony does not serialize Windows drive paths into yaml", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-portable-paths-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    const yamlDrive = /^([A-Za-z]):/.exec(yamlPath)?.[1]?.toUpperCase();
    const foreignDrive = yamlDrive === "C" ? "D" : "C";

    // Cross-drive paths cannot be expressed portably relative to the
    // ceremony dir: createFreshCeremony REFUSES rather than leaking a
    // machine-local drive path into the yaml (see yaml_path_portability).
    // The throw is a WINDOWS guarantee: on POSIX a "C:/..." string is not
    // drive-absolute (it parses as one relative segment), so the guard
    // cannot fire; there we assert the weaker invariant that nothing
    // drive-absolute lands in the yaml.
    if (process.platform === "win32") {
      assert.throws(
        () =>
          createFreshCeremony(yamlPath, {
            adminLogPath: `${foreignDrive}:/tn-portable/admin/admin.ndjson`,
          }),
        /different drive or volume/,
      );
    } else {
      createFreshCeremony(yamlPath, {
        adminLogPath: `${foreignDrive}:/tn-portable/admin/admin.ndjson`,
      });
      const yaml = readFileSync(yamlPath, "utf8");
      assert.doesNotMatch(yaml, /(?:^|\s)[A-Za-z]:[\\/]/m);
    }

    // Same-drive absolute paths relativize to ./-anchored yaml entries;
    // nothing drive-absolute is ever serialized.
    const okDir = mkdtempSync(join(tmpdir(), "tn-portable-ok-"));
    try {
      const okYaml = join(okDir, "tn.yaml");
      createFreshCeremony(okYaml, {
        logPath: join(okDir, "logs", "tn.ndjson"),
        adminLogPath: join(okDir, "admin", "admin.ndjson"),
      });
      const yaml = readFileSync(okYaml, "utf8");
      // No drive-absolute path tokens after whitespace (the vault url's
      // "https://" is the only legitimate ":/", and it is not drive-shaped).
      assert.doesNotMatch(yaml, /(?:^|\s)[A-Za-z]:[\\/]/m);
      assert.match(yaml, /admin_log_location: \.\/admin\/admin\.ndjson/);
      assert.match(yaml, /logs:\n {2}path: \.\//);
      assert.match(yaml, /handlers:\n- kind: file\.rotating[\s\S]*path: \.\//);
    } finally {
      rmSync(okDir, { recursive: true, force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
