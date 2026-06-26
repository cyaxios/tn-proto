/**
 * Smoke tests for ``tn-js streams`` and ``tn-js validate`` —
 * mirrors the Python CLI tests at python/tests around tn streams /
 * tn validate. Just runs the binary against a tempdir and checks
 * exit codes + stdout shape.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const CLI = resolve("./bin/tn-js.mjs");

function run(args: string[]): { code: number; stdout: string; stderr: string } {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8" });
  return {
    code: r.status ?? -1,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
  };
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "tn-cli-test-"));
}

function writeYaml(path: string, body: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, body, "utf8");
}

// A full non-stream default yaml that satisfies every check EXCEPT the
// group-kit one (which expects `<keys>/default.btn.mykit` on disk). Mirrors
// FULL_DEFAULT in python/tests/test_cmd_validate.py. Omits a populated
// keystore so the DID-consistency check (no keys/local.public) is skipped.
const FULL_DEFAULT =
  "ceremony:\n  id: c1\n  cipher: btn\n" +
  "logs:\n  path: ./logs/tn.ndjson\n" +
  "keystore:\n  path: ./keys\n" +
  "device:\n  device_identity: did:key:zDEV\n" +
  "groups:\n  default:\n    policy: private\n";

// Write FULL_DEFAULT plus the publisher self-kit the group-kit check wants,
// so a clean default ceremony validates green.
function writeFullDefault(td: string): void {
  writeYaml(join(td, ".tn", "default", "tn.yaml"), FULL_DEFAULT);
  const keys = join(td, ".tn", "default", "keys");
  mkdirSync(keys, { recursive: true });
  writeFileSync(join(keys, "default.btn.mykit"), "kit-bytes", "utf8");
}

test("tn-js streams: no .tn/ at all reports clean", () => {
  const td = tmp();
  try {
    const r = run(["streams", "--project-dir", td]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /no ceremonies found/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js streams: lists ceremonies under .tn/", () => {
  const td = tmp();
  try {
    writeYaml(
      join(td, ".tn", "default", "tn.yaml"),
      "ceremony:\n  profile: transaction\n",
    );
    writeYaml(
      join(td, ".tn", "payments", "tn.yaml"),
      "ceremony:\n  profile: audit\n",
    );
    const r = run(["streams", "--project-dir", td]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /default/);
    assert.match(r.stdout, /payments/);
    assert.match(r.stdout, /transaction/);
    assert.match(r.stdout, /audit/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js streams --format json", () => {
  const td = tmp();
  try {
    writeYaml(
      join(td, ".tn", "x", "tn.yaml"),
      "ceremony:\n  profile: transaction\n",
    );
    const r = run(["streams", "--project-dir", td, "--format", "json"]);
    assert.equal(r.code, 0);
    const parsed = JSON.parse(r.stdout);
    assert.ok(Array.isArray(parsed));
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0].name, "x");
    assert.equal(parsed[0].profile, "transaction");
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: empty project is OK", () => {
  const td = tmp();
  try {
    const r = run(["validate", "--project-dir", td]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /nothing to validate/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: a full, well-formed default ceremony passes", () => {
  // Was "known profile passes" with a bare `ceremony.profile` yaml; under the
  // 5-check validator (parity with Python) a non-stream default must also
  // carry logs/keystore/device/groups + ceremony.id + a group self-kit.
  const td = tmp();
  try {
    writeFullDefault(td);
    const r = run(["validate", "--project-dir", td]);
    assert.equal(r.code, 0, `expected exit 0, stderr=${r.stderr}`);
    assert.match(r.stdout, /OK/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: missing required top-level sections fail non-zero", () => {
  // Non-stream default with only `ceremony:` -> logs/keystore/device/groups
  // are all required. Mirrors test_missing_required_top_level_key.
  const td = tmp();
  try {
    writeYaml(join(td, ".tn", "default", "tn.yaml"), "ceremony:\n  id: c1\n");
    const r = run(["validate", "--project-dir", td]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /missing required top-level key/);
    assert.match(r.stderr, /'keystore'/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: missing ceremony.id fails non-zero", () => {
  // Mirrors test_missing_ceremony_id.
  const td = tmp();
  try {
    writeYaml(
      join(td, ".tn", "default", "tn.yaml"),
      FULL_DEFAULT.replace("  id: c1\n", ""),
    );
    const r = run(["validate", "--project-dir", td]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /ceremony\.id is required/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: legacy `me:` block is rejected", () => {
  // Mirrors test_legacy_me_block_is_rejected.
  const td = tmp();
  try {
    writeYaml(
      join(td, ".tn", "default", "tn.yaml"),
      "ceremony:\n  id: c1\n  cipher: btn\n" +
        "logs:\n  path: ./logs/tn.ndjson\n" +
        "keystore:\n  path: ./keys\n" +
        "me:\n  did: did:key:zOLD\n" +
        "groups:\n  default:\n    policy: private\n",
    );
    const r = run(["validate", "--project-dir", td]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /legacy `me:`/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: missing group self-kit is flagged", () => {
  // FULL_DEFAULT declares a btn `default` group + keystore.path=./keys but
  // no default.btn.mykit on disk -> "kit missing". Mirrors
  // test_missing_group_kit_is_flagged.
  const td = tmp();
  try {
    writeYaml(join(td, ".tn", "default", "tn.yaml"), FULL_DEFAULT);
    const r = run(["validate", "--project-dir", td]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /kit missing/);
    assert.match(r.stderr, /default\.btn\.mykit/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: yaml device.device_identity vs keystore mismatch is flagged", () => {
  // Mirrors test_validate_catches_yaml_did_keystore_mismatch: yaml DID and
  // keys/local.public disagree -> error.
  const td = tmp();
  try {
    writeFullDefault(td); // yaml device_identity = did:key:zDEV
    writeFileSync(
      join(td, ".tn", "default", "keys", "local.public"),
      "did:key:zOTHER",
      "ascii",
    );
    const r = run(["validate", "--project-dir", td]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /device\.device_identity does not match keystore/);
    assert.match(r.stderr, /did:key:zDEV/);
    assert.match(r.stderr, /did:key:zOTHER/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: a stream yaml has narrower requirements", () => {
  // A stream (`extends:`) only requires `ceremony`; it must NOT be flagged
  // for missing logs/keystore/device/groups. Mirrors
  // test_stream_yaml_has_narrower_requirements. No 'default' -> warning only,
  // so exit stays 0.
  const td = tmp();
  try {
    writeYaml(
      join(td, ".tn", "stream", "tn.yaml"),
      "extends: ../default/tn.yaml\nceremony:\n  id: s1\n",
    );
    const r = run(["validate", "--project-dir", td]);
    assert.equal(r.code, 0, `expected exit 0, stderr=${r.stderr}`);
    assert.doesNotMatch(r.stderr, /missing required top-level key/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: unknown profile fails non-zero", () => {
  const td = tmp();
  try {
    writeYaml(
      join(td, ".tn", "default", "tn.yaml"),
      "ceremony:\n  profile: not_a_real_profile\n",
    );
    const r = run(["validate", "--project-dir", td]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /unknown profile/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("tn-js validate: warns when default ceremony is missing", () => {
  const td = tmp();
  try {
    // A lone stream (no default). Under the 5-check validator a stream has
    // narrow requirements, so the only finding is the missing-default WARNING
    // (not an error) -> exit 0. Mirrors test_no_default_ceremony_warns.
    writeYaml(
      join(td, ".tn", "x", "tn.yaml"),
      "extends: ../default/tn.yaml\nceremony:\n  id: s1\n",
    );
    const r = run(["validate", "--project-dir", td]);
    // No default → warning, but still passes.
    assert.equal(r.code, 0, `expected exit 0, stderr=${r.stderr}`);
    assert.match(r.stderr, /no 'default' ceremony/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});
