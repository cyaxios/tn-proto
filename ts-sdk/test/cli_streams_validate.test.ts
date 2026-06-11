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

test("tn-js validate: known profile passes", () => {
  const td = tmp();
  try {
    writeYaml(
      join(td, ".tn", "default", "tn.yaml"),
      "ceremony:\n  profile: transaction\n",
    );
    const r = run(["validate", "--project-dir", td]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /OK/);
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
    writeYaml(
      join(td, ".tn", "x", "tn.yaml"),
      "ceremony:\n  profile: audit\n",
    );
    const r = run(["validate", "--project-dir", td]);
    // No default → warning, but still passes.
    assert.equal(r.code, 0);
    assert.match(r.stderr, /no 'default' ceremony/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});
