// `tn account connect` parity with Python cmd_account_connect for the paths
// that don't need a live vault: --yaml is discovered (not required), a missing
// ceremony exits 1 (Python _die), and a missing <code> is a usage error (2).

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";

const TN_JS_BIN = pathResolve(dirname(fileURLToPath(import.meta.url)), "..", "bin", "tn-js.mjs");

interface Res {
  stdout: string;
  stderr: string;
  code: number;
}

function run(args: string[], cwd: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [TN_JS_BIN, ...args], {
      cwd,
      env: { ...process.env, TN_IDENTITY_DIR: join(cwd, ".id"), TN_HOME: join(cwd, ".home") },
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

test("account connect with no ceremony exits 1 (discovery, Python _die)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-acct-"));
  try {
    // No --yaml and no ceremony in cwd → discovery fails → exit 1.
    const r = await run(["account", "connect", "tn_connect_dummy"], tmp);
    assert.equal(r.code, 1, `expected exit 1; stdout=${r.stdout} stderr=${r.stderr}`);
    assert.match(r.stderr, /no ceremony found here/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("account connect with no <code> is a usage error (exit 2)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-acct-"));
  try {
    const r = await run(["account", "connect"], tmp);
    assert.equal(r.code, 2, `expected exit 2; stderr=${r.stderr}`);
    assert.match(r.stderr, /<code> positional is required/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("account with an unknown subcommand is a usage error (exit 2)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-acct-"));
  try {
    const r = await run(["account", "bogus"], tmp);
    assert.equal(r.code, 2, `expected exit 2; stderr=${r.stderr}`);
    assert.match(r.stderr, /unknown subcommand/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
