// `tn init` identity ceremony parity with Python cmd_init: --mnemonic-file
// derivation, --keep-mnemonic persistence, --words entropy, reuse messaging,
// and non-TTY provisioning (persist the phrase + print a notice). Spawned in a
// non-TTY child with an isolated TN_IDENTITY_DIR so it never touches the real
// machine identity and never blocks on the Enter prompt.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";

const TN_JS_BIN = pathResolve(dirname(fileURLToPath(import.meta.url)), "..", "bin", "tn-js.mjs");

// Golden all-zeros 12-word mnemonic + its DID (from identity.test.ts).
const GOLDEN_M =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const GOLDEN_DID = "did:key:z6MkrLS6RRwz2XtkyngSFbV88ds7ce1mSaehMrcuigrSVAAk";

interface Res {
  stdout: string;
  stderr: string;
  code: number;
}

function runInit(args: string[], cwd: string, idDir: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [TN_JS_BIN, "init", ...args], {
      cwd,
      env: { ...process.env, TN_IDENTITY_DIR: idDir, TN_HOME: join(cwd, ".home") },
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

test("init --mnemonic-file derives the identity from the file (golden DID)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tncli-mn-"));
  const idDir = join(tmp, ".id");
  try {
    const mnFile = join(tmp, "phrase.txt");
    writeFileSync(mnFile, GOLDEN_M + "\n", "utf8");
    const r = await runInit(["proj", "--no-link", "--mnemonic-file", mnFile], tmp, idDir);
    assert.equal(r.code, 0, `stderr=${r.stderr}`);
    assert.match(r.stdout, /Identity derived from/);
    const doc = JSON.parse(readFileSync(join(idDir, "identity.json"), "utf8"));
    assert.equal(doc.did, GOLDEN_DID, "mnemonic-file identity must derive the golden DID");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("init --keep-mnemonic persists the recovery phrase into identity.json", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tncli-mn-"));
  const idDir = join(tmp, ".id");
  try {
    const r = await runInit(["proj", "--no-link", "--keep-mnemonic"], tmp, idDir);
    assert.equal(r.code, 0, `stderr=${r.stderr}`);
    const doc = JSON.parse(readFileSync(join(idDir, "identity.json"), "utf8"));
    assert.equal(typeof doc.mnemonic_stored, "string");
    assert.equal(doc.mnemonic_stored.trim().split(/\s+/).length, 12, "default is a 12-word phrase");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("init --words 24 mints a 24-word phrase (persisted via non-TTY provisioning)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tncli-mn-"));
  const idDir = join(tmp, ".id");
  try {
    // Non-TTY (spawned) with a fresh identity provisions unattended: the phrase
    // is persisted, so we can assert its length.
    const r = await runInit(["proj", "--no-link", "--words", "24"], tmp, idDir);
    assert.equal(r.code, 0, `stderr=${r.stderr}`);
    assert.match(r.stdout, /non-interactive mode: mnemonic will be persisted/);
    const doc = JSON.parse(readFileSync(join(idDir, "identity.json"), "utf8"));
    assert.equal(doc.mnemonic_stored.trim().split(/\s+/).length, 24);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("init reuses an existing identity on the second run", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tncli-mn-"));
  const idDir = join(tmp, ".id");
  try {
    const first = await runInit(["a", "--no-link"], tmp, idDir);
    assert.equal(first.code, 0, `stderr=${first.stderr}`);
    assert.match(first.stdout, /New identity written to/);
    const second = await runInit(["b", "--no-link"], tmp, idDir);
    assert.equal(second.code, 0, `stderr=${second.stderr}`);
    assert.match(second.stdout, /Reusing identity at/);
    // Same DID across both ceremonies (shared device identity).
    const did1 = (first.stdout.match(/DID: (did:key:\S+)/) ?? [])[1];
    const did2 = (second.stdout.match(/DID: (did:key:\S+)/) ?? [])[1];
    assert.ok(did1 && did1 === did2, `DID must be stable: ${did1} vs ${did2}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("init --words rejects an invalid entropy choice", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tncli-mn-"));
  const idDir = join(tmp, ".id");
  try {
    const r = await runInit(["proj", "--no-link", "--words", "13"], tmp, idDir);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /--words must be one of/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
