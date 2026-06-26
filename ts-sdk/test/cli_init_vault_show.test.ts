// Tests for the new tn-js CLI verbs added 2026-05-27:
//   tn-js init   — wraps the programmatic `tn.init(yaml?)` export
//   tn-js vault link / unlink — wraps tn.vault.link/unlink (log-event verbs)
//   tn-js show env — read-only ceremony config snapshot
//
// Asserts the CLI exits 0, prints structured JSON to stdout, and (for
// vault link/unlink) actually appends the expected event to the log.
//
// The deeper ceremony bootstrap path (mnemonic + claim URL emission) is
// Python-only today and tracked as Task #20 (port wallet/account
// namespaces to TS SDK). These tests cover what the CLI CAN do today
// via the existing SDK surface.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Tn } from "../src/tn.js";

// Resolve bin/tn-js.mjs as an absolute path so tests can spawn it from any
// cwd (each test uses a tmpdir cwd so the SDK's discovery doesn't find a
// parent project's tn.yaml).
const _here = dirname(fileURLToPath(import.meta.url));
const TN_JS_BIN = pathResolve(_here, "..", "bin", "tn-js.mjs");

interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

async function runCli(args: string[], cwd: string = process.cwd()): Promise<CliResult> {
  return new Promise<CliResult>((resolve, reject) => {
    // Isolate the machine-global identity + home: `tn init` does
    // Identity.loadOrMint() and (on a fresh mint) vault-link. Without this the
    // CLI would read/mint the real ~/.tn identity and could hit the network.
    const proc = spawn("node", [TN_JS_BIN, ...args], {
      cwd,
      env: {
        ...process.env,
        TN_IDENTITY_DIR: join(cwd, ".tn-identity"),
        TN_HOME: join(cwd, ".tn-home"),
      },
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

test("tn-js init (no name) — mints a .tn/<folder>/ ceremony, human output by default", async () => {
  // Python parity: no name uses the current folder's name and mints a root
  // ceremony there. mkdtemp names are valid ceremony names (letters/digits/dash).
  const tmp = mkdtempSync(join(tmpdir(), "tncliinit-"));
  try {
    const r = await runCli(["init", "--no-link"], tmp);
    assert.equal(r.code, 0, `init should exit 0; stderr=${r.stderr}`);
    // Human output by default (no JSON): the "using current folder" notice and
    // the ceremony-created summary line.
    assert.match(r.stdout, /no name given; using current folder/);
    assert.match(r.stdout, /\[tn init\] Ceremony .+ created at/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js init --json — mints + prints the receipt", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tncliinit-"));
  try {
    const r = await runCli(["init", "--no-link", "--json"], tmp);
    assert.equal(r.code, 0, `init should exit 0; stderr=${r.stderr}`);
    // The receipt is the LAST stdout line (human notice precedes it).
    const lines = r.stdout.trim().split("\n").filter((l) => l.trim().startsWith("{"));
    const obj = JSON.parse(lines[lines.length - 1]);
    assert.equal(obj.ok, true);
    assert.ok(typeof obj.did === "string" && obj.did.startsWith("did:"), `expected did:* string; got ${obj.did}`);
    assert.ok(typeof obj.ceremony_id === "string" && obj.ceremony_id.length > 0, `expected non-empty ceremony_id; got ${obj.ceremony_id}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js init <yaml-path> --json — attaches to a pre-existing ceremony, prints did", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-init-attach-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    // Seed a real ceremony first via the programmatic Tn class.
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const r = await runCli(["init", yamlPath, "--no-link", "--json"], tmp);
    assert.equal(r.code, 0, `init should exit 0; stderr=${r.stderr}`);
    const lines = r.stdout.trim().split("\n").filter((l) => l.trim().startsWith("{"));
    const obj = JSON.parse(lines[lines.length - 1]);
    assert.equal(obj.ok, true);
    assert.equal(obj.yaml_path, yamlPath);
    assert.ok(typeof obj.did === "string" && obj.did.startsWith("did:"), `expected did:* string; got ${obj.did}`);
    assert.ok(typeof obj.ceremony_id === "string" && obj.ceremony_id.length > 0, `expected non-empty ceremony_id; got ${obj.ceremony_id}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js init <name> --force moves the prior ceremony aside and re-mints", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tncliinit-"));
  try {
    const first = await runCli(["init", "proj", "--no-link", "--json"], tmp);
    assert.equal(first.code, 0, `first init should exit 0; stderr=${first.stderr}`);
    const r = await runCli(["init", "proj", "--no-link", "--force"], tmp);
    assert.equal(r.code, 0, `--force init should exit 0; stderr=${r.stderr}`);
    assert.match(r.stdout, /--force: prior ceremony moved to .+_overwritten_proj_/);
    assert.match(r.stdout, /Ceremony .+ created at/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js vault link — exits 0, prints receipt, appends event to log", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-vault-link-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const vaultDid = "did:web:vault.example";
    const projectId = "proj-test-001";
    const r = await runCli(["vault", "link", vaultDid, projectId, "--yaml", yamlPath], tmp);
    assert.equal(r.code, 0, `vault link should exit 0; stderr=${r.stderr}`);
    const obj = JSON.parse(r.stdout.trim());
    assert.equal(obj.ok, true);
    assert.equal(obj.verb, "vault.link");
    assert.equal(obj.vault_did, vaultDid);
    assert.equal(obj.project_id, projectId);
    assert.ok(typeof obj.event_id === "string" && obj.event_id.length > 0);
    assert.ok(typeof obj.row_hash === "string" && obj.row_hash.length > 0);

    // Confirm the event landed in the log by reading it back.
    const reader = await Tn.init(yamlPath);
    try {
      const types = [];
      for (const e of reader.read()) {
        types.push(e.event_type);
      }
      assert.ok(
        types.includes("tn.vault.linked"),
        `expected tn.vault.linked in log; got ${types.join(", ")}`,
      );
    } finally {
      await reader.close();
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js vault unlink --reason — exits 0, appends tn.vault.unlinked", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-vault-unlink-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const r = await runCli(
      ["vault", "unlink", "did:web:vault.example", "proj-test-001", "--reason", "test cleanup", "--yaml", yamlPath],
      tmp,
    );
    assert.equal(r.code, 0, `vault unlink should exit 0; stderr=${r.stderr}`);
    const obj = JSON.parse(r.stdout.trim());
    assert.equal(obj.verb, "vault.unlink");

    const reader = await Tn.init(yamlPath);
    try {
      const types = [];
      for (const e of reader.read()) types.push(e.event_type);
      assert.ok(types.includes("tn.vault.unlinked"));
    } finally {
      await reader.close();
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js vault link — missing positionals errors with non-zero exit", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-vault-bad-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const r = await runCli(["vault", "link", "did:web:only-one"], tmp);
    assert.notEqual(r.code, 0, "missing project-id positional must fail");
    assert.match(r.stderr, /vault link.*required/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js show env --json — exits 0, prints ceremony snapshot with did/ceremony fields", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-show-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const r = await runCli(["show", "env", "--yaml", yamlPath, "--json"], tmp);
    assert.equal(r.code, 0, `show env --json should exit 0; stderr=${r.stderr}`);
    const obj = JSON.parse(r.stdout.trim());
    assert.equal(obj.ok, true);
    assert.ok(obj.me && typeof obj.me.did === "string" && obj.me.did.startsWith("did:"));
    assert.ok(obj.ceremony && typeof obj.ceremony.id === "string");
    assert.equal(obj.ceremony.cipher, "btn");
    assert.ok(obj.keystore && typeof obj.keystore.path === "string");
    assert.ok(typeof obj.handlers_count === "number" && obj.handlers_count > 0);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js show env — DEFAULT output is human-readable, not JSON", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-show-human-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const r = await runCli(["show", "env", "--yaml", yamlPath], tmp);
    assert.equal(r.code, 0, `show env should exit 0; stderr=${r.stderr}`);
    // Human default: labeled lines, NOT JSON.
    assert.ok(!r.stdout.trimStart().startsWith("{"), `human output must not start with '{': ${r.stdout.slice(0, 60)}`);
    assert.throws(() => JSON.parse(r.stdout.trim()), "human output must not be valid JSON");
    assert.match(r.stdout, /ceremony\.cipher:\s+btn/, "expected human ceremony.cipher line");
    assert.match(r.stdout, /device:\s+did:/, "expected human device line");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js show env --format json — equivalent to --json", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-show-fmt-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const r = await runCli(["show", "env", "--yaml", yamlPath, "--format", "json"], tmp);
    assert.equal(r.code, 0, `show env --format json should exit 0; stderr=${r.stderr}`);
    const obj = JSON.parse(r.stdout.trim());
    assert.equal(obj.ok, true);
    assert.equal(obj.ceremony.cipher, "btn");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js show — unknown subcommand errors with hint", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-show-bad-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const seeded = await Tn.init(yamlPath);
    await seeded.close();

    const r = await runCli(["show", "garbage", "--yaml", yamlPath], tmp);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /show: unknown subcommand/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
