// CLI + unit tests for `tn-js wallet status`.
//
// Covers:
//  - no identity → informational message, exit 0
//  - identity only (no yaml) → prints DID, linked vault, prefs
//  - identity + yaml → prints ceremony fields including groups and cipher
//  - identity + yaml + pending sync queue → shows queue count and latest error
//  - identity + missing yaml → graceful "no yaml at <path>" message

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Tn } from "../src/tn.js";
import { Identity } from "../src/identity.js";
import { readSyncQueue, _internals as walletInternals } from "../src/wallet/index.js";

const _here = dirname(fileURLToPath(import.meta.url));
const TN_JS_BIN = pathResolve(_here, "..", "bin", "tn-js.mjs");

interface CliResult { stdout: string; stderr: string; code: number; }

async function runCli(args: string[], env: Record<string, string> = {}): Promise<CliResult> {
  return new Promise<CliResult>((resolve, reject) => {
    const proc = spawn("node", [TN_JS_BIN, ...args], {
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    proc.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    proc.on("close", (code: number | null) => resolve({ stdout, stderr, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

// ── unit tests (no subprocess) ─────────────────────────────────────────────

test("Identity.path getter returns the path identity was loaded from", () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-id-path-"));
  try {
    const idPath = join(tmp, "identity.json");
    const id = Identity.loadOrMint(idPath);
    id.save(idPath);
    const loaded = Identity.load(idPath);
    assert.equal(loaded.path, pathResolve(idPath));
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

test("Identity.prefs defaults to local/0 when fields absent from file", () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-prefs-"));
  try {
    const idPath = join(tmp, "identity.json");
    const id = Identity.loadOrMint(idPath);
    id.save(idPath);
    const loaded = Identity.load(idPath);
    assert.equal(loaded.prefs.defaultNewCeremonyMode, "local");
    assert.equal(loaded.prefsVersion, 0);
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

test("Identity.prefs reads back non-default values written by Python", () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-prefs2-"));
  try {
    const idPath = join(tmp, "identity.json");
    const id = Identity.loadOrMint(idPath);
    id.save(idPath);
    // Inject prefs into the file directly, mirroring what Python writes.
    const doc = JSON.parse(readFileSync(idPath, "utf8")) as Record<string, unknown>;
    doc["prefs"] = { default_new_ceremony_mode: "linked" };
    doc["prefs_version"] = 3;
    writeFileSync(idPath, JSON.stringify(doc, null, 2), "utf8");

    const loaded = Identity.load(idPath);
    assert.equal(loaded.prefs.defaultNewCeremonyMode, "linked");
    assert.equal(loaded.prefsVersion, 3);
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

test("readSyncQueue returns empty array when file absent", () => {
  const result = readSyncQueue("no-such-ceremony-id-xyz");
  assert.deepEqual(result, []);
});

test("readSyncQueue reads jsonl entries; syncQueuePath respects TN_STATE_DIR", () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-sq-"));
  const orig = process.env["TN_STATE_DIR"];
  try {
    process.env["TN_STATE_DIR"] = tmp;
    const ceremonyId = "test-ceremony-abc123";
    const queueDir = join(tmp, "sync_queue");
    mkdirSync(queueDir, { recursive: true });
    const qPath = walletInternals.syncQueuePath(ceremonyId);
    // syncQueuePath should use TN_STATE_DIR.
    assert.ok(qPath.startsWith(tmp), `expected path under ${tmp}, got ${qPath}`);
    writeFileSync(
      qPath,
      '{"ceremony_id":"test-ceremony-abc123","ts":"2026-01-01T00:00:00Z","error":"upload failed"}\n' +
        '{"ceremony_id":"test-ceremony-abc123","ts":"2026-01-02T00:00:00Z","error":"timeout"}\n',
      "utf-8",
    );
    const result = readSyncQueue(ceremonyId);
    assert.equal(result.length, 2);
    assert.equal(result[0]?.["error"], "upload failed");
    assert.equal(result[1]?.["error"], "timeout");
  } finally {
    if (orig === undefined) delete process.env["TN_STATE_DIR"];
    else process.env["TN_STATE_DIR"] = orig;
    rmSync(tmp, { recursive: true });
  }
});

// ── CLI subprocess tests ───────────────────────────────────────────────────

test("wallet status: no identity → informational message, exit 0", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-cli-noid-"));
  try {
    const result = await runCli(["wallet", "status"], { TN_IDENTITY_DIR: tmp });
    assert.equal(result.code, 0, `expected exit 0; stderr: ${result.stderr}`);
    assert.ok(
      result.stdout.includes("No identity"),
      `expected 'No identity' in output:\n${result.stdout}`,
    );
    assert.ok(
      result.stdout.includes("tn init"),
      `expected 'tn init' hint in output:\n${result.stdout}`,
    );
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

test("wallet status: identity only → prints DID, file, prefs", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-cli-id-"));
  try {
    const idPath = join(tmp, "identity.json");
    const id = Identity.loadOrMint(idPath);
    id.save(idPath);

    const result = await runCli(["wallet", "status"], { TN_IDENTITY_DIR: tmp });
    assert.equal(result.code, 0, `expected exit 0; stderr: ${result.stderr}`);
    assert.ok(result.stdout.includes("Identity:"), `missing 'Identity:' line\n${result.stdout}`);
    assert.ok(result.stdout.includes(id.did), `missing DID ${id.did}\n${result.stdout}`);
    assert.ok(result.stdout.includes("file:"), `missing 'file:' line\n${result.stdout}`);
    assert.ok(result.stdout.includes("linked:"), `missing 'linked:' line\n${result.stdout}`);
    assert.ok(result.stdout.includes("prefs:"), `missing 'prefs:' line\n${result.stdout}`);
    assert.ok(
      result.stdout.includes("default_new_ceremony_mode=local"),
      `expected default_new_ceremony_mode=local\n${result.stdout}`,
    );
    assert.ok(
      result.stdout.includes("prefs_version=0"),
      `expected prefs_version=0\n${result.stdout}`,
    );
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

test("wallet status: identity + yaml → prints ceremony fields", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-cli-yaml-"));
  try {
    const idPath = join(tmp, "identity.json");
    const id = Identity.loadOrMint(idPath);
    id.save(idPath);

    const yamlPath = join(tmp, "tn.yaml");
    const tn = await Tn.init(yamlPath);
    const cfg = tn.config() as Record<string, unknown>;
    const ceremonyId = cfg.ceremonyId as string;
    await tn.close();

    const result = await runCli(["wallet", "status", yamlPath], {
      TN_IDENTITY_DIR: tmp,
    });
    assert.equal(result.code, 0, `expected exit 0; stderr: ${result.stderr}`);
    assert.ok(result.stdout.includes("Ceremony:"), `missing 'Ceremony:' line\n${result.stdout}`);
    assert.ok(
      result.stdout.includes(ceremonyId),
      `missing ceremony id ${ceremonyId}\n${result.stdout}`,
    );
    assert.ok(result.stdout.includes("mode:"), `missing 'mode:' line\n${result.stdout}`);
    assert.ok(result.stdout.includes("cipher:"), `missing 'cipher:' line\n${result.stdout}`);
    assert.ok(result.stdout.includes("groups:"), `missing 'groups:' line\n${result.stdout}`);
    assert.ok(
      result.stdout.includes("pending_sync:"),
      `missing 'pending_sync:' line\n${result.stdout}`,
    );
    assert.ok(
      result.stdout.includes("(queue empty)"),
      `expected empty queue message\n${result.stdout}`,
    );
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

test("wallet status: missing yaml → graceful message, exit 0", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-cli-noyaml-"));
  try {
    const idPath = join(tmp, "identity.json");
    const id = Identity.loadOrMint(idPath);
    id.save(idPath);

    const missingYaml = join(tmp, "does-not-exist.yaml");
    const result = await runCli(["wallet", "status", missingYaml], {
      TN_IDENTITY_DIR: tmp,
    });
    assert.equal(result.code, 0, `expected exit 0; stderr: ${result.stderr}`);
    assert.ok(
      result.stdout.includes("no yaml at"),
      `expected 'no yaml at' message\n${result.stdout}`,
    );
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

test("wallet status: pending sync queue entries shown in output", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "ws-cli-pending-"));
  try {
    const idPath = join(tmp, "identity.json");
    const id = Identity.loadOrMint(idPath);
    id.save(idPath);

    const yamlPath = join(tmp, "tn.yaml");
    const tn = await Tn.init(yamlPath);
    const cfg = tn.config() as Record<string, unknown>;
    const ceremonyId = cfg.ceremonyId as string;
    await tn.close();

    // Write a fake sync queue entry using TN_STATE_DIR override.
    const stateDir = join(tmp, "state");
    const queueDir = join(stateDir, "sync_queue");
    mkdirSync(queueDir, { recursive: true });
    writeFileSync(
      join(queueDir, `${ceremonyId}.jsonl`),
      JSON.stringify({
        ceremony_id: ceremonyId,
        ts: "2026-01-01T00:00:00Z",
        error: "simulated upload failure",
      }) + "\n",
      "utf-8",
    );

    const result = await runCli(["wallet", "status", yamlPath], {
      TN_IDENTITY_DIR: tmp,
      TN_STATE_DIR: stateDir,
    });
    assert.equal(result.code, 0, `expected exit 0; stderr: ${result.stderr}`);
    assert.ok(
      result.stdout.includes("1 queued failure"),
      `expected '1 queued failure' in output:\n${result.stdout}`,
    );
    assert.ok(
      result.stdout.includes("simulated upload failure"),
      `expected latest error in output:\n${result.stdout}`,
    );
    assert.ok(
      result.stdout.includes("--drain-queue"),
      `expected drain-queue hint in output:\n${result.stdout}`,
    );
  } finally {
    rmSync(tmp, { recursive: true });
  }
});
