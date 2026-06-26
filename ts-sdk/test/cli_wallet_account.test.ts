// CLI-level tests for the new wallet + account wrappers.
//
// These exercise tn-js as a subprocess, mirroring how a real customer
// (or the tn-e2e harness) would invoke it. Live tests against the tne2e
// vault stack; skipped gracefully when the stack isn't reachable.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Tn } from "../src/tn.js";
import { parse as parseYaml } from "yaml";

const _here = dirname(fileURLToPath(import.meta.url));
const TN_JS_BIN = pathResolve(_here, "..", "bin", "tn-js.mjs");

const VAULT_URL = process.env.TN_TEST_VAULT_URL ?? "http://localhost:38790";

async function vaultReachable(): Promise<boolean> {
  try {
    const r = await fetch(`${VAULT_URL}/api/v1/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:key:z6MkProbe" }),
    });
    return r.ok || r.status === 400;
  } catch {
    return false;
  }
}
const reachable = await vaultReachable();

interface CliResult { stdout: string; stderr: string; code: number; }

async function runCli(args: string[], cwd: string = process.cwd()): Promise<CliResult> {
  return new Promise<CliResult>((resolve, reject) => {
    // Isolate the machine-global identity per subprocess. Otherwise the
    // account-connect signing-identity cascade (supplied > machine > ceremony)
    // resolves to the developer's REAL identity.json, which may already be
    // bound to another account → spurious 409s and cross-test coupling. An
    // empty TN_IDENTITY_DIR forces tier-3 (the ceremony keystore), giving each
    // seeded ceremony a fresh, unbound DID — what these tests assume.
    const proc = spawn("node", [TN_JS_BIN, ...args], {
      cwd,
      env: { ...process.env, TN_IDENTITY_DIR: join(cwd, ".tn-identity") },
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

async function seedCeremony(): Promise<{ tmp: string; yamlPath: string }> {
  const tmp = mkdtempSync(join(tmpdir(), "cli-wa-test-"));
  const yamlPath = join(tmp, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  await tn.close();
  return { tmp, yamlPath };
}

/** Mint a vault connect code by spinning up a dev-bypass account. */
async function mintConnectCode(handle: string): Promise<{ code: string; minterAccountId: string }> {
  const dl = await fetch(`${VAULT_URL}/api/v1/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle }),
  });
  if (!dl.ok) throw new Error(`dev/login ${dl.status}: ${await dl.text()}`);
  const { token, account_id: minterAccountId } = (await dl.json()) as { token: string; account_id: string };

  const mint = await fetch(`${VAULT_URL}/api/v1/account/connect-codes`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ project_name: `cli-port-${Date.now()}` }),
  });
  if (!mint.ok) throw new Error(`mint ${mint.status}: ${await mint.text()}`);
  const minted = (await mint.json()) as { code?: string };
  if (!minted.code) throw new Error(`mint missing code: ${JSON.stringify(minted)}`);
  return { code: minted.code, minterAccountId };
}

// ── wallet link ──────────────────────────────────────────────────────

test("tn-js wallet link — exits 0, prints receipt, mutates yaml to linked", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const r = await runCli([
      "wallet", "link", VAULT_URL,
      "--yaml", yamlPath,
      "--name", `cli-port-link-${Date.now()}`,
      "--json",
    ], tmp);
    assert.equal(r.code, 0, `wallet link should exit 0; stderr=${r.stderr}`);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.ok, true);
    assert.equal(out.verb, "wallet.link");
    assert.equal(out.vault_base_url, VAULT_URL);
    assert.equal(out.newly_linked, true);
    assert.ok(typeof out.project_id === "string" && out.project_id.length > 0);

    // Yaml mutation persisted.
    const doc = parseYaml(readFileSync(yamlPath, "utf-8")) as { ceremony: Record<string, unknown> };
    assert.equal(doc.ceremony.mode, "linked");
    assert.equal(doc.ceremony.linked_vault, VAULT_URL);
    assert.equal(doc.ceremony.linked_project_id, out.project_id);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js wallet link — second invocation is idempotent (newly_linked=false)", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const args = ["wallet", "link", VAULT_URL, "--yaml", yamlPath, "--name", `cli-port-idem-${Date.now()}`, "--json"];
    const first = await runCli(args, tmp);
    assert.equal(first.code, 0);
    const second = await runCli(args, tmp);
    assert.equal(second.code, 0, `second wallet link must exit 0; stderr=${second.stderr}`);
    const out = JSON.parse(second.stdout.trim());
    assert.equal(out.newly_linked, false, "second link to same vault must be a no-op");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js wallet link — DEFAULT output is human-readable, not JSON", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const r = await runCli([
      "wallet", "link", VAULT_URL,
      "--yaml", yamlPath,
      "--name", `cli-port-link-human-${Date.now()}`,
    ], tmp);
    assert.equal(r.code, 0, `wallet link should exit 0; stderr=${r.stderr}`);
    assert.ok(!r.stdout.trimStart().startsWith("{"), `human output must not start with '{': ${r.stdout.slice(0, 60)}`);
    assert.throws(() => JSON.parse(r.stdout.trim()), "human output must not be valid JSON");
    assert.match(r.stdout, /^Linked /m, "expected 'Linked ...' human line");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js wallet link — missing positional errors with hint", async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const r = await runCli(["wallet", "link", "--yaml", yamlPath], tmp);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /vault-url|positional/i);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js wallet unlink — flips yaml back to local", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    // Link first.
    await runCli(["wallet", "link", VAULT_URL, "--yaml", yamlPath, "--name", `cli-port-unlink-${Date.now()}`], tmp);
    // Now unlink (structured output behind --json).
    const r = await runCli(["wallet", "unlink", "--yaml", yamlPath, "--json"], tmp);
    assert.equal(r.code, 0, `wallet unlink should exit 0; stderr=${r.stderr}`);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.verb, "wallet.unlink");

    // DEFAULT (no --json) unlink output is human-readable.
    await runCli(["wallet", "link", VAULT_URL, "--yaml", yamlPath, "--name", `cli-port-unlink2-${Date.now()}`], tmp);
    const human = await runCli(["wallet", "unlink", "--yaml", yamlPath], tmp);
    assert.equal(human.code, 0, `wallet unlink (human) should exit 0; stderr=${human.stderr}`);
    assert.ok(!human.stdout.trimStart().startsWith("{"), `human output must not start with '{': ${human.stdout.slice(0, 60)}`);
    assert.throws(() => JSON.parse(human.stdout.trim()), "human output must not be valid JSON");
    assert.match(human.stdout, /^Unlinked /m, "expected 'Unlinked ...' human line");

    const doc = parseYaml(readFileSync(yamlPath, "utf-8")) as { ceremony: Record<string, unknown> };
    assert.equal(doc.ceremony.mode, "local");
    assert.equal(doc.ceremony.linked_vault, "");
    assert.equal(doc.ceremony.linked_project_id, "");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── account connect ─────────────────────────────────────────────────

test("tn-js account connect — exits 0, prints receipt, persists account_id to sync state", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const { code, minterAccountId } = await mintConnectCode(`cli-acc-${Date.now()}`);
    const r = await runCli([
      "account", "connect", code,
      "--yaml", yamlPath,
      "--vault", VAULT_URL,
      "--json",
    ], tmp);
    assert.equal(r.code, 0, `account connect should exit 0; stderr=${r.stderr}`);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.ok, true);
    assert.equal(out.verb, "account.connect");
    assert.equal(out.account_id, minterAccountId, "redeemed account must match minter");
    assert.ok(typeof out.did === "string" && out.did.startsWith("did:"));

    // Sync state file persisted.
    const statePath = join(tmp, ".tn", "sync", "state.json");
    const state = JSON.parse(readFileSync(statePath, "utf-8")) as Record<string, unknown>;
    assert.equal(state.account_id, minterAccountId);
    assert.equal(state.account_bound, true);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js account connect — DEFAULT output is human-readable, not JSON", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const { code, minterAccountId } = await mintConnectCode(`cli-acc-human-${Date.now()}`);
    const r = await runCli([
      "account", "connect", code,
      "--yaml", yamlPath,
      "--vault", VAULT_URL,
    ], tmp);
    assert.equal(r.code, 0, `account connect should exit 0; stderr=${r.stderr}`);
    assert.ok(!r.stdout.trimStart().startsWith("{"), `human output must not start with '{': ${r.stdout.slice(0, 60)}`);
    assert.throws(() => JSON.parse(r.stdout.trim()), "human output must not be valid JSON");
    assert.match(r.stdout, new RegExp(`^Connected to vault account ${minterAccountId}`, "m"));
    assert.match(r.stdout, /^\s+did:\s+did:/m, "expected human did line");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js account connect — invalid code surfaces 404 via non-zero exit", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const r = await runCli([
      "account", "connect", "tn_connect_definitely_not_real_xyz",
      "--yaml", yamlPath,
      "--vault", VAULT_URL,
    ], tmp);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /status=404|404|connect/i);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js account connect — missing positional errors", async () => {
  const { tmp, yamlPath } = await seedCeremony();
  try {
    const r = await runCli(["account", "connect", "--yaml", yamlPath, "--vault", VAULT_URL], tmp);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /code|positional/i);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("wallet restore --mnemonic refuses to overwrite an existing identity without --force", async () => {
  // Parity with Python cli_wallet (identity_path.exists() and not args.force
  // -> _die(... code=2)). Identity-only restore (no --vault) so no vault is
  // needed; runCli isolates TN_IDENTITY_DIR to <cwd>/.tn-identity.
  const tmp = mkdtempSync(join(tmpdir(), "tn-restore-force-"));
  const phrase =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  try {
    // First restore: no identity yet, writes identity.json, exit 0.
    const first = await runCli(["wallet", "restore", "--mnemonic", phrase], tmp);
    assert.equal(first.code, 0, first.stderr);
    // Second restore without --force: must refuse with exit 2 and not overwrite.
    const second = await runCli(["wallet", "restore", "--mnemonic", phrase], tmp);
    assert.equal(second.code, 2, `expected exit 2, got ${second.code}: ${second.stderr}`);
    assert.match(second.stderr, /already exists.*--force/s);
    // With --force it proceeds (exit 0).
    const forced = await runCli(["wallet", "restore", "--mnemonic", phrase, "--force"], tmp);
    assert.equal(forced.code, 0, forced.stderr);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
