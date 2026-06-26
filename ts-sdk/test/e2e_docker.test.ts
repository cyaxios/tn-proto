// TS-native end-to-end suite — the Node twin of the Python tn-e2e
// scenarios, driving `tn-js` as a subprocess against the live tne2e docker
// vault stack (mongo + vault + admin on localhost:38790). Skipped gracefully
// when the stack isn't reachable, so it's safe in CI (no vault) and runs for
// real locally (docker up).
//
// Mirrors the headline guarantees the Python suite asserts:
//   1. init emits a claim URL + flipped .tn/<name>/ layout (vault on by default)
//   2. init --no-link mints with NO claim URL
//   3. warm-attach: init -> account connect -> init attaches (no browser), shared DID
//   4. add-recipient (group-add) works first try
//
// Per-test identity isolation (TN_IDENTITY_DIR + XDG_DATA_HOME under a fresh
// scratch dir) so a stamped linked_account_id can't leak across tests — the
// same isolation the Python harness conftest enforces.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse as parseYaml } from "yaml";

const _here = dirname(fileURLToPath(import.meta.url));
const TN_JS_BIN = pathResolve(_here, "..", "bin", "tn-js.mjs");
const VAULT_URL = process.env["TN_TEST_VAULT_URL"] ?? "http://localhost:38790";

const _CLAIM_URL_RE =
  /https?:\/\/[a-z0-9.\-:]+\/claim\/[0-9A-HJKMNP-TV-Z]{26}#k=[A-Za-z0-9_-]{43}/;

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
const gate = { skip: !reachable && "tne2e docker vault not reachable" };

interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

/** Fresh project root + isolated identity dir for one scenario. */
function scratch(): { root: string; env: Record<string, string> } {
  const base = mkdtempSync(join(tmpdir(), "tnjs-e2e-"));
  const root = join(base, "proj");
  mkdirSync(root, { recursive: true });
  return {
    root,
    env: {
      ...process.env,
      TN_IDENTITY_DIR: join(base, "id"),
      XDG_DATA_HOME: join(base, "xdg"),
      TN_VAULT_URL: VAULT_URL,
    } as Record<string, string>,
  };
}

function runCli(args: string[], cwd: string, env: Record<string, string>): Promise<CliResult> {
  return new Promise<CliResult>((resolve, reject) => {
    const proc = spawn("node", [TN_JS_BIN, ...args], { cwd, env });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

// Mongo back door: read the vault's DB directly to prove the write landed,
// not just that the CLI printed a happy receipt. Uses `docker exec` + mongosh
// in the tne2e-mongo container (dep-free — no mongodb driver needed). Returns
// null if docker/mongosh/the container isn't available, so the DB assertions
// are best-effort (the CLI-level asserts still gate the test).
const MONGO_CONTAINER = process.env["TN_E2E_MONGO_CONTAINER"] ?? "tne2e-mongo";
const VAULT_DB = process.env["TN_E2E_VAULT_DB"] ?? "tn_vault_e2e";

function mongoReachable(): boolean {
  const r = spawnSync(
    "docker",
    ["exec", MONGO_CONTAINER, "mongosh", VAULT_DB, "--quiet", "--eval", "1"],
    { encoding: "utf8" },
  );
  return r.status === 0;
}
const _mongoOk = mongoReachable();

function mongoFindOne(collection: string, query: Record<string, unknown>): Record<string, unknown> | null {
  const evalJs = `JSON.stringify(db.${collection}.findOne(${JSON.stringify(query)}))`;
  const r = spawnSync(
    "docker",
    ["exec", MONGO_CONTAINER, "mongosh", VAULT_DB, "--quiet", "--eval", evalJs],
    { encoding: "utf8" },
  );
  if (r.status !== 0 || !r.stdout) return null;
  const out = r.stdout.trim();
  if (!out || out === "null") return null;
  try {
    return JSON.parse(out) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function jsonReceipt(stdout: string): Record<string, unknown> | null {
  for (const line of stdout.trim().split(/\r?\n/).reverse()) {
    const s = line.trim();
    if (s.startsWith("{") && s.endsWith("}")) {
      try {
        return JSON.parse(s) as Record<string, unknown>;
      } catch {
        /* keep scanning */
      }
    }
  }
  return null;
}

async function mintConnectCode(handle: string): Promise<{ code: string; accountId: string }> {
  const dl = await fetch(`${VAULT_URL}/api/v1/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle }),
  });
  if (!dl.ok) throw new Error(`dev/login ${dl.status}`);
  const { token, account_id: accountId } = (await dl.json()) as { token: string; account_id: string };
  const mint = await fetch(`${VAULT_URL}/api/v1/account/connect-codes`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ project_name: `e2e-${Date.now()}` }),
  });
  if (!mint.ok) throw new Error(`mint ${mint.status}`);
  const { code } = (await mint.json()) as { code: string };
  return { code, accountId };
}

// ── 1. init emits a claim URL + flipped layout (vault on by default) ──────
test("e2e: tn-js init emits a claim URL + flipped .tn/<name>/ layout", gate, async () => {
  const { root, env } = scratch();
  const r = await runCli(["init", "E2eProj", "--json"], root, env);
  assert.equal(r.code, 0, `init exit nonzero; stderr=${r.stderr}`);

  // Flipped layout with its own keystore.
  const yamlPath = join(root, ".tn", "E2eProj", "tn.yaml");
  assert.ok(existsSync(yamlPath), `expected ${yamlPath}`);
  assert.ok(existsSync(join(root, ".tn", "E2eProj", "keys", "local.private")));

  // Claim URL emitted (vault on by default) + carried on the receipt.
  assert.ok(_CLAIM_URL_RE.test(r.stdout), `no claim URL in stdout: ${r.stdout.slice(-200)}`);
  const receipt = jsonReceipt(r.stdout);
  assert.ok(receipt && typeof receipt["claim_url"] === "string");
  assert.ok(_CLAIM_URL_RE.test(receipt!["claim_url"] as string));

  // project_name stamped for the vault label.
  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as { ceremony?: { project_name?: string } };
  assert.equal(doc.ceremony?.project_name, "E2eProj");

  // BACK DOOR: the pending-claim must actually exist in the vault's mongo,
  // carrying the project_name the SDK sent via X-Project-Name — what the CLI
  // receipt alone can't prove (a stale vault prints a claim URL but stores no
  // project_name). Best-effort: skips if docker/mongosh isn't available.
  const vaultId = (receipt!["claim_url"] as string).split("/claim/")[1]!.split("#")[0]!;
  if (_mongoOk) {
    const row = mongoFindOne("pending_claims", { _id: vaultId });
    assert.ok(row, `vault DB must have a pending_claims row for ${vaultId}`);
    assert.equal(row!["project_name"], "E2eProj", "vault DB pending_claim.project_name");
    assert.ok(row!["body_b64"], "vault DB pending_claim has encrypted body");
  }
});

// ── 2. init --no-link mints with NO claim URL ─────────────────────────────
test("e2e: tn-js init --no-link mints without a claim URL", gate, async () => {
  const { root, env } = scratch();
  const r = await runCli(["init", "OfflineProj", "--no-link", "--json"], root, env);
  assert.equal(r.code, 0, `init --no-link exit nonzero; stderr=${r.stderr}`);
  assert.ok(existsSync(join(root, ".tn", "OfflineProj", "tn.yaml")));
  assert.ok(!_CLAIM_URL_RE.test(r.stdout), "no-link must not emit a claim URL");
  const receipt = jsonReceipt(r.stdout);
  assert.equal(receipt?.["claim_url"], undefined);
});

// ── 3. warm-attach: init -> connect -> init attaches (no browser) ─────────
test("e2e: warm-attach attaches a new project with no browser (shared DID)", gate, async () => {
  const { root, env } = scratch();

  // init A (cold) — emits a claim URL.
  const a = await runCli(["init", "ProjA", "--json"], root, env);
  assert.equal(a.code, 0, `init A nonzero; ${a.stderr}`);
  const didA = jsonReceipt(a.stdout)?.["did"];

  // Mint + redeem a connect code (stamps linked_account_id on the global id).
  const { code, accountId } = await mintConnectCode(`e2e-warm-${Date.now()}`);
  const yamlA = join(root, ".tn", "ProjA", "tn.yaml");
  const c = await runCli(["account", "connect", code, "--yaml", yamlA, "--vault", VAULT_URL, "--json"], root, env);
  assert.equal(c.code, 0, `connect nonzero; ${c.stderr}`);
  assert.equal(jsonReceipt(c.stdout)?.["account_id"], accountId);
  assert.equal(jsonReceipt(c.stdout)?.["global_identity_stamped"], true);

  // init B — should WARM-ATTACH (no claim URL), sharing A's device DID.
  const b = await runCli(["init", "ProjB", "--json"], root, env);
  assert.equal(b.code, 0, `init B nonzero; ${b.stderr}`);
  assert.ok(
    b.stdout.includes("Attached to your vault account"),
    `expected warm attach; got: ${b.stdout.slice(-300)}`,
  );
  const receiptB = jsonReceipt(b.stdout);
  assert.equal(receiptB?.["attached"], true);
  assert.equal(receiptB?.["did"], didA, "ProjA and ProjB must share one device DID");

  // BACK DOOR: warm-attach must actually bind a project to the account in the
  // vault's mongo (account_projects), with the device DID in publishers —
  // proving "Attached" is real DB state, not stdout. Best-effort.
  if (_mongoOk) {
    const ap = mongoFindOne("account_projects", { account_id: accountId });
    assert.ok(ap, `vault DB must have an account_projects row for ${accountId}`);
    assert.ok(
      JSON.stringify(ap!["publishers"] ?? "").includes(String(didA)),
      "vault DB account_projects publishers should include the device DID",
    );
  }
});

// ── 4. add-recipient (group-add) works first try ─────────────────────────
test("e2e: tn-js admin add-recipient mints a kit first try", gate, async () => {
  const { root, env } = scratch();
  const init = await runCli(["init", "GroupProj", "--no-link"], root, env);
  assert.equal(init.code, 0, `init nonzero; ${init.stderr}`);
  const yamlPath = join(root, ".tn", "GroupProj", "tn.yaml");
  const kitPath = join(root, "alice.btn.mykit");

  const add = await runCli(
    ["admin", "add-recipient", "--yaml", yamlPath, "--group", "default", "--out", kitPath],
    root,
    env,
  );
  assert.equal(add.code, 0, `add-recipient exit nonzero; stderr=${add.stderr}`);
  assert.ok(existsSync(kitPath), `expected kit at ${kitPath}`);
});
