// Unit tests for the `tn wallet pull-prefs` CLI verb (src/cli/wallet_pull_prefs.ts),
// the TS parity port of Python's cmd_wallet_pull_prefs.
//
// These are hermetic: a fresh temp identity.json is seeded via Identity, the
// vault is a mock fetch driving the DID challenge/verify dance plus
// GET /api/v1/account/prefs, and stdout/stderr are captured to in-memory
// sinks. No live vault, no subprocess — so c8 sees every line of the verb.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Identity } from "../src/identity.js";
import { walletPullPrefsCmd } from "../src/cli/wallet_pull_prefs.js";

const VAULT_URL = "https://vault.example";

/** Collect writes into a single string. */
function sink(): { write(s: string): void; text(): string } {
  let buf = "";
  return { write: (s: string) => { buf += s; }, text: () => buf };
}

/** Seed a fresh, valid identity.json in a temp dir. Returns its path + dir. */
function seedIdentity(opts: { linkedVault?: string | null } = {}): { dir: string; identityPath: string } {
  const dir = mkdtempSync(join(tmpdir(), "cli-pullprefs-"));
  const identityPath = join(dir, "identity.json");
  const id = Identity.loadOrMint(identityPath);
  if (opts.linkedVault !== undefined) {
    id.linkedVault = opts.linkedVault;
    id.save(identityPath);
  }
  return { dir, identityPath };
}

/**
 * Build a mock fetch that answers the auth dance + the prefs GET. `prefs` is
 * the JSON body returned by GET /account/prefs; `prefsStatus` lets a test
 * force an error response.
 */
function mockFetch(opts: {
  prefs?: Record<string, unknown>;
  prefsStatus?: number;
  onPrefs?: (req: { headers: Record<string, string> }) => void;
}): typeof fetch {
  const prefs = opts.prefs ?? { default_new_ceremony_mode: "per-recipient", prefs_version: 7 };
  return (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const u = String(url);
    const headers = (init?.headers ?? {}) as Record<string, string>;
    if (u.endsWith("/api/v1/auth/challenge")) {
      return new Response(JSON.stringify({ nonce: "test-nonce-123" }), { status: 200 });
    }
    if (u.endsWith("/api/v1/auth/verify")) {
      return new Response(JSON.stringify({ token: "test-jwt-token" }), { status: 200 });
    }
    if (u.endsWith("/api/v1/account/prefs")) {
      opts.onPrefs?.({ headers });
      if (opts.prefsStatus && opts.prefsStatus >= 400) {
        return new Response("nope", { status: opts.prefsStatus });
      }
      return new Response(JSON.stringify(prefs), { status: 200 });
    }
    throw new Error(`unexpected fetch to ${u}`);
  }) as unknown as typeof fetch;
}

test("wallet pull-prefs — happy path: pulls, persists to identity.json, prints 3 lines, exit 0", async () => {
  const { dir, identityPath } = seedIdentity();
  try {
    const out = sink();
    const err = sink();
    let authHeader: string | undefined;
    const fetchImpl = mockFetch({
      prefs: { default_new_ceremony_mode: "per-recipient", prefs_version: 9 },
      onPrefs: ({ headers }) => { authHeader = headers.Authorization; },
    });

    const code = await walletPullPrefsCmd({
      vault: VAULT_URL,
      identityPath,
      fetchImpl,
      stdout: out,
      stderr: err,
    });

    assert.equal(code, 0);
    assert.equal(err.text(), "");
    // The prefs GET carried the bearer token the auth dance minted.
    assert.equal(authHeader, "Bearer test-jwt-token");

    // stdout: exactly the three Python lines.
    assert.equal(
      out.text(),
      `Pulled prefs from ${VAULT_URL}:\n` +
        `  default_new_ceremony_mode: per-recipient\n` +
        `  prefs_version: 9\n`,
    );

    // identity.json persisted the two fields (prefs nested, version top-level).
    const reloaded = Identity.load(identityPath);
    assert.equal(reloaded.prefs.defaultNewCeremonyMode, "per-recipient");
    assert.equal(reloaded.prefsVersion, 9);
    const rawDoc = JSON.parse(readFileSync(identityPath, "utf8")) as Record<string, unknown>;
    assert.equal((rawDoc["prefs"] as Record<string, unknown>)["default_new_ceremony_mode"], "per-recipient");
    assert.equal(rawDoc["prefs_version"], 9);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wallet pull-prefs — falls back to identity.linked_vault when --vault omitted", async () => {
  const { dir, identityPath } = seedIdentity({ linkedVault: VAULT_URL });
  try {
    const out = sink();
    const fetchImpl = mockFetch({ prefs: { default_new_ceremony_mode: "per-project", prefs_version: 2 } });

    const code = await walletPullPrefsCmd({ identityPath, fetchImpl, stdout: out });

    assert.equal(code, 0);
    assert.match(out.text(), new RegExp(`Pulled prefs from ${VAULT_URL.replace(/\./g, "\\.")}:`));
    assert.match(out.text(), /default_new_ceremony_mode: per-project/);
    assert.match(out.text(), /prefs_version: 2/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wallet pull-prefs — no vault anywhere: dies with Python's message, exit 1", async () => {
  const { dir, identityPath } = seedIdentity({ linkedVault: null });
  try {
    const out = sink();
    const err = sink();

    const code = await walletPullPrefsCmd({ identityPath, stdout: out, stderr: err });

    assert.equal(code, 1);
    assert.equal(out.text(), "");
    assert.match(err.text(), /--vault <url> required \(no vault cached in identity\.json\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wallet pull-prefs — prefs GET 4xx surfaces an error", async () => {
  const { dir, identityPath } = seedIdentity();
  try {
    const fetchImpl = mockFetch({ prefsStatus: 403 });
    await assert.rejects(
      walletPullPrefsCmd({ vault: VAULT_URL, identityPath, fetchImpl, stdout: sink(), stderr: sink() }),
      /GET \/api\/v1\/account\/prefs returned 403/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wallet pull-prefs — prefs GET 4xx with unreadable body still errors (catch branch)", async () => {
  const { dir, identityPath } = seedIdentity();
  try {
    // A 4xx Response whose .text() throws, exercising the body-read catch.
    const fetchImpl = (async (url: string | URL | Request): Promise<Response> => {
      const u = String(url);
      if (u.endsWith("/api/v1/auth/challenge")) {
        return new Response(JSON.stringify({ nonce: "n" }), { status: 200 });
      }
      if (u.endsWith("/api/v1/auth/verify")) {
        return new Response(JSON.stringify({ token: "t" }), { status: 200 });
      }
      // Build a 500 response, then sabotage its body reader.
      const resp = new Response("x", { status: 500 });
      Object.defineProperty(resp, "text", {
        value: () => Promise.reject(new Error("body stream broke")),
      });
      return resp;
    }) as unknown as typeof fetch;

    await assert.rejects(
      walletPullPrefsCmd({ vault: VAULT_URL, identityPath, fetchImpl, stdout: sink(), stderr: sink() }),
      /GET \/api\/v1\/account\/prefs returned 500/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wallet pull-prefs — preserves an existing prefs object's sibling keys", async () => {
  const { dir, identityPath } = seedIdentity();
  try {
    // Inject a sibling key under prefs that the verb must not clobber.
    const doc = JSON.parse(readFileSync(identityPath, "utf8")) as Record<string, unknown>;
    doc["prefs"] = { default_new_ceremony_mode: "local", some_future_field: "keepme" };
    writeFileSync(identityPath, JSON.stringify(doc, null, 2), "utf8");

    const out = sink();
    const fetchImpl = mockFetch({ prefs: { default_new_ceremony_mode: "per-recipient", prefs_version: 4 } });
    const code = await walletPullPrefsCmd({ vault: VAULT_URL, identityPath, fetchImpl, stdout: out });

    assert.equal(code, 0);
    const reloaded = JSON.parse(readFileSync(identityPath, "utf8")) as Record<string, unknown>;
    const prefs = reloaded["prefs"] as Record<string, unknown>;
    assert.equal(prefs["default_new_ceremony_mode"], "per-recipient");
    assert.equal(prefs["some_future_field"], "keepme", "sibling pref key must survive");
    assert.equal(reloaded["prefs_version"], 4);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Subprocess test: the bin wrapper must intercept `--help` and print usage
// rather than dialing the vault (which throws an uncaught `fetch failed`
// ECONNREFUSED when no host is reachable). This guards the regression where
// `--help` fell through the arg parser straight into walletPullPrefsCmd.
test("wallet pull-prefs --help — bin wrapper prints usage, exits clean, no stack trace", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const binPath = join(here, "..", "bin", "tn-js.mjs");

  const res = spawnSync(process.execPath, [binPath, "wallet", "pull-prefs", "--help"], {
    encoding: "utf8",
  });

  // Exited cleanly via process.exit, not via an uncaught throw.
  assert.equal(res.status, 0, `expected exit 0, got ${res.status}; stderr:\n${res.stderr}`);
  // No uncaught error / stack trace leaked to stderr.
  assert.doesNotMatch(res.stderr, /fetch failed|ECONNREFUSED|at \w|TypeError|Node\.js v/);
  // Usage line printed to stdout.
  assert.match(res.stdout, /usage: tn wallet pull-prefs/);
});

test("wallet pull-prefs — default stdout/stderr sinks (smoke: no sink args)", async () => {
  const { dir, identityPath } = seedIdentity({ linkedVault: null });
  try {
    // No stdout/stderr passed -> exercises the `?? process.std*` defaults.
    // linked_vault=null + no --vault -> exit 1 without touching the network.
    const code = await walletPullPrefsCmd({ identityPath });
    assert.equal(code, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
