// In-process coverage for the `tn wallet sync` CLI verb
// (src/cli/wallet_sync.ts), the TypeScript parity port of Python's
// `cmd_wallet_sync` + `_pull_absorb_step` + `_stage_account_inbox` +
// `_cmd_wallet_sync_pull` on the SUPPORTED AWK/BEK whole-body model.
//
// Hermetic: a real btn ceremony is stood up per test via `Tn.init` (so the
// pull/absorb + push legs hit the real NodeRuntime / keystore), a temp
// machine-global identity.json is seeded via `Identity`, and the vault is a
// mock `fetch` that answers the DID auth dance plus every account route the
// verb touches (account/inbox, inbox snapshot, wrapped-key GET/PUT,
// credentials GET, encrypted-blob GET, encrypted-blob-account PUT). No live
// vault, no subprocess — so c8 sees every line.
//
// The mock's credential + wrapped-key material is built with the REAL
// awk_bek primitives (deriveCredentialKeyPbkdf2 / wrapBytes under the two
// pinned AADs), so the derive-BEK and mint-BEK paths run actual crypto — a
// wrong AAD or KDF mismatch would fail the unwrap, not silently pass.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { Identity } from "../src/identity.js";
import { walletSyncCmd } from "../src/cli/wallet_sync.js";
import {
  AAD_AWK_WRAP,
  AAD_BEK_WRAP,
  deriveCredentialKeyPbkdf2,
} from "../src/vault/awk_bek.js";
import { importEmk, wrapBytes } from "../src/core/emk.js";
import { bytesToB64, b64ToBytes, randomBytes } from "../src/core/encoding.js";

const PASSPHRASE = "correct horse battery staple";
const PBKDF2_ITERS = 20_000; // >= the 10000 floor awk_bek enforces

interface Sink {
  text(): string;
  write(s: string): void;
}
function sink(): Sink {
  let buf = "";
  return { write: (s: string) => { buf += s; }, text: () => buf };
}

/** Stand up a fresh btn ceremony in its own temp dir. */
async function freshCeremony(prefix: string): Promise<{ dir: string; yamlPath: string; did: string }> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const yamlPath = join(dir, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  const did = tn.did;
  await tn.close();
  return { dir, yamlPath, did };
}

/** Export a real kit_bundle `.tnpkg` (fromDid=exporter) for `recipientDid`. */
async function exportKitBundle(yamlPath: string, outPath: string, recipientDid: string): Promise<void> {
  const tn = await Tn.init(yamlPath);
  try {
    await tn.pkg.export({ bundle: { recipientDid, groups: ["default"] } }, outPath);
  } finally {
    await tn.close();
  }
}

/** Seed a temp machine-global identity.json. */
function seedIdentity(dir: string): string {
  const identityPath = join(dir, "identity.json");
  Identity.loadOrMint(identityPath);
  return identityPath;
}

/** Patch the ceremony yaml's `ceremony:` block to mark it linked. */
function markLinked(yamlPath: string, vault: string, projectId: string): void {
  let text = readFileSync(yamlPath, "utf8");
  // The Tn.init yaml already carries `mode:`, `linked_vault:`, and
  // `linked_project_id:` keys in its `ceremony:` block — replace each line
  // in place (appending would create duplicate keys the yaml parser rejects).
  text = text.replace(/^(\s*)mode:.*$/m, `$1mode: linked`);
  text = text.replace(/^(\s*)linked_vault:.*$/m, `$1linked_vault: ${vault}`);
  text = text.replace(/^(\s*)linked_project_id:.*$/m, `$1linked_project_id: ${projectId}`);
  writeFileSync(yamlPath, text, "utf8");
}

/** Stamp account_bound=true into the ceremony's sync-state sidecar. */
function markAccountBound(yamlPath: string, dir: string): void {
  // stemDir for `<dir>/tn.yaml` is `<dir>/.tn/tn`; state at sync/state.json.
  const stateDir = join(dir, ".tn", "tn", "sync");
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, "state.json"), JSON.stringify({ account_bound: true }), "utf8");
}

/** Build a PBKDF2 credential row + (optionally) a wrapped BEK under the AWK,
 *  using the real awk_bek primitives so the verb's unwrap actually runs. */
async function buildVaultMaterial(opts: { withWrappedBek: boolean }): Promise<{
  cred: Record<string, unknown>;
  wrappedKey: Record<string, unknown> | null;
  awk: Uint8Array;
  bek: Uint8Array | null;
}> {
  const salt = randomBytes(16);
  const awk = randomBytes(32);
  const credKey = await deriveCredentialKeyPbkdf2(PASSPHRASE, salt, PBKDF2_ITERS);
  const awkWrap = await wrapBytes(credKey, awk, AAD_AWK_WRAP);
  const cred = {
    kdf: "pbkdf2-sha256",
    kdf_params: { salt_b64: bytesToB64(salt), iterations: PBKDF2_ITERS },
    wrapped_account_key_b64: awkWrap.ciphertext_b64,
    wrap_nonce_b64: awkWrap.nonce_b64,
    is_primary: true,
  };

  let wrappedKey: Record<string, unknown> | null = null;
  let bek: Uint8Array | null = null;
  if (opts.withWrappedBek) {
    bek = randomBytes(32);
    const bekWrap = await wrapBytes(await importEmk(awk), bek, AAD_BEK_WRAP);
    wrappedKey = { wrapped_bek_b64: bekWrap.ciphertext_b64, wrap_nonce_b64: bekWrap.nonce_b64 };
  }
  return { cred, wrappedKey, awk, bek };
}

/** A recorded call against the mock vault. */
interface Recorded {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
}

/** Build a mock fetch + a call log. Routes are matched by URL suffix. */
function mockVault(opts: {
  inboxItems?: Record<string, unknown>[];
  snapshotBytes?: Uint8Array;
  cred?: Record<string, unknown>;
  wrappedKey?: Record<string, unknown> | null;
  encryptedBlob?: Record<string, unknown> | { __status: number };
  inboxStatus?: number;
}): { fetchImpl: typeof fetch; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const u = String(url);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = (init?.headers ?? {}) as Record<string, string>;
    let body: unknown = undefined;
    if (typeof init?.body === "string") {
      try { body = JSON.parse(init.body); } catch { body = init.body; }
    }
    calls.push({ method, path: u, body, headers });

    if (u.endsWith("/api/v1/auth/challenge")) {
      return new Response(JSON.stringify({ nonce: "nonce-xyz" }), { status: 200 });
    }
    if (u.endsWith("/api/v1/auth/verify")) {
      return new Response(JSON.stringify({ token: "jwt-token" }), { status: 200 });
    }
    if (u.endsWith("/api/v1/account/inbox")) {
      if (opts.inboxStatus && opts.inboxStatus >= 400) {
        return new Response("no", { status: opts.inboxStatus });
      }
      return new Response(JSON.stringify({ items: opts.inboxItems ?? [] }), { status: 200 });
    }
    if (u.includes("/api/v1/account/inbox/")) {
      return new Response(opts.snapshotBytes ?? new Uint8Array(), { status: 200 });
    }
    if (u.endsWith("/wrapped-key") && method === "GET") {
      if (opts.wrappedKey == null) return new Response("not found", { status: 404 });
      return new Response(JSON.stringify(opts.wrappedKey), { status: 200 });
    }
    if (u.endsWith("/wrapped-key") && method === "PUT") {
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (u.includes("/api/v1/account/credentials")) {
      return new Response(JSON.stringify([opts.cred]), { status: 200 });
    }
    if (u.endsWith("/encrypted-blob") && method === "GET") {
      const eb = opts.encryptedBlob;
      if (eb && typeof eb === "object" && "__status" in eb) {
        return new Response("x", { status: (eb as { __status: number }).__status });
      }
      return new Response(JSON.stringify(eb ?? {}), { status: 200 });
    }
    if (u.endsWith("/encrypted-blob-account") && method === "PUT") {
      return new Response(JSON.stringify({ generation: 1 }), { status: 200 });
    }
    throw new Error(`unexpected fetch ${method} ${u}`);
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

// ── --pull (stage only) ──────────────────────────────────────────────

test("wallet sync --pull stages inbox snapshots without absorbing (exit 0)", async () => {
  const acct = await freshCeremony("ts-wsync-pull-acct-");
  const peer = await freshCeremony("ts-wsync-pull-peer-");
  const dir = acct.dir;
  try {
    markAccountBound(acct.yamlPath, dir);
    const identityPath = seedIdentity(dir);

    // A real kit_bundle .tnpkg as the snapshot body.
    const pkg = join(peer.dir, "snap.tnpkg");
    await exportKitBundle(peer.yamlPath, pkg, acct.did);
    const snapshotBytes = new Uint8Array(readFileSync(pkg));

    const { fetchImpl, calls } = mockVault({
      inboxItems: [
        { publisher_identity: peer.did, ceremony_id: "cer_peer", ts: "2026-06-05T00:00:00Z" },
        { publisher_identity: peer.did, ceremony_id: "cer_peer", ts: "consumed", consumed_at: "yes" },
      ],
      snapshotBytes,
    });

    const out = sink();
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath,
      pull: true,
      vault: "https://vault.example",
      identityPath,
      fetchImpl,
      stdout: out,
      stderr: err,
    });

    assert.equal(code, 0, `stderr=${err.text()}`);
    assert.match(out.text(), /staged -> /);
    assert.match(out.text(), /Pulled 1 snapshot\(s\); run `tn absorb <path>`/);
    // The consumed item was skipped (only 1 download).
    assert.equal(calls.filter((c) => c.path.includes("/account/inbox/")).length, 1);

    // Idempotent: a second --pull skips the already-staged file.
    const out2 = sink();
    const code2 = await walletSyncCmd({
      yaml: acct.yamlPath, pull: true, vault: "https://vault.example",
      identityPath, fetchImpl, stdout: out2, stderr: sink(),
    });
    assert.equal(code2, 0);
    assert.match(out2.text(), /Pulled 0 snapshot\(s\)/);
    assert.match(out2.text(), /\(1 already staged locally and skipped\)/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
    rmSync(peer.dir, { recursive: true, force: true });
  }
});

test("wallet sync --pull on an unbound, unlinked ceremony dies exit 2", async () => {
  const acct = await freshCeremony("ts-wsync-pull-unbound-");
  try {
    const identityPath = seedIdentity(acct.dir);
    const { fetchImpl } = mockVault({});
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath, pull: true, vault: "https://vault.example",
      identityPath, fetchImpl, stdout: sink(), stderr: err,
    });
    assert.equal(code, 2);
    assert.match(err.text(), /no account binding for this ceremony/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

// ── bare sync: pull+absorb then push (mint-BEK path) ──────────────────

test("bare wallet sync: pull+absorb then push, minting a fresh BEK (exit 0)", async () => {
  const acct = await freshCeremony("ts-wsync-bare-acct-");
  const peer = await freshCeremony("ts-wsync-bare-peer-");
  try {
    const dir = acct.dir;
    markLinked(acct.yamlPath, "https://vault.example", "proj_01");
    markAccountBound(acct.yamlPath, dir);
    const identityPath = seedIdentity(dir);

    const pkg = join(peer.dir, "snap.tnpkg");
    await exportKitBundle(peer.yamlPath, pkg, acct.did);
    const snapshotBytes = new Uint8Array(readFileSync(pkg));

    const { cred } = await buildVaultMaterial({ withWrappedBek: false });
    const { fetchImpl, calls } = mockVault({
      inboxItems: [{ publisher_identity: peer.did, ceremony_id: "cer_peer", ts: "2026-06-05T00:00:01Z" }],
      snapshotBytes,
      cred,
      wrappedKey: null, // 404 -> mint path
      encryptedBlob: { __status: 404 }, // no blob yet -> If-Match: *
    });

    const out = sink();
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath,
      passphrase: PASSPHRASE,
      vault: "https://vault.example",
      identityPath,
      fetchImpl,
      stdout: out,
      stderr: err,
    });

    assert.equal(code, 0, `stderr=${err.text()}`);
    assert.match(out.text(), /pulled\+absorbed 1 snapshot\(s\)/);
    assert.match(out.text(), /Synced .* -> https:\/\/vault\.example/);
    assert.match(out.text(), /uploaded \d+ files: \[/);

    // The mint path PUT the wrapped-key, then PUT the encrypted body with
    // If-Match: * (first write).
    const wkPut = calls.find((c) => c.path.endsWith("/wrapped-key") && c.method === "PUT");
    assert.ok(wkPut, "expected a wrapped-key PUT on the mint path");
    const blobPut = calls.find((c) => c.path.endsWith("/encrypted-blob-account") && c.method === "PUT");
    assert.ok(blobPut, "expected an encrypted-blob-account PUT");
    assert.equal(blobPut!.headers["If-Match"], "*");
    // The body frame round-trips: ciphertext_b64 is the whole nonce||ct frame.
    const ct = (blobPut!.body as Record<string, unknown>)["ciphertext_b64"];
    assert.equal(typeof ct, "string");
    assert.ok(b64ToBytes(ct as string).length > 12 + 16, "frame carries nonce+ct+tag");
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
    rmSync(peer.dir, { recursive: true, force: true });
  }
});

// ── --push-only: derive existing BEK, If-Match from generation ────────

test("wallet sync --push-only derives the existing BEK and uses the blob generation", async () => {
  const acct = await freshCeremony("ts-wsync-push-");
  try {
    const dir = acct.dir;
    markLinked(acct.yamlPath, "https://vault.example", "proj_02");
    const identityPath = seedIdentity(dir);

    const { cred, wrappedKey } = await buildVaultMaterial({ withWrappedBek: true });
    const { fetchImpl, calls } = mockVault({
      cred,
      wrappedKey, // present -> derive path
      encryptedBlob: { generation: 7 }, // existing blob -> If-Match: 7
    });

    const out = sink();
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath,
      pushOnly: true,
      passphrase: PASSPHRASE,
      vault: "https://vault.example",
      identityPath,
      fetchImpl,
      stdout: out,
      stderr: err,
    });

    assert.equal(code, 0, `stderr=${err.text()}`);
    // push-only skips the pull/absorb line.
    assert.doesNotMatch(out.text(), /pulled\+absorbed/);
    assert.match(out.text(), /Synced .* -> https:\/\/vault\.example/);
    // Derive path: NO wrapped-key PUT (the row already exists).
    assert.equal(calls.filter((c) => c.path.endsWith("/wrapped-key") && c.method === "PUT").length, 0);
    const blobPut = calls.find((c) => c.path.endsWith("/encrypted-blob-account") && c.method === "PUT");
    assert.equal(blobPut!.headers["If-Match"], "7");
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

// ── --drain-queue: push with the drain banner ─────────────────────────

test("wallet sync --drain-queue pushes and prints the drain banner", async () => {
  const acct = await freshCeremony("ts-wsync-drain-");
  try {
    const dir = acct.dir;
    markLinked(acct.yamlPath, "https://vault.example", "proj_03");
    const identityPath = seedIdentity(dir);

    const { cred, wrappedKey } = await buildVaultMaterial({ withWrappedBek: true });
    const { fetchImpl } = mockVault({ cred, wrappedKey, encryptedBlob: { generation: 2 } });

    const out = sink();
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath,
      drainQueue: true,
      passphrase: PASSPHRASE,
      vault: "https://vault.example",
      identityPath,
      fetchImpl,
      stdout: out,
      stderr: err,
    });

    assert.equal(code, 0, `stderr=${err.text()}`);
    assert.match(out.text(), /Drained sync queue for /);
    assert.match(out.text(), /uploaded \d+ files/);
    assert.doesNotMatch(out.text(), /pulled\+absorbed/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

// ── not-linked handling ───────────────────────────────────────────────

test("bare sync on an account-bound but UNLINKED ceremony: pull/merge skipped + push skipped, exit 0", async () => {
  const acct = await freshCeremony("ts-wsync-unlinked-bound-");
  try {
    const dir = acct.dir;
    markAccountBound(acct.yamlPath, dir); // bound but NOT linked
    const identityPath = seedIdentity(dir);

    // Inbox returns 401 -> stageAccountInbox yields null -> pull/merge skipped.
    const { fetchImpl } = mockVault({ inboxStatus: 401 });

    const out = sink();
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath,
      vault: "https://vault.example",
      identityPath,
      fetchImpl,
      stdout: out,
      stderr: err,
    });

    assert.equal(code, 0, `stderr=${err.text()}`);
    assert.match(out.text(), /pull\/merge skipped: ceremony not bound to a vault account/);
    assert.match(out.text(), /push skipped: ceremony not linked to a vault/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

test("--push-only on an unlinked ceremony dies (nothing to push)", async () => {
  const acct = await freshCeremony("ts-wsync-pushonly-unlinked-");
  try {
    const identityPath = seedIdentity(acct.dir);
    const { fetchImpl } = mockVault({});
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath, pushOnly: true, passphrase: PASSPHRASE,
      vault: "https://vault.example", identityPath, fetchImpl, stdout: sink(), stderr: err,
    });
    assert.equal(code, 1);
    assert.match(err.text(), /is not linked; nothing to push/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

test("bare sync on an unlinked, unbound ceremony dies (nothing to sync)", async () => {
  const acct = await freshCeremony("ts-wsync-unlinked-unbound-");
  try {
    const identityPath = seedIdentity(acct.dir);
    const { fetchImpl } = mockVault({});
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath, passphrase: PASSPHRASE,
      vault: "https://vault.example", identityPath, fetchImpl, stdout: sink(), stderr: err,
    });
    assert.equal(code, 1);
    assert.match(err.text(), /not linked and not account-bound/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

// ── push without a passphrase dies ────────────────────────────────────

test("linked sync without --passphrase dies", async () => {
  const acct = await freshCeremony("ts-wsync-nopass-");
  try {
    markLinked(acct.yamlPath, "https://vault.example", "proj_04");
    const identityPath = seedIdentity(acct.dir);
    const { fetchImpl } = mockVault({});
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath, pushOnly: true,
      vault: "https://vault.example", identityPath, fetchImpl, stdout: sink(), stderr: err,
    });
    assert.equal(code, 1);
    assert.match(err.text(), /--passphrase required/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

test("linked ceremony missing linked_project_id dies (relink to repair)", async () => {
  const acct = await freshCeremony("ts-wsync-noproj-");
  try {
    // Mark linked but blank out linked_project_id so the repair guard fires.
    markLinked(acct.yamlPath, "https://vault.example", "");
    const identityPath = seedIdentity(acct.dir);
    const { fetchImpl } = mockVault({});
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath, pushOnly: true, passphrase: PASSPHRASE,
      vault: "https://vault.example", identityPath, fetchImpl, stdout: sink(), stderr: err,
    });
    assert.equal(code, 1);
    assert.match(err.text(), /has no linked_project_id; relink to repair/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});

// ── yaml discovery / error paths ──────────────────────────────────────

test("missing explicit --yaml dies with the not-found message", async () => {
  const err = sink();
  const code = await walletSyncCmd({
    yaml: join(tmpdir(), "definitely-missing-tn.yaml"),
    stdout: sink(),
    stderr: err,
  });
  assert.equal(code, 1);
  assert.match(err.text(), /yaml not found:/);
});

test("default stdout/stderr sinks (smoke: no sink args, missing yaml -> exit 1)", async () => {
  // No stdout/stderr passed -> exercises the `?? process.std*` defaults.
  // A missing explicit --yaml short-circuits to exit 1 with no network.
  const code = await walletSyncCmd({ yaml: join(tmpdir(), "no-such-tn.yaml") });
  assert.equal(code, 1);
});

test("a non-absorbable staged snapshot is tolerated; the merge still completes", async () => {
  // A snapshot whose bytes aren't a valid kit_bundle yields a rejected
  // receipt (acceptedCount 0) rather than aborting — covering the
  // conflict-iteration loop for a zero-accept snapshot alongside a good one.
  const acct = await freshCeremony("ts-wsync-mixed-");
  const peer = await freshCeremony("ts-wsync-mixed-peer-");
  try {
    const dir = acct.dir;
    markAccountBound(acct.yamlPath, dir);
    const identityPath = seedIdentity(dir);

    const good = join(peer.dir, "good.tnpkg");
    await exportKitBundle(peer.yamlPath, good, acct.did);
    const goodBytes = new Uint8Array(readFileSync(good));
    // An empty STORED zip — parseable as a zip but carries no manifest body.
    const emptyZip = new Uint8Array([0x50, 0x4b, 0x05, 0x06, ...new Array(18).fill(0)]);

    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const u = String(url);
      if (u.endsWith("/api/v1/auth/challenge")) return new Response(JSON.stringify({ nonce: "n" }), { status: 200 });
      if (u.endsWith("/api/v1/auth/verify")) return new Response(JSON.stringify({ token: "t" }), { status: 200 });
      if (u.endsWith("/api/v1/account/inbox")) {
        return new Response(JSON.stringify({ items: [
          { publisher_identity: peer.did, ceremony_id: "cer_g", ts: "2026-06-05T01:00:00Z" },
          { publisher_identity: peer.did, ceremony_id: "cer_e", ts: "2026-06-05T01:00:01Z" },
        ] }), { status: 200 });
      }
      if (u.includes("/api/v1/account/inbox/")) {
        return new Response(u.includes("cer_g") ? goodBytes : emptyZip, { status: 200 });
      }
      throw new Error(`unexpected ${u}`);
    }) as unknown as typeof fetch;

    const out = sink();
    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath, vault: "https://vault.example",
      identityPath, fetchImpl, stdout: out, stderr: err,
    });
    assert.equal(code, 0, `stderr=${err.text()}`);
    assert.match(out.text(), /pulled\+absorbed 2 snapshot\(s\)/);
    assert.match(out.text(), /push skipped: ceremony not linked/);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
    rmSync(peer.dir, { recursive: true, force: true });
  }
});

test("push error (bad PUT) surfaces as a die exit 1", async () => {
  const acct = await freshCeremony("ts-wsync-puterr-");
  try {
    markLinked(acct.yamlPath, "https://vault.example", "proj_05");
    const identityPath = seedIdentity(acct.dir);
    const { cred, wrappedKey } = await buildVaultMaterial({ withWrappedBek: true });

    // Override the encrypted-blob-account PUT to 500.
    const base = mockVault({ cred, wrappedKey, encryptedBlob: { generation: 1 } });
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const u = String(url);
      const method = (init?.method ?? "GET").toUpperCase();
      if (u.endsWith("/encrypted-blob-account") && method === "PUT") {
        return new Response("boom", { status: 500 });
      }
      return base.fetchImpl(url, init);
    }) as unknown as typeof fetch;

    const err = sink();
    const code = await walletSyncCmd({
      yaml: acct.yamlPath, pushOnly: true, passphrase: PASSPHRASE,
      vault: "https://vault.example", identityPath, fetchImpl, stdout: sink(), stderr: err,
    });
    assert.equal(code, 1);
    assert.match(err.text(), /push failed for /);
  } finally {
    rmSync(acct.dir, { recursive: true, force: true });
  }
});
