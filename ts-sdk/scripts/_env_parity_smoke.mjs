// Node-side smoke for the env-var parity work.
//
// Verifies every TN_* env var the Python SDK honors has a working TS
// equivalent (or is documented N/A). Run after `npm run build`:
//
//   node scripts/_env_parity_smoke.mjs

// Initialize the wasm before any DeviceKey / wasm-backed call. The
// nodejs pkg target ships initSync; we feed it the .wasm bytes
// directly so we don't depend on the default `fetch` path (which
// errors on file:// URLs under Node).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve as pathResolve } from "node:path";
import { initSync } from "tn-wasm";

const __here = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(
  pathResolve(__here, "..", "..", "crypto", "tn-wasm", "pkg", "tn_wasm_bg.wasm"),
);
initSync({ module: wasmBytes });

import {
  Tn,
  parseBearer,
  resolveVaultUrl,
  resolveDidEndpoint,
  isAutoLinkDisabled,
  bootstrapFromApiKey,
  UnsealNotWiredError,
  DEFAULT_VAULT_URL,
} from "../dist/index.js";

let failures = 0;
function assert(cond, msg) {
  if (cond) {
    console.log(`  PASS  ${msg}`);
  } else {
    console.log(`  FAIL  ${msg}`);
    failures += 1;
  }
}

// ---- TN_STRICT --------------------------------------------------------

console.log("\nTN_STRICT");
delete process.env.TN_STRICT;
Tn.clearStrict();
assert(Tn.isStrict() === false, "no env + no override -> false");

process.env.TN_STRICT = "1";
assert(Tn.isStrict() === true, "TN_STRICT=1 -> true");

process.env.TN_STRICT = "yes";
assert(Tn.isStrict() === true, "TN_STRICT=yes -> true");

process.env.TN_STRICT = "  TRUE  ";
assert(Tn.isStrict() === true, "TN_STRICT='  TRUE  ' -> true (trim+lowercase)");

process.env.TN_STRICT = "off";
assert(Tn.isStrict() === false, "TN_STRICT=off -> false");

process.env.TN_STRICT = "1";
Tn.setStrict(false);
assert(Tn.isStrict() === false, "setStrict(false) wins over TN_STRICT=1");

Tn.clearStrict();
assert(Tn.isStrict() === true, "clearStrict() falls back to env -> true again");

delete process.env.TN_STRICT;
Tn.clearStrict();

// ---- TN_RUN_ID --------------------------------------------------------

console.log("\nTN_RUN_ID");
delete process.env.TN_RUN_ID;
const { ensureProcessRunId, _resetProcessRunIdForTests } = await import("../dist/_run_id.js");
_resetProcessRunIdForTests();
const r1 = ensureProcessRunId();
assert(typeof r1 === "string" && r1.length === 32,
  `ensureProcessRunId() returns a 32-char hex (${r1.slice(0, 8)}...)`);
assert(process.env.TN_RUN_ID === r1,
  `ensureProcessRunId() stamps process.env.TN_RUN_ID`);

// Singleton: second call returns the same id, even if env got cleared.
delete process.env.TN_RUN_ID;
const r2 = ensureProcessRunId();
assert(r2 === r1, "second call returns the same singleton run id");
assert(process.env.TN_RUN_ID === r1, "re-stamps env defensively");

// Inherited stale env doesn't win — we overwrite.
_resetProcessRunIdForTests();
process.env.TN_RUN_ID = "stale-parent-shell-run-id";
const r3 = ensureProcessRunId();
assert(r3 !== "stale-parent-shell-run-id",
  "inherited TN_RUN_ID does NOT silently join the parent's run");
assert(process.env.TN_RUN_ID === r3, "env stamped with fresh value, not the stale one");

// ---- TN_VAULT_URL -----------------------------------------------------

console.log("\nTN_VAULT_URL");
delete process.env.TN_VAULT_URL;
assert(resolveVaultUrl() === DEFAULT_VAULT_URL,
  `no env -> DEFAULT_VAULT_URL (${DEFAULT_VAULT_URL})`);

process.env.TN_VAULT_URL = "http://localhost:8790";
assert(resolveVaultUrl() === "http://localhost:8790",
  "TN_VAULT_URL=http://localhost:8790 -> http://localhost:8790");

assert(resolveVaultUrl("https://override.example.com") === "https://override.example.com",
  "explicit arg wins over env");

delete process.env.TN_VAULT_URL;

// ---- TN_VAULT_DEFAULT_BASE -------------------------------------------

console.log("\nTN_VAULT_DEFAULT_BASE");
delete process.env.TN_VAULT_DEFAULT_BASE;
{
  const ep = await resolveDidEndpoint("did:key:z6MkfakeDidKeyForTest123");
  assert(ep === DEFAULT_VAULT_URL,
    `did:key + no env -> DEFAULT_VAULT_URL`);
}

// (resolveDidEndpoint memoizes per-DID; use a fresh DID for the next test)
process.env.TN_VAULT_DEFAULT_BASE = "http://localhost:8790/";
{
  const ep = await resolveDidEndpoint("did:key:z6MkfakeDidKeyForTest456");
  assert(ep === "http://localhost:8790",
    "did:key + TN_VAULT_DEFAULT_BASE=...localhost:8790/ -> http://localhost:8790 (trailing slash stripped)");
}

delete process.env.TN_VAULT_DEFAULT_BASE;

// ---- TN_NO_LINK -------------------------------------------------------

console.log("\nTN_NO_LINK");
delete process.env.TN_NO_LINK;
assert(isAutoLinkDisabled() === false, "no env -> false");

process.env.TN_NO_LINK = "1";
assert(isAutoLinkDisabled() === true, "TN_NO_LINK=1 -> true");

process.env.TN_NO_LINK = "yes";
assert(isAutoLinkDisabled() === false, "TN_NO_LINK=yes -> false (only '1' matches Python)");

delete process.env.TN_NO_LINK;

// ---- TN_API_KEY -- parseBearer ---------------------------------------

console.log("\nTN_API_KEY -- parseBearer");
assert(parseBearer("") === null, "empty -> null");
assert(parseBearer("not_a_bearer") === null, "wrong prefix -> null");
assert(parseBearer("tn_apikey_short") === null, "too short -> null");

// Construct a syntactically-valid bearer: 32-byte seed + 16-byte key id.
{
  const seed = new Uint8Array(32);
  const kid = new Uint8Array(16);
  for (let i = 0; i < 32; i++) seed[i] = i;
  for (let i = 0; i < 16; i++) kid[i] = 100 + i;
  const b64url = (b) =>
    Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const bearer = `tn_apikey_${b64url(seed)}_${b64url(kid)}`;
  const parsed = parseBearer(bearer);
  assert(parsed !== null, "valid bearer -> non-null");
  assert(parsed && parsed.seed.length === 32, "seed is 32 bytes");
  assert(parsed && parsed.keyIdBytes.length === 16, "keyIdBytes is 16 bytes");
  assert(parsed && parsed.keyIdB64 === b64url(kid), "keyIdB64 round-trips");
}

// ---- TN_API_KEY -- bootstrapFromApiKey (network half) ----------------

console.log("\nTN_API_KEY -- bootstrapFromApiKey");
delete process.env.TN_API_KEY;
{
  const r = await bootstrapFromApiKey({ vaultDid: "did:key:z6Mkfake" });
  assert(r === null, "no TN_API_KEY -> null");
}

process.env.TN_API_KEY = "not_a_bearer";
{
  const r = await bootstrapFromApiKey({ vaultDid: "did:key:z6Mkfake" });
  assert(r === null, "malformed TN_API_KEY -> null");
}

// End-to-end with a fake fetch. We stub `globalThis.fetch` to capture
// the auth + sealed-bundle round-trip and confirm the function gets
// all the way to UnsealNotWiredError (proving every env-var-honoring
// step ran).
{
  const seed = new Uint8Array(32);
  const kid = new Uint8Array(16);
  for (let i = 0; i < 32; i++) seed[i] = i;
  for (let i = 0; i < 16; i++) kid[i] = 200 + i;
  const b64url = (b) =>
    Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  process.env.TN_API_KEY = `tn_apikey_${b64url(seed)}_${b64url(kid)}`;
  process.env.TN_VAULT_DEFAULT_BASE = "http://fake.vault.invalid";

  const captured = [];
  globalThis.fetch = async (url, init) => {
    captured.push({ url: String(url), method: init?.method ?? "GET" });
    if (url.endsWith("/api/v1/auth/challenge")) {
      return new Response(JSON.stringify({ nonce: "test-nonce" }), { status: 200 });
    }
    if (url.endsWith("/api/v1/auth/verify")) {
      return new Response(JSON.stringify({ token: "fake-jwt" }), { status: 200 });
    }
    if (String(url).includes("/sealed-bundle")) {
      // Return a placeholder "sealed bundle". Real bytes don't matter
      // here; we just need the function to reach the throw point.
      return new Response(JSON.stringify({
        sealed_bundle_b64: Buffer.from("fake-sealed-bundle-bytes").toString("base64"),
        kind: "project_seed",
      }), { status: 200 });
    }
    return new Response("", { status: 404 });
  };

  // The fake sealed bundle isn't a real tnpkg — the absorb step will
  // reject it with a "not a valid `.tnpkg` zip" reason, but only AFTER
  // every env-var-honoring network call has fired. That's what we're
  // proving here: the env vars (TN_API_KEY, TN_VAULT_DEFAULT_BASE)
  // drove a complete /auth/challenge -> /auth/verify -> /sealed-bundle
  // round-trip with the right Bearer + URL.
  const result = await bootstrapFromApiKey({ vaultDid: "did:key:z6MkfakeBootstrap" });
  assert(result !== null,
    "bootstrapFromApiKey returned a result (not null fallthrough)");
  if (result !== null) {
    assert(result.did.startsWith("did:key:z"),
      `result.did is a did:key (${result.did.slice(0, 24)}...)`);
    assert(result.vaultBase === "http://fake.vault.invalid",
      `result.vaultBase respects TN_VAULT_DEFAULT_BASE`);
    assert(result.sealedBytes.length > 0,
      `result.sealedBytes carries the fetched bundle (${result.sealedBytes.length}B)`);
    assert(result.kind === "project_seed",
      `result.kind matches server response`);
    assert(result.receipt !== undefined,
      `result.receipt is populated (shape verified by _sealed_absorb_smoke.mjs)`);
    assert(typeof result.receipt.rejectedReason === "string",
      `result.receipt.rejectedReason populated (fake sealed bundle is not a real tnpkg, so absorb rejects — expected)`);
  }
  assert(captured.length === 3,
    `fired 3 network calls (got ${captured.length}: ${captured.map(c => c.method + " " + c.url.replace("http://fake.vault.invalid", "")).join(", ")})`);

  delete process.env.TN_API_KEY;
  delete process.env.TN_VAULT_DEFAULT_BASE;
}

// ---- Report -----------------------------------------------------------

console.log(`\n${failures === 0 ? "smoke PASSED" : `smoke FAILED -- ${failures} assertion(s)`}`);
process.exit(failures === 0 ? 0 : 1);
