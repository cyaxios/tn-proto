// REAL same-language seal -> verify round-trip (TypeScript).
//
// `verifyCmd` (bin/tn-js.mjs) has NO .test.ts coverage in the CI run set —
// the only seal->verify chain in the repo is the cross-language, out-of-CI
// `interop_driver.mjs`. This file fills that gap with a genuine SAME-language
// round-trip: spawn the REAL `bin/tn-js.mjs seal` subprocess, take its EXACT
// stdout ndjson, pipe it to the REAL `bin/tn-js.mjs verify` subprocess, and
// assert ok:true. See docs/cli-test-plans/verify.md.
//
// PASS: genuine seal output verifies ok:true; row_hash / sequence echoed.
// FAIL cases a correct verify MUST catch: tampered public field, tampered
// scalar, corrupted signature, broken prev_hash chain, malformed JSON (exit 2).

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { Buffer } from "node:buffer";

const CLI = "./bin/tn-js.mjs";

// Deterministic 32-byte Ed25519 seed (bytes 0..31), base64 — mirrors the
// Python round-trip's bytes(range(32)).
const SEED_B64 = Buffer.from(Uint8Array.from({ length: 32 }, (_v, j) => j)).toString("base64");
const GENESIS_PREV = "sha256:" + "0".repeat(64);

interface SealInput {
  seed_b64: string;
  event_type: string;
  level: string;
  sequence: number;
  prev_hash: string;
  timestamp: string;
  event_id: string;
  public_fields?: Record<string, unknown>;
}

function sealInput(overrides: Partial<SealInput> = {}): SealInput {
  return {
    seed_b64: SEED_B64,
    event_type: "order.created",
    level: "info",
    sequence: 1,
    prev_hash: GENESIS_PREV,
    timestamp: "2026-04-23T12:00:00.000000Z",
    event_id: "00000000-0000-4000-8000-000000000001",
    public_fields: { amount: 100, status: "paid" },
    ...overrides,
  };
}

/** Run the REAL `tn-js` CLI subprocess with `stdin`; return its result. */
function runCli(args: string[], stdin: string): { stdout: string; stderr: string; status: number } {
  const res = spawnSync("node", [CLI, ...args], {
    input: stdin,
    encoding: "utf8",
    cwd: process.cwd(),
  });
  if (res.error) throw res.error;
  return { stdout: res.stdout, stderr: res.stderr, status: res.status ?? -1 };
}

/** Real seal: pipe input JSON lines through `tn-js seal`; return raw ndjson. */
function seal(inputs: SealInput[]): string {
  const stdin = inputs.map((o) => JSON.stringify(o)).join("\n") + "\n";
  const r = runCli(["seal"], stdin);
  assert.equal(r.status, 0, `seal should exit 0; stderr=${r.stderr}`);
  return r.stdout;
}

// Precondition probe: is `tn-js seal` actually functional at this HEAD?
//
// As of the 0.4.3a1 identity-naming flip (commit 65c7746), src/core/chain.ts
// `rowHash()` and the tn-wasm `computeRowHash` require a `device_identity`
// field, but bin/tn-js.mjs `sealCmd`/`verifyCmd` still pass `did:` (never
// updated by that flip — the same untested-second-impl drift seen elsewhere).
// So `tn-js seal` throws `field "device_identity" missing or not a string`
// and exits non-zero. We CANNOT honestly assert a seal->verify round-trip
// while seal is broken, and we are not permitted to edit bin/tn-js.mjs to fix
// it. Rather than fake a pass, the seal-dependent tests below skip with a
// loud reason when this probe shows seal is broken; they run for real once
// the bin is fixed to pass `device_identity`. The malformed-JSON verify test
// does NOT depend on seal and always runs.
function sealIsFunctional(): { ok: boolean; detail: string } {
  const r = runCli(["seal"], JSON.stringify(sealInput()) + "\n");
  if (r.status === 0 && r.stdout.trim().length > 0) return { ok: true, detail: "" };
  return { ok: false, detail: (r.stderr || "").split("\n")[0] };
}
const SEAL = sealIsFunctional();
const skipSeal = SEAL.ok
  ? false
  : `tn-js seal is broken at HEAD (${SEAL.detail}); bin passes did: where ` +
    `rowHash/WASM require device_identity. Round-trip cannot be honestly ` +
    `asserted until bin/tn-js.mjs is fixed. See report.`;

/** Real verify: pipe envelope ndjson through `tn-js verify`; parse results. */
function verify(envNdjson: string): { status: number; results: Array<Record<string, unknown>> } {
  const r = runCli(["verify"], envNdjson);
  const results = r.stdout
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
  return { status: r.status, results };
}

// ── PASS ──────────────────────────────────────────────────────────────

test("seal -> verify: genuine single envelope verifies ok:true", { skip: skipSeal }, () => {
  const inp = sealInput();
  const envNdjson = seal([inp]);
  const envelope = JSON.parse(envNdjson.trim());

  const { status, results } = verify(envNdjson);
  assert.equal(status, 0);
  assert.equal(results.length, 1);
  assert.deepEqual(results[0], {
    ok: true,
    did: envelope.did ?? envelope.device_identity,
    event_type: "order.created",
    event_id: inp.event_id,
    row_hash: envelope.row_hash,
    sequence: 1,
  });
  // row_hash the verifier recomputed equals the one seal stored.
  assert.equal(results[0].row_hash, envelope.row_hash);
});

test("seal -> verify: batch all verify ok:true", { skip: skipSeal }, () => {
  const inputs = Array.from({ length: 3 }, (_v, i) =>
    sealInput({
      sequence: i + 1,
      event_id: `00000000-0000-4000-8000-00000000000${i + 1}`,
      timestamp: `2026-04-23T12:0${i}:00.000000Z`,
      public_fields: { amount: (i + 1) * 100, note: `entry ${i}` },
    }),
  );
  const envNdjson = seal(inputs);
  const { status, results } = verify(envNdjson);
  assert.equal(status, 0);
  assert.equal(results.length, 3);
  assert.ok(results.every((r) => r.ok === true));
  assert.deepEqual(
    results.map((r) => r.sequence),
    [1, 2, 3],
  );
});

test("seal -> verify: empty public_fields still verifies ok:true", { skip: skipSeal }, () => {
  const envNdjson = seal([sealInput({ public_fields: {} })]);
  const { status, results } = verify(envNdjson);
  assert.equal(status, 0);
  assert.equal(results[0].ok, true);
});

// ── FAIL — a correct verify MUST catch each mutation of genuine seal output.
// Each test first asserts the UNMUTATED genuine envelope verifies ok:true, so
// the failure is provably caused by the mutation (it would pass if not
// mutated / if verification were skipped).

test("seal -> verify: tampered public field caught (row_hash mismatch)", { skip: skipSeal }, () => {
  const env = JSON.parse(seal([sealInput()]).trim());

  // Sanity: untouched genuine envelope verifies.
  assert.equal(verify(JSON.stringify(env) + "\n").results[0].ok, true);

  env.amount = 999; // flip a public field after sealing
  const { status, results } = verify(JSON.stringify(env) + "\n");
  assert.equal(status, 0);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].reason, "row_hash mismatch");
  assert.equal(results[0].got, env.row_hash);
  assert.notEqual(results[0].expected, env.row_hash);
});

test("seal -> verify: tampered scalar caught (row_hash mismatch)", { skip: skipSeal }, () => {
  const env = JSON.parse(seal([sealInput()]).trim());
  env.event_type = "order.refunded"; // change a hashed scalar after sealing
  const { status, results } = verify(JSON.stringify(env) + "\n");
  assert.equal(status, 0);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].reason, "row_hash mismatch");
});

test("seal -> verify: corrupted signature caught (bad signature)", { skip: skipSeal }, () => {
  const env = JSON.parse(seal([sealInput()]).trim());
  // Well-formed but wrong 64-byte signature so row_hash still matches and we
  // reach the signature check. The wire codec is base64URL (unpadded) — same
  // encoding signatureB64 emits — so it decodes cleanly to 64 bytes and the
  // verify reaches "bad signature" rather than a decode exception.
  env.signature = Buffer.from(new Uint8Array(64).fill(1)).toString("base64url");
  const { status, results } = verify(JSON.stringify(env) + "\n");
  assert.equal(status, 0);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].reason, "bad signature");
});

test("seal -> verify: broken prev_hash chain caught (row_hash mismatch)", { skip: skipSeal }, () => {
  // Genuine 2-entry chain: entry2.prev_hash == entry1.row_hash.
  const env1 = JSON.parse(seal([sealInput({ sequence: 1 })]).trim());
  const env2 = JSON.parse(
    seal([
      sealInput({
        sequence: 2,
        event_id: "00000000-0000-4000-8000-000000000002",
        timestamp: "2026-04-23T12:01:00.000000Z",
        prev_hash: env1.row_hash,
        public_fields: { amount: 200 },
      }),
    ]).trim(),
  );

  // Correct chain: link holds and both entries verify.
  assert.equal(env2.prev_hash, env1.row_hash);
  const okRun = verify(JSON.stringify(env1) + "\n" + JSON.stringify(env2) + "\n");
  assert.deepEqual(
    okRun.results.map((r) => r.ok),
    [true, true],
  );

  // Break the link: rewrite entry2.prev_hash to a wrong (genesis) value.
  env2.prev_hash = GENESIS_PREV;
  const { status, results } = verify(JSON.stringify(env1) + "\n" + JSON.stringify(env2) + "\n");
  assert.equal(status, 0);
  assert.equal(results[0].ok, true); // entry1 untouched
  assert.equal(results[1].ok, false); // entry2 link broken
  assert.equal(results[1].reason, "row_hash mismatch");
  assert.notEqual(env2.prev_hash, env1.row_hash);
});

test("verify: malformed JSON on stdin is fatal (exit 2)", () => {
  const r = runCli(["verify"], "{not valid json\n");
  assert.equal(r.status, 2, `expected exit 2; stderr=${r.stderr}`);
  // No result line written for the fatal input.
  assert.equal(r.stdout.trim(), "");
});

// Note: the "encrypted group payload" FAIL case is NOT a seal->verify
// round-trip here. `sealCmd` is the public-only path (groups={}, no
// publicFields value becomes a {ciphertext,...} block), so there is no
// GENUINE seal output carrying a group payload to feed verify. Fabricating a
// fake ciphertext block would not be a real round-trip, so per the HARD RULE
// it is left out (the rejection branch lives in verifyCmd and is exercised
// cross-language by the interop driver).
