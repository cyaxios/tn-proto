// Phase C interop harness. Proves byte-for-byte round-trip between
// tn-js (WASM-backed) and the Python `tn` reference.
//
//   1. Generate a batch of seal inputs (deterministic seeds, fixed
//      timestamps, fixed event_ids).
//   2. Pipe them through tn-js seal. Capture the ndjson output.
//   3. Pipe the same inputs through python tn_py_helper.py seal.
//   4. Diff the two ndjson outputs. If they differ by a single byte,
//      the bindings are out of sync.
//   5. Have Python verify TS output; have TS verify Python output.
//      Both sides must accept both sides' envelopes.
//
// The harness runs with no filesystem state: everything is pipes and
// in-memory strings. Run with:
//
//   node test/interop_driver.mjs
//   bash test/interop_driver.sh   # same, resolves python via venv

import { spawnSync } from "node:child_process";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { existsSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const jsCli = join(tsRoot, "bin", "tn-js.mjs");
const pyHelper = join(here, "tn_py_helper.py");

function resolvePython() {
  const fromEnv = process.env.TN_PYTHON;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const candidates = [
    resolve(tsRoot, "../../.venv/Scripts/python.exe"),
    resolve(tsRoot, "../../.venv/bin/python"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return "python";
}
const PYTHON = resolvePython();

function runPipe(bin, args, input) {
  const res = spawnSync(bin, args, { input, encoding: "utf8" });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(`${bin} ${args.join(" ")} exited ${res.status}: ${res.stderr}`);
  }
  return res.stdout;
}

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}

// Deterministic inputs
const inputs = [];
for (let i = 0; i < 3; i += 1) {
  const seed = new Uint8Array(32);
  for (let j = 0; j < 32; j += 1) seed[j] = (i * 17 + j) & 0xff;
  inputs.push({
    seed_b64: b64(seed),
    event_type: "order.created",
    level: "info",
    sequence: i + 1,
    prev_hash:
      i === 0
        ? "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        : "sha256:" + "a".repeat(64),
    timestamp: `2026-04-23T12:0${i}:00Z`,
    event_id: `00000000-0000-0000-0000-00000000000${i + 1}`,
    public_fields: { amount: (i + 1) * 100, status: "paid", note: `entry ${i}` },
  });
}
const sealStdin = inputs.map((o) => JSON.stringify(o)).join("\n") + "\n";

console.log(`== Seal ${inputs.length} entries on both sides ==`);
const jsEnv = runPipe("node", [jsCli, "seal"], sealStdin);
const pyEnv = runPipe(PYTHON, [pyHelper, "seal"], sealStdin);

let failed = 0;

if (jsEnv === pyEnv) {
  console.log(`[ok]   seal output identical (${jsEnv.length} bytes)`);
} else {
  console.log("[fail] seal output differs");
  console.log("--- js ---");
  console.log(jsEnv);
  console.log("--- py ---");
  console.log(pyEnv);
  failed += 1;
}

console.log("\n== Cross-verify ==");
// Python verifies TS envelopes.
const pyOfJs = runPipe(PYTHON, [pyHelper, "verify"], jsEnv);
for (const line of pyOfJs.trim().split(/\r?\n/)) {
  const r = JSON.parse(line);
  if (r.ok) {
    console.log(`[ok]   py verify(js) ${r.event_id}`);
  } else {
    console.log(`[fail] py verify(js) ${r.reason}`);
    failed += 1;
  }
}

// TS verifies Python envelopes.
const jsOfPy = runPipe("node", [jsCli, "verify"], pyEnv);
for (const line of jsOfPy.trim().split(/\r?\n/)) {
  const r = JSON.parse(line);
  if (r.ok) {
    console.log(`[ok]   js verify(py) ${r.event_id}`);
  } else {
    console.log(`[fail] js verify(py) ${r.reason}`);
    failed += 1;
  }
}

// Sanity: canonical bytes identical.
console.log("\n== Canonical ==");
const canonJs = runPipe("node", [jsCli, "canonical"], sealStdin);
const canonPy = runPipe(PYTHON, [pyHelper, "canonical"], sealStdin);
if (canonJs === canonPy) {
  console.log("[ok]   canonical bytes identical");
} else {
  console.log("[fail] canonical bytes differ");
  failed += 1;
}

if (failed === 0) {
  console.log("\nall green");
  process.exit(0);
}
console.log(`\n${failed} failures`);
process.exit(1);
