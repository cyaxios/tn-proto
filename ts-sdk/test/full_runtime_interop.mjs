// Full-runtime interop: proves tn-js info/read can write entries that
// the Python `tn` SDK reads and decrypts, and vice versa, over the
// same ceremony yaml and keystore.
//
// Sets up a temp directory, seeds a deterministic btn publisher via
// tn-js (or Python), then pings entries back and forth.

import { mkdirSync, mkdtempSync, writeFileSync, rmSync, existsSync as existsSyncFs } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "node:buffer";
const existsSync = existsSyncFs;

import { DeviceKey } from "../dist/index.js";
import { BtnPublisher } from "../dist/raw.js";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const tnJs = join(tsRoot, "bin", "tn-js.mjs");
const pyHelper = join(here, "full_runtime_py_helper.py");
const repoRoot = resolve(tsRoot, "../..");

function pickPython() {
  const fromEnv = process.env.TN_PYTHON;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  for (const p of [
    join(repoRoot, ".venv/Scripts/python.exe"),
    join(repoRoot, ".venv/bin/python"),
  ]) {
    if (existsSync(p)) return p;
  }
  return "python";
}
const PYTHON = pickPython();

let passed = 0;
let failed = 0;
function ok(name) {
  console.log(`[ok]   ${name}`);
  passed += 1;
}
function fail(name, why) {
  console.log(`[fail] ${name}: ${why}`);
  failed += 1;
}

function run(bin, args, opts = {}) {
  const res = spawnSync(bin, args, { encoding: "utf8", ...opts });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(
      `${bin} ${args.join(" ")} exited ${res.status}\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
    );
  }
  return res.stdout;
}

// Deterministic ceremony seed for the shared publisher.
const SEED = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) SEED[i] = (i * 11 + 3) & 0xff;

const INDEX_MASTER = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) INDEX_MASTER[i] = (i * 7 + 1) & 0xff;

// Ceremony identity seed (Ed25519 device key).
const DEV_SEED = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) DEV_SEED[i] = (i + 9) & 0xff;

const tempRoot = mkdtempSync(join(tmpdir(), "tn-interop-"));

try {
  const keysDir = join(tempRoot, ".tn/keys");
  const logsDir = join(tempRoot, ".tn/logs");
  mkdirSync(keysDir, { recursive: true });
  mkdirSync(logsDir, { recursive: true });

  // Derive device.
  const dk = DeviceKey.fromSeed(DEV_SEED);
  writeFileSync(join(keysDir, "local.private"), Buffer.from(DEV_SEED));
  writeFileSync(join(keysDir, "local.public"), dk.did, "utf8");
  writeFileSync(join(keysDir, "index_master.key"), Buffer.from(INDEX_MASTER));

  // Publisher state + self-kit.
  const pub = new BtnPublisher(SEED);
  const selfKit = pub.mint();
  writeFileSync(join(keysDir, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keysDir, "default.btn.mykit"), Buffer.from(selfKit));

  const ceremonyId = `interop_${Buffer.from(SEED.subarray(0, 4)).toString("hex")}`;
  const yaml = `ceremony:
  id: ${ceremonyId}
  mode: local
  cipher: btn
logs:
  path: ./.tn/logs/tn.ndjson
keystore:
  path: ./.tn/keys
me:
  did: ${dk.did}
public_fields:
- timestamp
- event_id
- event_type
- level
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - did: ${dk.did}
fields: {}
`;
  const yamlPath = join(tempRoot, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");
  ok(`temp ceremony set up at ${tempRoot}`);

  // ------------------------------------------------------------------
  // JS writes entry #1, Python reads it.
  // ------------------------------------------------------------------
  const js1 = run("node", [
    tnJs,
    "info",
    "--yaml",
    yamlPath,
    "--event",
    "order.created",
    "--int",
    "amount=100",
    "--field",
    "currency=USD",
  ]);
  ok(`JS wrote entry: ${js1.trim()}`);

  const pyRead1 = run(PYTHON, [pyHelper, "read", yamlPath]);
  const pyEntries1 = pyRead1
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const order1 = pyEntries1.find((e) => e.event_type === "order.created");
  if (!order1) {
    fail("Python reads JS entry", `no order.created in ${pyEntries1.length} entries`);
  } else if (order1.fields.amount === 100 && order1.fields.currency === "USD") {
    ok("Python decrypts JS entry and recovers fields");
  } else {
    fail("Python decrypts JS entry", JSON.stringify(order1));
  }

  // ------------------------------------------------------------------
  // Python writes entry #2, JS reads both.
  // ------------------------------------------------------------------
  run(PYTHON, [pyHelper, "info", yamlPath, "shipment.created", "order_id=1", "carrier=acme"]);
  ok("Python wrote entry");

  const jsRead = run("node", [tnJs, "read", "--yaml", yamlPath]);
  const jsEntries = jsRead
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const orderJs = jsEntries.find((e) => e.event_type === "order.created");
  const shipJs = jsEntries.find((e) => e.event_type === "shipment.created");
  if (orderJs && orderJs.fields.amount === 100) ok("JS re-reads its own entry");
  else fail("JS re-reads its own entry", JSON.stringify(orderJs));
  if (shipJs && String(shipJs.fields.order_id) === "1" && shipJs.fields.carrier === "acme") {
    ok("JS decrypts Python entry and recovers fields");
  } else {
    fail("JS decrypts Python entry", JSON.stringify(shipJs));
  }

  // ------------------------------------------------------------------
  // Sanity: envelopes verify at the row_hash + signature level. Reuse
  // tn-js verify by extracting a public-only entry from the log.
  // Note: encrypted entries need the group-payload verify path, which
  // the current `verify` subcommand skips. The JS read above already
  // proved row_hash + signature by reconstructing plaintext.
  // ------------------------------------------------------------------

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
