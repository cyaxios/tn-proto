// Admin-verb interop: JS adds a recipient (mints a kit, attests the
// event). Python reads the log through tn.read and through the admin
// reducer to prove the state change is visible on both sides.

import { mkdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "node:buffer";

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

let passed = 0;
let failed = 0;
function ok(m) {
  console.log(`[ok]   ${m}`);
  passed += 1;
}
function fail(m, why) {
  console.log(`[fail] ${m}: ${why}`);
  failed += 1;
}

const SEED = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) SEED[i] = (i * 13 + 5) & 0xff;
const DEV_SEED = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) DEV_SEED[i] = (i * 17 + 2) & 0xff;
const IDX_MASTER = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) IDX_MASTER[i] = (i * 19 + 11) & 0xff;

const tempRoot = mkdtempSync(join(tmpdir(), "tn-admin-"));

try {
  const keys = join(tempRoot, ".tn/keys");
  const logs = join(tempRoot, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const dk = DeviceKey.fromSeed(DEV_SEED);
  writeFileSync(join(keys, "local.private"), Buffer.from(DEV_SEED));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  writeFileSync(join(keys, "index_master.key"), Buffer.from(IDX_MASTER));

  const pub = new BtnPublisher(SEED);
  const selfKit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(selfKit));

  const yaml = `ceremony:
  id: admin_interop
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
- group
- leaf_index
- recipient_did
- kit_sha256
- cipher
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
  ok(`temp ceremony at ${tempRoot}`);

  const bobKitPath = join(tempRoot, "bob.tnpkg");
  const bobDid = "did:key:z6MkfakeBob11111111111111111111111111111111";

  const addOut = run("node", [
    tnJs,
    "admin",
    "add-recipient",
    "--yaml",
    yamlPath,
    "--group",
    "default",
    "--out",
    bobKitPath,
    "--recipient-did",
    bobDid,
  ]);
  const addResult = JSON.parse(addOut);
  if (addResult.ok && addResult.leaf_index === 1) ok(`mint kit at leaf 1 (selfKit was 0)`);
  else fail("mint at leaf 1", JSON.stringify(addResult));

  if (existsSync(bobKitPath)) ok("kit written to disk");
  else fail("kit written to disk", "missing");

  // Python reads the log. tn.recipient.added is a public-only event
  // (no group payload), so it shows up even though bob has no kit.
  const pyEntries = run(PYTHON, [pyHelper, "read", yamlPath])
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const added = pyEntries.find((e) => e.event_type === "tn.recipient.added");
  if (!added) {
    fail(
      "Python sees tn.recipient.added",
      `entries: ${pyEntries.map((e) => e.event_type).join(", ")}`,
    );
  } else if (
    added.fields.leaf_index === 1 &&
    added.fields.recipient_did === bobDid &&
    typeof added.fields.kit_sha256 === "string" &&
    added.fields.cipher === "btn"
  ) {
    ok("Python decodes recipient_added with correct fields");
  } else {
    fail("recipient_added fields", JSON.stringify(added.fields));
  }

  // Admin reducer agreement. Feed the envelope directly to
  // tn_core.admin.reduce and compare against what tn-js produced.
  const logPath = join(logs, "tn.ndjson");
  const logText = readFileSync(logPath, "utf8");
  const addedLine = logText
    .split(/\r?\n/)
    .find((l) => l.includes('"event_type":"tn.recipient.added"'));
  if (!addedLine) {
    fail("recipient_added envelope present in log", "not found");
  } else {
    const pyReduce = run(PYTHON, [
      "-c",
      `
import sys, json, importlib.util
sys.path.insert(0, r'${repoRoot.replace(/\\/g, "/")}/tn-protocol/python')
from tn_core.admin import reduce as R
env = json.loads(${JSON.stringify(addedLine)})
print(json.dumps(R(env), sort_keys=True))
`,
    ]);
    const pyDelta = JSON.parse(pyReduce.trim());
    if (
      pyDelta.kind === "recipient_added" &&
      pyDelta.leaf_index === 1 &&
      pyDelta.recipient_did === bobDid
    ) {
      ok("Python admin reducer emits matching state delta");
    } else {
      fail("admin reducer delta", JSON.stringify(pyDelta));
    }
  }

  // Revoke, re-count, re-check log.
  const revokeOut = run("node", [
    tnJs,
    "admin",
    "revoke-recipient",
    "--yaml",
    yamlPath,
    "--group",
    "default",
    "--leaf",
    "1",
    "--recipient-did",
    bobDid,
  ]);
  if (JSON.parse(revokeOut).ok) ok("revoke-recipient returns ok");
  else fail("revoke-recipient", revokeOut);

  const countOut = run("node", [
    tnJs,
    "admin",
    "revoked-count",
    "--yaml",
    yamlPath,
    "--group",
    "default",
  ]);
  const countRes = JSON.parse(countOut);
  if (countRes.count === 1) ok("revoked count = 1 after revoking 1 kit");
  else fail("revoked count", JSON.stringify(countRes));

  const finalEntries = run(PYTHON, [pyHelper, "read", yamlPath])
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const revoked = finalEntries.find((e) => e.event_type === "tn.recipient.revoked");
  if (revoked && revoked.fields.leaf_index === 1 && revoked.fields.recipient_did === bobDid) {
    ok("Python sees tn.recipient.revoked with correct fields");
  } else {
    fail("tn.recipient.revoked", JSON.stringify(revoked));
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
