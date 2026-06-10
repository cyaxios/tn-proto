// Cross-impl ROUND-TRIP test for the identity_seed kind (GAP 2).
//
// TS export identity_seed -> Python absorb: Python installs the SAME
//   device DID (and re-derives it from the installed private seed, proving
//   an operable identity, not just a copied string).
// Python export identity_seed -> TS absorb: TS installs the SAME device DID.
//
// The Ed25519 DID derivation is byte-identical across the two cores (both
// route signing/derivation through the Rust crate), so a seed yields the
// same did:key on both sides — the test pins that the bundle FORMAT (body
// members + self-issued manifest signed via the shared Rust manifest
// helpers) also round-trips, not just the key math.
//
// Skip policy mirrors admin_state_interop.test.ts: console.warn + return
// WITHOUT asserting when no Python `import tn` is available; assert (and
// fail loudly) when a usable interpreter is present.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { DeviceKey } from "../src/index.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { BtnPublisher } from "../src/raw.js";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const repoRoot = resolve(tsRoot, "..");
const pyHelper = join(here, "identity_seed_py_helper.py");

function resolvePython(): string {
  const fromEnv = process.env.TN_PYTHON;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const candidates = [
    resolve(repoRoot, ".venv_win/Scripts/python.exe"),
    resolve(repoRoot, ".venv/Scripts/python.exe"),
    resolve(repoRoot, ".venv/bin/python"),
    resolve(repoRoot, ".venv_linux/bin/python"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return "python";
}

function probePython(): string | null {
  const py = resolvePython();
  const res = spawnSync(py, ["-c", "import tn"], { encoding: "utf8" });
  if (res.error === undefined && res.status === 0) return py;
  return null;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

// Build a deterministic single-file btn ceremony bound to `seed`, return
// the live NodeRuntime + cleanup. Mirrors makeCeremony in
// admin_state_interop.test.ts (minus extra recipients).
function makeRuntime(seed: Uint8Array): { rt: NodeRuntime; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-identity-seed-interop-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 7 + 2) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 11) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const selfKit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(selfKit));
  pub.free();

  const yaml = `ceremony:
  id: identity_seed_interop
  mode: local
  cipher: btn
logs:
  path: ./.tn/logs/tn.ndjson
keystore:
  path: ./.tn/keys
device:
  device_identity: ${dk.did}
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: ${dk.did}
fields: {}
`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  const rt = NodeRuntime.init(yamlPath);
  return { rt, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("identity_seed.interop.ts_export_python_absorb", async () => {
  const py = probePython();
  if (py === null) {
    console.warn(
      "[skip] identity_seed interop (ts->py): no Python interpreter with " +
        "`import tn` found. Skipping WITHOUT asserting — Python-less env.",
    );
    return;
  }
  console.warn(`[info] identity_seed interop (ts->py): probe OK; using ${py}`);

  // Distinctive seed so the DID is unmistakable.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 17 + 31) & 0xff;
  const expectedDid = DeviceKey.fromSeed(seed).did;

  const { rt, cleanup } = makeRuntime(seed);
  const outDir = mkdtempSync(join(tmpdir(), "tn-identity-seed-out-"));
  try {
    const tnpkgPath = join(outDir, "identity.tnpkg");
    rt.exportPkg({ kind: "identity_seed", nickname: "alice-laptop" }, tnpkgPath);
    assert.ok(existsSync(tnpkgPath), "TS should have written the identity_seed tnpkg");

    const dest = join(outDir, "py-dest");
    const res = spawnSync(py, [pyHelper, "absorb", tnpkgPath, dest], { encoding: "utf8" });
    if (res.error) throw res.error;
    assert.equal(
      res.status,
      0,
      `python absorb helper exited ${res.status}\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
    );
    const parsed = JSON.parse(res.stdout) as {
      kind: string;
      status: string | null;
      reason: string | null;
      accepted_count: number | null;
      installed_did: string | null;
      derived_did: string | null;
    };

    assert.equal(parsed.kind, "identity_seed", `unexpected receipt kind: ${JSON.stringify(parsed)}`);
    assert.notEqual(parsed.status, "rejected", `Python rejected the TS bundle: ${parsed.reason}`);
    assert.equal(parsed.accepted_count, 1, `expected accepted_count=1: ${JSON.stringify(parsed)}`);
    assert.equal(
      parsed.installed_did,
      expectedDid,
      "Python's installed local.public DID must equal the seed's DID",
    );
    assert.equal(
      parsed.derived_did,
      expectedDid,
      "Python must re-derive the SAME DID from the installed private seed (operable identity)",
    );
    console.warn(`[info] identity_seed ts->py OK; Python installed ${parsed.installed_did}`);
  } finally {
    await rt.close();
    cleanup();
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("identity_seed.interop.python_export_ts_absorb", async () => {
  const py = probePython();
  if (py === null) {
    console.warn(
      "[skip] identity_seed interop (py->ts): no Python interpreter with " +
        "`import tn` found. Skipping WITHOUT asserting — Python-less env.",
    );
    return;
  }
  console.warn(`[info] identity_seed interop (py->ts): probe OK; using ${py}`);

  // The identity Python will mint into the bundle.
  const incomingSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) incomingSeed[i] = (i * 23 + 5) & 0xff;
  const incomingDid = DeviceKey.fromSeed(incomingSeed).did;

  // A DIFFERENT identity for the fresh TS ceremony we absorb INTO, so a
  // successful absorb genuinely swaps the installed identity.
  const hostSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) hostSeed[i] = (i * 3 + 41) & 0xff;
  assert.notEqual(DeviceKey.fromSeed(hostSeed).did, incomingDid);

  const outDir = mkdtempSync(join(tmpdir(), "tn-identity-seed-py-out-"));
  const { rt, cleanup } = makeRuntime(hostSeed);
  try {
    const tnpkgPath = join(outDir, "py_identity.tnpkg");
    const res = spawnSync(py, [pyHelper, "export", tnpkgPath, hex(incomingSeed), "bob-phone"], {
      encoding: "utf8",
    });
    if (res.error) throw res.error;
    assert.equal(
      res.status,
      0,
      `python export helper exited ${res.status}\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
    );
    const exp = JSON.parse(res.stdout) as { did: string };
    assert.equal(exp.did, incomingDid, "Python export should report the seed's DID");
    assert.ok(existsSync(tnpkgPath), "Python should have written the identity_seed tnpkg");

    // Fresh ceremony has 0 user events, so absorb's overwrite path installs
    // the incoming identity (mirrors Python's Bug-3 fresh-ceremony rule).
    const receipt = rt.absorbPkg(tnpkgPath);
    assert.equal(receipt.kind, "identity_seed", `unexpected kind: ${JSON.stringify(receipt)}`);
    assert.equal(
      receipt.rejectedReason,
      undefined,
      `TS rejected the Python bundle: ${receipt.rejectedReason}`,
    );
    assert.equal(receipt.acceptedCount, 1, `expected acceptedCount=1: ${JSON.stringify(receipt)}`);

    // The TS keystore's local.public must now hold the incoming DID, and
    // it must re-derive from the installed private seed.
    const keystore = rt.config.keystorePath;
    const installedDid = readFileSync(join(keystore, "local.public"), "utf8").trim();
    assert.equal(installedDid, incomingDid, "TS local.public must equal the incoming DID");
    const installedSeed = new Uint8Array(readFileSync(join(keystore, "local.private")));
    assert.equal(
      DeviceKey.fromSeed(installedSeed).did,
      incomingDid,
      "TS must re-derive the same DID from the installed private seed",
    );
    console.warn(`[info] identity_seed py->ts OK; TS installed ${installedDid}`);
  } finally {
    await rt.close();
    cleanup();
    rmSync(outDir, { recursive: true, force: true });
  }
});
