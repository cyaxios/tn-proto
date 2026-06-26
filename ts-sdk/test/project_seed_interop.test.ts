// Cross-impl ROUND-TRIP test for the project_seed kind (full-ceremony
// identity + config backup / restore).
//
// project_seed is the "Create Project" / full-device-backup bundle: it
// carries KEYS + CONFIG (tn.yaml + every keystore file nested under
// body/keys/), NOT the event log (see project memory). So a successful
// restore is NOT "the original log replays" — there is no log in the
// bundle. It is:
//
//   1. the restored ceremony has the SAME device DID (and re-derives it
//      from the installed private seed — an operable identity, not just a
//      copied string),
//   2. the restored ceremony has the SAME group set, and
//   3. the restored keys/config OPERATE — a fresh emit + read round-trips
//      through the restored btn keystore.
//
// Both SDKs implement export(kind="project_seed") + absorb/bootstrap, but
// no cross-impl test existed, so a silent drift in the body layout, the
// self-addressed manifest, or the btn key material could corrupt restores
// undetected. This pins the round trip in BOTH directions.
//
// Direction A (TS export -> Python absorb):
//   TS builds a real btn ceremony, exports a project_seed, spawns Python
//   to bootstrap-absorb it into a fresh dir; Python re-derives the DID
//   from the installed seed, reports the restored group set, and PROVES
//   OPERATE by emitting + reading a fresh entry. TS asserts DID + groups +
//   the read-back entry.
//
// Direction B (Python export -> TS absorb):
//   Python builds a fresh ceremony (tn.init mints the full keystore for
//   the `default` + `tn.agents` groups), exports a project_seed, reports
//   its DID + group set. TS bootstrap-absorbs it into a fresh dir, re-init
//   the restored ceremony, asserts DID + group set, then PROVES OPERATE by
//   emitting + reading a fresh entry.
//
// The faithful "restore on a fresh device" path on BOTH sides is the
// cwd-bootstrap absorb (Python: tn.absorb with no prior init; TS:
// absorbBootstrap({cwd})), which reads the bundle's body/tn.yaml for the
// keystore/log layout and writes everything under a fresh dir. That is the
// path exercised here.
//
// Skip policy mirrors identity_seed_interop.test.ts: console.warn + return
// WITHOUT asserting when no Python `import tn` is available; assert (and
// fail loudly) when a usable interpreter is present.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { DeviceKey, Tn, absorbBootstrap } from "../src/index.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { BtnPublisher } from "../src/raw.js";
import type { Entry } from "../src/Entry.js";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const repoRoot = resolve(tsRoot, "..");
const pyHelper = join(here, "project_seed_py_helper.py");

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

// Build a deterministic single-file btn ceremony bound to `seed`, return
// the live NodeRuntime + cleanup + the dir. Mirrors makeRuntime in
// identity_seed_interop.test.ts — a complete btn keystore (local
// keypair + index_master + the `default` group's btn self-state/self-kit)
// so project_seed has real key material to back up.
function makeRuntime(seed: Uint8Array): {
  rt: NodeRuntime;
  dir: string;
  did: string;
  cleanup: () => void;
} {
  const dir = mkdtempSync(join(tmpdir(), "tn-project-seed-interop-"));
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
  id: project_seed_interop
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
  return { rt, dir, did: dk.did, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("project_seed.interop.ts_export_python_absorb", async () => {
  const py = probePython();
  if (py === null) {
    console.warn(
      "[skip] project_seed interop (ts->py): no Python interpreter with " +
        "`import tn` found. Skipping WITHOUT asserting — Python-less env.",
    );
    return;
  }
  console.warn(`[info] project_seed interop (ts->py): probe OK; using ${py}`);

  // Distinctive seed so the DID is unmistakable.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 17 + 31) & 0xff;
  const expectedDid = DeviceKey.fromSeed(seed).did;

  const { rt, did, cleanup } = makeRuntime(seed);
  assert.equal(did, expectedDid);
  const outDir = mkdtempSync(join(tmpdir(), "tn-project-seed-out-"));
  try {
    const tnpkgPath = join(outDir, "project.tnpkg");
    rt.exportPkg({ kind: "project_seed", confirmIncludesSecrets: true }, tnpkgPath);
    assert.ok(existsSync(tnpkgPath), "TS should have written the project_seed tnpkg");

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
      restored_groups: string[] | null;
      operate_ok: boolean;
      readback_event_type: string | null;
      readback_fields: Record<string, unknown> | null;
    };

    assert.equal(parsed.kind, "project_seed", `unexpected receipt kind: ${JSON.stringify(parsed)}`);
    assert.notEqual(parsed.status, "rejected", `Python rejected the TS bundle: ${parsed.reason}`);
    assert.equal(
      parsed.installed_did,
      expectedDid,
      "Python's installed local.public DID must equal the TS ceremony's DID",
    );
    assert.equal(
      parsed.derived_did,
      expectedDid,
      "Python must re-derive the SAME DID from the installed private seed (operable identity)",
    );
    // Group set: the TS ceremony declares exactly `default`. The restore
    // must carry that group through.
    assert.deepEqual(
      parsed.restored_groups,
      ["default"],
      `restored group set must match the TS ceremony: ${JSON.stringify(parsed.restored_groups)}`,
    );
    // Operate proof: Python emitted + read back a fresh entry through the
    // restored btn keystore.
    assert.equal(parsed.operate_ok, true, "Python must emit+read a fresh entry on the restored ceremony");
    assert.equal(parsed.readback_event_type, "order.created", "read-back event_type mismatch");
    assert.deepEqual(
      parsed.readback_fields,
      { amount: 4242, marker: "ps-interop-a" },
      `read-back fields mismatch: ${JSON.stringify(parsed.readback_fields)}`,
    );
    console.warn(
      `[info] project_seed ts->py OK; Python restored ${parsed.installed_did} ` +
        `groups=${JSON.stringify(parsed.restored_groups)} and emit+read round-tripped`,
    );
  } finally {
    await rt.close();
    cleanup();
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("project_seed.interop.python_export_ts_absorb", async () => {
  const py = probePython();
  if (py === null) {
    console.warn(
      "[skip] project_seed interop (py->ts): no Python interpreter with " +
        "`import tn` found. Skipping WITHOUT asserting — Python-less env.",
    );
    return;
  }
  console.warn(`[info] project_seed interop (py->ts): probe OK; using ${py}`);

  const outDir = mkdtempSync(join(tmpdir(), "tn-project-seed-py-out-"));
  const restoreDir = mkdtempSync(join(tmpdir(), "tn-project-seed-ts-restore-"));
  let tn: Tn | null = null;
  try {
    // Python builds a fresh ceremony + exports a project_seed; reports the
    // DID + group set the TS restore must reproduce.
    const tnpkgPath = join(outDir, "py_project.tnpkg");
    const res = spawnSync(py, [pyHelper, "export", tnpkgPath], { encoding: "utf8" });
    if (res.error) throw res.error;
    assert.equal(
      res.status,
      0,
      `python export helper exited ${res.status}\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
    );
    const exp = JSON.parse(res.stdout) as { did: string; groups: string[] };
    assert.ok(exp.did.startsWith("did:key:z"), `python export should report a did:key: ${exp.did}`);
    assert.ok(existsSync(tnpkgPath), "Python should have written the project_seed tnpkg");
    const incomingDid = exp.did;
    const expectedGroups = exp.groups;

    // TS restores via the cwd-bootstrap path into a fresh dir (the
    // faithful "restore on a fresh device" flow — no prior runtime).
    const receipt = absorbBootstrap(tnpkgPath, { cwd: restoreDir });
    assert.equal(receipt.kind, "project_seed", `unexpected kind: ${JSON.stringify(receipt)}`);
    assert.equal(
      receipt.rejectedReason,
      undefined,
      `TS rejected the Python bundle: ${receipt.rejectedReason}`,
    );
    assert.ok(
      receipt.acceptedCount > 0,
      `expected acceptedCount>0 for a fresh restore: ${JSON.stringify(receipt)}`,
    );

    // The restore wrote ./tn.yaml under restoreDir; loading it must yield
    // the incoming identity, and the installed private seed must re-derive
    // the same DID (operable identity, not just a copied string).
    const restoredYaml = join(restoreDir, "tn.yaml");
    assert.ok(existsSync(restoredYaml), "bootstrap restore must write tn.yaml into the fresh dir");

    tn = await Tn.init(restoredYaml, { stdout: false });
    assert.equal(tn.did, incomingDid, "TS restored ceremony DID must equal the Python bundle's DID");

    // `Tn.config()` returns the underlying NodeRuntime config (typed as
    // `unknown` on the public surface); narrow to the two members we read.
    const cfg = tn.config() as { keystorePath: string; groups: Map<string, unknown> };

    // Re-derive from the installed private seed on disk.
    const installedSeed = new Uint8Array(readFileSync(join(cfg.keystorePath, "local.private")));
    assert.equal(
      DeviceKey.fromSeed(installedSeed).did,
      incomingDid,
      "TS must re-derive the same DID from the installed private seed",
    );

    // Group set parity (Python's fresh ceremony has `default` + the
    // implicit `tn.agents` group).
    const restoredGroups = [...cfg.groups.keys()].sort();
    assert.deepEqual(
      restoredGroups,
      [...expectedGroups].sort(),
      `restored group set must match the Python ceremony: ${JSON.stringify(restoredGroups)} ` +
        `vs ${JSON.stringify(expectedGroups)}`,
    );

    // Operate proof: emit + read a fresh entry through the restored btn
    // keystore.
    tn.info("order.created", { amount: 7777, marker: "ps-interop-b" });
    const userRows: Entry[] = [];
    for (const e of tn.read()) {
      const entry = e as Entry;
      if (!entry.event_type.startsWith("tn.")) userRows.push(entry);
    }
    assert.ok(userRows.length > 0, "restored ceremony must read back the freshly-emitted entry");
    const last = userRows[userRows.length - 1]!;
    assert.equal(last.event_type, "order.created", "read-back event_type mismatch");
    assert.equal(last.fields["amount"], 7777, `read-back amount mismatch: ${JSON.stringify(last.fields)}`);
    assert.equal(
      last.fields["marker"],
      "ps-interop-b",
      `read-back marker mismatch: ${JSON.stringify(last.fields)}`,
    );
    console.warn(
      `[info] project_seed py->ts OK; TS restored ${tn.did} ` +
        `groups=${JSON.stringify(restoredGroups)} and emit+read round-tripped`,
    );
  } finally {
    if (tn !== null) await tn.close();
    rmSync(outDir, { recursive: true, force: true });
    rmSync(restoreDir, { recursive: true, force: true });
  }
});
