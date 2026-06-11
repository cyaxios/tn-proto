// Cross-impl ROUND-TRIP test for vault link-state (GAP 3).
//
// Proves TS `tn.vault.setLinkState` and Python `tn.admin.set_link_state`
// agree on the SAME on-disk field — `ceremony.mode` in the AUTHORITATIVE
// yaml — in BOTH directions:
//
//   TS write -> Python read:  TS setLinkState("linked") flips ceremony.mode
//     to "linked"; reload via loadConfig sees "linked"; spawn Python on the
//     same yaml and it ALSO sees mode == "linked".
//   Python write -> TS read:  Python set_link_state(mode="local") flips it
//     back; TS loadConfig now sees "local".
//
// Both sides write through their authoritative-yaml path (Python:
// _update_authoritative_yaml(key="vault"); TS: NodeRuntime.setCeremonyMode
// -> authoritativeYamlFor(yamlPath, "vault")). For a single-file ceremony
// that resolves back to the yaml itself, so the two writes target the same
// file and the same key.
//
// Skip policy mirrors admin_state_interop.test.ts: if no Python interpreter
// with `import tn` is available the test console.warns and returns WITHOUT
// asserting. It does NOT skip when a usable interpreter is present — it then
// asserts the round-trip and FAILS loudly if interop is broken.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { DeviceKey, Tn, loadConfig } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const repoRoot = resolve(tsRoot, "..");
const pyHelper = join(here, "vault_set_link_state_py_helper.py");

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

interface Ceremony {
  yamlPath: string;
  cleanup: () => void;
}

// Deterministic single-file btn ceremony on disk (mirrors the makeCeremony
// shape from admin_state_interop.test.ts, minus the extra recipients —
// link-state doesn't touch the roster). Starts mode: local.
function makeCeremony(): Ceremony {
  const dir = mkdtempSync(join(tmpdir(), "tn-set-link-state-interop-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 13 + 7) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 3 + 1) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 9 + 5) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const selfKit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(selfKit));
  pub.free();

  const yaml = `ceremony:
  id: set_link_state_interop
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

  return {
    yamlPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

interface PyState {
  mode: string;
  linked_vault: string | null;
}

function pyState(py: string, args: string[]): PyState {
  const res = spawnSync(py, [pyHelper, ...args], { encoding: "utf8" });
  if (res.error) throw res.error;
  assert.equal(
    res.status,
    0,
    `python helper exited ${res.status}\nargs: ${JSON.stringify(args)}\n` +
      `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
  );
  try {
    return JSON.parse(res.stdout) as PyState;
  } catch (e) {
    throw new Error(
      `python helper did not emit valid JSON: ${(e as Error).message}\n` +
        `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
      { cause: e },
    );
  }
}

test("vault_set_link_state.interop.round_trip", async () => {
  const py = probePython();
  if (py === null) {
    console.warn(
      "[skip] vault.setLinkState interop: no Python interpreter with " +
        "`import tn` found (set TN_PYTHON or provide a venv with tn " +
        "installed). Skipping WITHOUT asserting — Python-less env.",
    );
    return;
  }
  console.warn(`[info] vault.setLinkState interop: probe OK; using interpreter ${py}`);

  // The Python helper links to this same URL; matching it keeps the
  // re-link guard happy across the two writers.
  const VAULT_URL = "https://vault.example";

  const c = makeCeremony();
  try {
    // Baseline: both sides agree the fresh ceremony is local.
    assert.equal(loadConfig(c.yamlPath).mode, "local", "TS baseline mode should be local");
    assert.equal(pyState(py, ["read", c.yamlPath]).mode, "local", "Python baseline mode should be local");

    // ── Direction 1: TS writes "linked", Python reads it. Python's
    //    loader rejects mode:linked without linked_vault, so supply one.
    const tn = await Tn.init(c.yamlPath);
    try {
      await tn.vault.setLinkState("linked", { linkedVault: VAULT_URL });
    } finally {
      await tn.close();
    }
    const tsLinked = loadConfig(c.yamlPath);
    assert.equal(tsLinked.mode, "linked", "after TS setLinkState('linked'), TS loadConfig should see linked");
    assert.equal(tsLinked.vault.url, VAULT_URL, "TS should have written vault.url");

    const pyAfterTsLink = pyState(py, ["read", c.yamlPath]);
    assert.equal(
      pyAfterTsLink.mode,
      "linked",
      "after TS setLinkState('linked'), Python must read ceremony.mode == linked",
    );
    assert.equal(
      pyAfterTsLink.linked_vault,
      VAULT_URL,
      "Python must resolve the linked_vault TS wrote",
    );

    // ── Direction 2: Python writes "local" (unlink), TS reads it.
    const pyAfterUnlink = pyState(py, ["set", c.yamlPath, "local"]);
    assert.equal(pyAfterUnlink.mode, "local", "Python set_link_state(mode='local') should persist local");
    const tsAfterPyUnlink = loadConfig(c.yamlPath);
    assert.equal(
      tsAfterPyUnlink.mode,
      "local",
      "after Python set_link_state(mode='local'), TS loadConfig must see local",
    );

    // ── Direction 3: Python writes "linked", TS reads the vault url.
    const pyAfterLink = pyState(py, ["set", c.yamlPath, "linked"]);
    assert.equal(pyAfterLink.mode, "linked", "Python set_link_state(mode='linked') should persist linked");
    const tsAfterPyLink = loadConfig(c.yamlPath);
    assert.equal(tsAfterPyLink.mode, "linked", "TS must read the linked mode Python wrote");
    assert.equal(
      tsAfterPyLink.vault.url,
      VAULT_URL,
      "TS must resolve the linked_vault Python wrote",
    );

    console.warn(
      "[info] vault.setLinkState interop: round-trip OK " +
        "(TS<->Python agree on ceremony.mode + linked_vault, both directions)",
    );
  } finally {
    c.cleanup();
  }
});
