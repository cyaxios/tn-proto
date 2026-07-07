// CROSS-IMPL: a Python producer + a TS consumer on the SAME group-keys
// snapshot, proving the account-sync group-key path crosses the language
// boundary. Against the LIVE dev vault on 34987 (TN_DEV_AUTH_BYPASS=1) for the
// reachability gate; the cross-impl artifact itself is file-level (a
// `group_keys.tnpkg`), so the boundary it proves does not depend on the
// vault's inbox transport.
//
// WHAT CROSSES (proven here):
//   * Device A is PYTHON: `tn.init(cipher="btn")` + `tn.ensure_group` + a
//     G-routed write, then `tn.export.export_group_keys` packs the group's
//     btn key material + the authoritative `groups.<name>` yaml block into a
//     `group_keys` `.tnpkg` (wire kind `full_keystore`, scope `group_keys`).
//   * Device B is TS: a fresh TS btn ceremony `absorb`s that Python-produced
//     `.tnpkg` via the real `absorbCmd`. After absorb, B REGISTERS the group
//     AND it is USABLE — B encrypts a fresh field into the group and reads it
//     back DECRYPTED. The Python-minted btn publisher key installed and routes
//     under the TS runtime.
//
// WHAT DOES NOT CROSS (documented, not faked):
//   * The whole-ceremony BODY restore does NOT cross. The TS restore lays each
//     body member out by its FLAT name and its traversal guard refuses any name
//     containing a separator, whereas the Python push keys members NESTED as
//     `body/keys/<name>` / `body/tn.yaml` (and the Python restore rebuilds
//     those subpaths). So a TS `restoreViaPassphrase` of a Python-pushed body
//     blob writes no usable keystore. The capstone
//     (account_sync_full_live) therefore keeps the cross-device body leg
//     same-language; the GROUP-KEYS snapshot is the piece that crosses, and
//     that is what this test pins.
//
// CI-safe: probes the vault first; ALSO skips when a usable Python + `tn`
// import is not available (the producer half), so it never hard-fails a TS-only
// runner. Run: node --import tsx --import ./test/_setup_wasm.mjs --test \
//   test/account_sync_cross_impl_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { Tn } from "../src/tn.js";
import { Entry } from "../src/Entry.js";
import { absorbCmd } from "../src/cli/absorb.js";

import { ulidish, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

// The Python repo + venv live as siblings of ts-sdk: tn_proto/python.
const PYTHON_DIR = resolve(import.meta.dirname, "..", "..", "python");
const PY_CANDIDATES = [
  resolve(import.meta.dirname, "..", "..", ".venv", "Scripts", "python.exe"),
  resolve(import.meta.dirname, "..", "..", ".venv", "bin", "python"),
  resolve(PYTHON_DIR, ".venv", "Scripts", "python.exe"),
  resolve(PYTHON_DIR, ".venv", "bin", "python"),
];

/** Locate a Python interpreter that can import `tn`; null if none works. */
function findUsablePython(): string | null {
  for (const py of PY_CANDIDATES) {
    if (!existsSync(py)) continue;
    const probe = spawnSync(py, ["-c", "import tn"], {
      cwd: PYTHON_DIR,
      env: { ...process.env, PYTHONPATH: PYTHON_DIR },
      encoding: "utf8",
    });
    if (probe.status === 0) return py;
  }
  return null;
}

const PYTHON = reachable ? findUsablePython() : null;
const skipReason = !reachable
  ? "dev vault not reachable on 34987"
  : !PYTHON
    ? "no Python interpreter able to import `tn` (cross-impl producer half)"
    : false;

/** The producer script: a Python btn ceremony exports a group_keys .tnpkg. */
const PY_PRODUCER = `
import sys
from pathlib import Path

import tn
from tn.export import export_group_keys

src = Path(sys.argv[1])
out = Path(sys.argv[2])
group = sys.argv[3]
field = sys.argv[4]
secret = sys.argv[5]

yaml_path = src / "tn.yaml"
tn.init(yaml_path, cipher="btn")
cfg = tn.current_config()
tn.ensure_group(cfg, group, fields=[field, "memo"])
device = cfg.device
# A G-routed write so the producer genuinely exercises the group before export.
tn.info("xi.fromPython", **{field: secret, "memo": "py-write"}, group=group)
tn.flush_and_close()

tn.init(yaml_path)
cfg = tn.current_config()
export_group_keys(out, cfg=cfg, sign_with=device, author_did=device.did)
tn.flush_and_close()
print(device.did)
`;

test(
  "cross-impl — Python publishes group keys; TS absorbs them and the group is USABLE (encrypt+decrypt) under the TS runtime",
  { skip: skipReason },
  async () => {
    const group = "xgrp";
    const field = "amount"; // a btn-routed field name the producer declares
    const secret = "777";

    const pySrc = mkdtempSync(join(tmpdir(), "xi-py-src-"));
    const pkgPath = join(mkdtempSync(join(tmpdir(), "xi-pkg-")), "group_keys.tnpkg");
    const tsDir = mkdtempSync(join(tmpdir(), "xi-ts-"));
    const scriptPath = join(mkdtempSync(join(tmpdir(), "xi-script-")), "produce.py");
    const dirs = [pySrc, tsDir];

    try {
      // ── Device A (PYTHON): produce a group_keys .tnpkg. ──
      writeFileSync(scriptPath, PY_PRODUCER, "utf8");
      const proc = spawnSync(
        PYTHON!,
        [scriptPath, pySrc, pkgPath, group, field, secret],
        {
          cwd: PYTHON_DIR,
          env: { ...process.env, PYTHONPATH: PYTHON_DIR, COVERAGE_CORE: "sysmon" },
          encoding: "utf8",
        },
      );
      assert.equal(
        proc.status,
        0,
        `python producer failed (status ${proc.status}):\n${proc.stdout}\n${proc.stderr}`,
      );
      assert.ok(existsSync(pkgPath), `python producer did not write ${pkgPath}`);
      const pyDid = (proc.stdout || "").trim().split(/\r?\n/).pop() || "";
      assert.match(pyDid, /^did:key:/, `python producer must print its DID; got: ${proc.stdout}`);

      // ── Device B (TS): a fresh btn ceremony absorbs the Python package. ──
      const tsYaml = join(tsDir, "tn.yaml");
      const seed = await Tn.init(tsYaml);
      const tsDid = seed.did;
      await seed.close();
      assert.notEqual(tsDid, pyDid, "TS device must have a distinct DID (genuine cross-device)");

      let absorbOut = "";
      const code = await absorbCmd({
        packagePath: pkgPath,
        yaml: tsYaml,
        stdout: (s) => { absorbOut += s; },
        stderr: (s) => { absorbOut += s; },
      });
      assert.equal(code, 0, `TS absorb of the Python group_keys must exit 0:\n${absorbOut}`);
      assert.match(absorbOut, /accepted=[1-9]/, `TS absorb must accept >=1 member:\n${absorbOut}`);

      // ── USABLE under TS: encrypt a fresh field into the absorbed group and
      //    read it back DECRYPTED. If the Python-minted btn key had not
      //    installed/routed under TS, this field would not surface. ──
      const tsRt = await Tn.init(tsYaml);
      try {
        const marker = `ts-${ulidish().slice(0, 8)}`;
        tsRt.info("xi.fromTS", { [field]: marker, memo: "ts-write" });
        const back = [...tsRt.read()]
          .filter((e): e is Entry => e instanceof Entry)
          .find((e) => e.event_type === "xi.fromTS");
        assert.ok(back, "TS must read back its own write to the absorbed group");
        assert.equal(
          back!.fields[field],
          marker,
          "the Python-published group must be USABLE under TS (encrypt+decrypt crosses)",
        );
      } finally {
        await tsRt.close();
      }
    } finally {
      rmSync(scriptPath, { force: true });
      rmSync(pkgPath, { force: true });
      for (const d of dirs) rmSync(d, { recursive: true, force: true });
    }
  },
);
