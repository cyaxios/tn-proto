// Cross-SDK regression: a `tn.ceremony.init` row written by the Rust
// core (here via Python `tn.init`) must verify `row_hash` under the TS
// reader.
//
// Root cause this guards against (0.5.0a4): `device_identity` is the
// mandatory reserved envelope scalar, but the Rust writer also injected
// it into the `tn.ceremony.init` public `init_fields` (and the admin
// catalog required it). On a Python/TS-written ceremony — whose yaml
// carries the full DEFAULT_PUBLIC_FIELDS including `device_identity` —
// the writer hashed it twice (scalar + public field) while the TS
// reader's `_ENVELOPE_RESERVED` correctly excludes the scalar and hashes
// it once. The two disagreed, so `read({ verify: "raise" })` threw
// `VerifyError ... event="tn.ceremony.init" ... row_hash` on the very
// first attested row. User events (`txn.created`) and `tn.group.added`
// verified fine because they never put `device_identity` in their public
// fields.
//
// This is the exact cross-SDK shape of the user repro: Python writes the
// ceremony, TS reads + verifies it. Requires a local Python with
// tn-protocol installed; skips otherwise (CI runs the full matrix).

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn, VerifyError } from "../src/tn.js";

function pickPython(): string | null {
  const candidates = [process.env["TN_PYTHON"], "python3", "python"].filter(
    (v): v is string => typeof v === "string" && v.length > 0,
  );
  for (const bin of candidates) {
    try {
      const result = spawnSync(bin, ["-c", "import tn; print('ok')"], {
        encoding: "utf8",
        timeout: 10_000,
      });
      if (result.status === 0 && result.stdout.trim() === "ok") return bin;
    } catch {
      /* try next */
    }
  }
  return null;
}

// Inline Python writer: create a fresh btn ceremony (config yaml carries
// device_identity in public_fields), emit a user event, print the admin
// log path as the last stdout line.
const PY_WRITER = `
import os, json
from pathlib import Path
proj = os.environ["TN_PROJ"]
os.chdir(proj)
import tn
tn.init(str(Path(proj) / "tn.yaml"), cipher="btn", link=False)
tn.info("txn.created", amount=42)
from tn import current_config
from tn._log_targets import resolve_log_target
cfg = current_config()
admin = str(resolve_log_target("admin", cfg)[0])
print(json.dumps({"yaml": str(Path(proj) / "tn.yaml"), "admin": admin}))
`;

test(
  "Python-written tn.ceremony.init verifies row_hash under TS read({verify:'raise'})",
  {
    skip:
      pickPython() === null
        ? "Python tn-protocol not available locally; runs in CI"
        : false,
  },
  async () => {
    const python = pickPython()!;
    const base = mkdtempSync(join(tmpdir(), "tn-ceremony-init-parity-"));
    const proj = join(base, "proj");
    const ident = join(base, "ident");
    const xdg = join(base, "xdg");
    const env = {
      ...process.env,
      TN_IDENTITY_DIR: ident,
      XDG_DATA_HOME: xdg,
      TN_PROJ: proj,
      TN_NO_STDOUT: "1",
    };
    mkdirSync(proj, { recursive: true });
    mkdirSync(ident, { recursive: true });
    mkdirSync(xdg, { recursive: true });
    let client: Tn | null = null;
    try {
      // 1. Python writes the ceremony + ceremony.init (Rust writer).
      const w = spawnSync(python, ["-c", PY_WRITER], {
        encoding: "utf8",
        timeout: 60_000,
        env: { ...env, PYTHONPATH: env["PYTHONPATH"] ?? "" },
      });
      if (w.status !== 0) {
        throw new Error(`python writer failed (${w.status}): ${w.stderr || w.stdout}`);
      }
      const lastLine = w.stdout.trim().split(/\r?\n/).filter(Boolean).pop()!;
      const paths = JSON.parse(lastLine) as { yaml: string; admin: string };

      // 2. TS attaches to the same ceremony and verifies the admin log.
      process.env.TN_IDENTITY_DIR = ident;
      process.env.XDG_DATA_HOME = xdg;
      client = await Tn.init(paths.yaml, { link: false });

      let sawInit = false;
      let count = 0;
      let threw: VerifyError | null = null;
      try {
        for (const e of client.read({ log: paths.admin, verify: "raise", raw: true })) {
          count += 1;
          const env_ = (e as { envelope?: Record<string, unknown> }).envelope ?? e;
          if (env_["event_type"] === "tn.ceremony.init") sawInit = true;
        }
      } catch (ex) {
        if (ex instanceof VerifyError) threw = ex;
        else throw ex;
      }

      assert.equal(
        threw,
        null,
        `read({verify:"raise"}) threw on a Python-written log: ${threw?.message}`,
      );
      assert.ok(count > 0, "expected at least one admin row");
      assert.ok(
        sawInit,
        "tn.ceremony.init must be present in the admin log and must verify",
      );
    } finally {
      if (client) {
        try {
          await client.close();
        } catch {
          /* ignore */
        }
      }
      rmSync(base, { recursive: true, force: true });
    }
  },
);
