/**
 * SILO: C6 — `tn` CLI verbs
 * TEST: a log written by Python's `tn` CLI can be read by `tn-js read`.
 *
 * This is the cross-CLI muscle-memory test. Operators routinely move
 * between languages — a script that writes logs in Python production
 * but reads them with `tn-js read` from a Node tooling shell MUST
 * surface the same envelopes. If the read CLIs drift, operators get
 * confused and start treating "I read X but it shows Y" as
 * everyday breakage.
 *
 * Flow:
 *   1. Spawn Python: `python -m tn.cli init <proj> --no-link
 *      --skip-confirm --keep-mnemonic`. Then a child Python writes
 *      one envelope via library tn.info().
 *   2. Invoke `node bin/tn-js.mjs read --yaml <proj>/tn.yaml --compact`.
 *   3. Assert exit 0; stdout contains the event_type we wrote.
 *
 * Asserts (named):
 *   - "python-cli-init-exit-0"
 *   - "python-wrote-event"
 *   - "tnjs-read-exit-0"
 *   - "tnjs-read-stdout-contains-event-type"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const TNJS = "C:/codex/tn/tn_proto/ts-sdk/bin/tn-js.mjs";
const PY =
  process.env["TN_REGRESSION_PYTHON"] ??
  "C:/codex/tn/tn_proto/.venv/Scripts/python.exe";

test("C6 (cross-CLI): tn-js read sees what Python's tn wrote", async () => {
  setTestContext({
    silo: "c6",
    test: "c6_ts_read_cross_cli::py_writes_tnjs_reads",
  });

  const projectDir = mkdtempSync(join(tmpdir(), "c6-xcli-"));
  const identityDir = `${projectDir}_id`;

  // Step 1: tn init via Python CLI.
  const proj = join(projectDir, "myproject");
  const initEnv = {
    ...process.env,
    TN_IDENTITY_DIR: identityDir,
    TN_NO_LINK: "1",
  };
  const init = spawnSync(
    PY,
    [
      "-m", "tn.cli",
      "init", proj,
      "--skip-confirm",
      "--keep-mnemonic",
      "--no-link",
    ],
    { env: initEnv, encoding: "utf-8", timeout: 30000 },
  );
  assertNamed({
    name: "python-cli-init-exit-0",
    expected: 0,
    observed: init.status ?? -1,
    onMiss:
      `python -m tn.cli init exited ${init.status}. ` +
      `stderr=${JSON.stringify(init.stderr?.slice(0, 400) ?? "")}`,
  });

  const yamlPath = join(proj, "tn.yaml");
  // Sanity: yaml is on disk.
  if (!existsSync(yamlPath)) {
    throw new Error(`tn init didn't produce ${yamlPath}`);
  }

  // Step 2: write one envelope using the Python library (so we know
  // the log path is initialized the same way a normal Python user
  // would do it).
  const writeProc = spawnSync(
    PY,
    [
      "-c",
      `
import os, sys
os.environ['TN_IDENTITY_DIR'] = r'${identityDir.replace(/\\/g, "\\\\")}'
os.environ['TN_NO_LINK'] = '1'
import tn
tn.init(r'${yamlPath.replace(/\\/g, "\\\\")}')
tn.info("c6.xcli.smoke", greeting="hello-from-python")
tn.flush_and_close()
print("ok")
`,
    ],
    { env: initEnv, encoding: "utf-8", timeout: 30000 },
  );
  assertNamed({
    name: "python-wrote-event",
    expected: 0,
    observed: writeProc.status ?? -1,
    onMiss:
      `Python tn.info subprocess exited ${writeProc.status}. ` +
      `stderr=${JSON.stringify(writeProc.stderr?.slice(0, 400) ?? "")}`,
  });

  // Step 3: tn-js read.
  const tnjs = spawnSync(
    "node",
    [TNJS, "read", "--yaml", yamlPath, "--compact"],
    { encoding: "utf-8", timeout: 30000 },
  );
  assertNamed({
    name: "tnjs-read-exit-0",
    expected: 0,
    observed: tnjs.status ?? -1,
    onMiss:
      `tn-js read --yaml ${yamlPath} exited ${tnjs.status}. ` +
      `stderr=${JSON.stringify(tnjs.stderr?.slice(0, 400) ?? "")}`,
  });

  assertNamed({
    name: "tnjs-read-stdout-contains-event-type",
    expected: true,
    observed:
      typeof tnjs.stdout === "string" &&
      tnjs.stdout.includes("c6.xcli.smoke"),
    onMiss:
      `tn-js read stdout didn't include the Python-written event_type ` +
      `'c6.xcli.smoke'. The Python and TS read paths see different ` +
      `parsings of the same on-disk log. Stdout sample: ` +
      `${JSON.stringify(tnjs.stdout?.slice(0, 600) ?? "")}`,
  });

  void assert;
});
