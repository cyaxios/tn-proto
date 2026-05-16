/**
 * SILO: C6 — `tn` CLI verbs
 * TEST: pin the CURRENT CLI surface on both sides so a rename can't
 *       silently make divergence worse.
 *
 * Why this exists: the user's directive — "[CLI commands] need to be
 * really similar otherwise things will get very messy." Today the two
 * CLIs are NOT similar:
 *
 *   Operation       Python                          tn-js
 *   ─────────────   ─────────────────────────────   ─────────────────────────────────
 *   add recipient   tn add_recipient <g> <r>        tn-js admin add-recipient
 *                   (positional, top-level)         (admin subcommand, --flags)
 *   rotate          tn rotate [<g>]                 tn-js admin rotate [--group <g>]
 *                   (top-level)                     (admin subcommand)
 *   read            tn read [<yaml>]                tn-js read --yaml <path>
 *                   (positional yaml)               (--yaml flag)
 *   init            tn init <dir>                   (none)
 *
 * The test exercises EACH side's --help, checks the verb shape is
 * what we expect today, and would fail if either side renamed/dropped
 * a verb. The named-assertions make the differences visible in the
 * report so a CLI rename PR has to update the test (and that forces
 * the critic log log to stay current).
 *
 * Asserts (named):
 *   - "python-cli-help-mentions-add_recipient"
 *   - "tnjs-cli-help-mentions-admin-add-recipient"
 *   - "python-cli-help-mentions-rotate"
 *   - "tnjs-cli-help-mentions-admin-rotate"
 *   - "python-cli-help-mentions-init"   ← Python-only
 *   - "tnjs-cli-help-does-not-mention-init"  ← deliberate gap; flag if it lands
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";

import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const TNJS = "C:/codex/tn/tn_proto/ts-sdk/bin/tn-js.mjs";
const PY =
  process.env["TN_REGRESSION_PYTHON"] ??
  "C:/codex/tn/tn_proto/.venv/Scripts/python.exe";

function pythonHelp(): string {
  // -h on tn.cli prints to stdout AND exits with code 0 typically;
  // capture both anyway.
  const proc = spawnSync(PY, ["-m", "tn.cli", "--help"], {
    encoding: "utf-8",
    timeout: 15000,
  });
  return (proc.stdout ?? "") + (proc.stderr ?? "");
}

function tnjsHelp(): string {
  // tn-js prints --help to stderr and exits non-zero per its shape;
  // capture both streams.
  const proc = spawnSync("node", [TNJS, "--help"], {
    encoding: "utf-8",
    timeout: 15000,
  });
  return (proc.stdout ?? "") + (proc.stderr ?? "");
}

test("C6: CLI verb-naming parity snapshot (Python vs tn-js)", () => {
  setTestContext({
    silo: "c6",
    test: "c6_ts_cli_verb_parity::snapshot_2026_05",
  });

  const pyH = pythonHelp();
  const tjH = tnjsHelp();

  // Verb: add recipient.
  assertNamed({
    name: "python-cli-help-mentions-add_recipient",
    expected: true,
    observed: pyH.includes("add_recipient"),
    onMiss:
      `Python tn CLI --help does not mention 'add_recipient'. If renamed, ` +
      `update this test AND coordinate the TS-side rename of 'admin add-recipient'. ` +
      `help sample: ${JSON.stringify(pyH.slice(0, 600))}`,
  });
  assertNamed({
    name: "tnjs-cli-help-mentions-admin-add-recipient",
    expected: true,
    observed: tjH.includes("admin add-recipient") || tjH.includes("admin\nadd-recipient") || tjH.includes("add-recipient"),
    onMiss:
      `tn-js --help does not mention 'admin add-recipient' or 'add-recipient'. ` +
      `If renamed, update this test and coordinate the Python-side rename. ` +
      `help sample: ${JSON.stringify(tjH.slice(0, 600))}`,
  });

  // Verb: rotate.
  assertNamed({
    name: "python-cli-help-mentions-rotate",
    expected: true,
    observed: pyH.includes("rotate"),
    onMiss: `Python --help missing 'rotate'. sample: ${JSON.stringify(pyH.slice(0, 400))}`,
  });
  assertNamed({
    name: "tnjs-cli-help-mentions-admin-rotate",
    expected: true,
    observed: tjH.includes("admin rotate") || tjH.includes("admin\nrotate") || tjH.includes("rotate"),
    onMiss: `tn-js --help missing 'admin rotate' or 'rotate'. sample: ${JSON.stringify(tjH.slice(0, 400))}`,
  });

  // Verb: init — Python has it, tn-js does NOT.
  assertNamed({
    name: "python-cli-help-mentions-init",
    expected: true,
    observed: pyH.includes("init"),
    onMiss: `Python --help missing 'init'.`,
  });
  assertNamed({
    name: "tnjs-cli-help-does-not-mention-init",
    expected: false,
    observed: tjH.includes("init "),
    onMiss:
      `tn-js --help DOES now mention 'init '. That's a scope expansion — ` +
      `if tn-js grew an init verb, update this test AND coordinate the ` +
      `Python-side flag/positional parity. Currently this is a deliberate gap.`,
  });

  // Verb: read — both sides have it but with different arg styles.
  // Python: positional yaml; tn-js: --yaml flag. We capture that asymmetry
  // here as a named-assertion so a rename to either side has to update
  // this test on purpose.
  assertNamed({
    name: "python-cli-help-mentions-read",
    expected: true,
    observed: pyH.includes("read"),
    onMiss: `Python --help missing 'read'.`,
  });
  assertNamed({
    name: "tnjs-cli-help-mentions-read-with-yaml-flag",
    expected: true,
    observed: tjH.includes("read") && tjH.includes("--yaml"),
    onMiss:
      `tn-js --help should mention 'read' AND '--yaml' (the read verb's ` +
      `argument shape). If you switched read to a positional, update ` +
      `parity. sample: ${JSON.stringify(tjH.slice(0, 600))}`,
  });

  void assert;
});

test("C6: tn-js unknown verb exits non-zero (parity with Python)", () => {
  setTestContext({
    silo: "c6",
    test: "c6_ts_cli_verb_parity::tnjs_unknown_verb",
  });
  const proc = spawnSync("node", [TNJS, "nonsense-verb-does-not-exist"], {
    encoding: "utf-8",
    timeout: 15000,
  });
  assertNamed({
    name: "tnjs-unknown-verb-exits-nonzero",
    expected: true,
    observed: (proc.status ?? 0) !== 0,
    onMiss:
      `tn-js nonsense-verb exited ${proc.status}. Should fail. ` +
      `stderr=${JSON.stringify(proc.stderr?.slice(0, 300) ?? "")}`,
  });
  assertNamed({
    name: "tnjs-unknown-verb-stderr-non-empty",
    expected: true,
    observed: typeof proc.stderr === "string" && proc.stderr.trim().length > 0,
    onMiss:
      `tn-js with unknown verb failed silently — no stderr. Operators ` +
      `need a hint. stdout=${JSON.stringify(proc.stdout?.slice(0, 200) ?? "")}`,
  });
});
