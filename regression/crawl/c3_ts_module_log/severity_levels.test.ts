/**
 * SILO: C3 — TS module-level logging
 * TEST: every public severity verb writes an envelope with the correct level
 * SEE: regression/crawl/c3_ts_module_log/README.md
 *
 * Mirrors C1's severity-level test on the TS side. After the
 * module-level surface was added (api-critique 2026-05-14 — C3), this
 * test exercises `tn.info`, `tn.warning`, `tn.error`, `tn.debug`,
 * `tn.log` and asserts the level field on each emitted envelope.
 *
 * Asserts (named): one "level-<verb>-stamped" per severity verb plus
 * one "level-<verb>-is-<expected>" per verb.
 *
 * Why we care: the slim-down in PR #63 routes emit through wasm. A
 * regression in the level wiring (e.g. info maps to debug, log
 * surfaces a non-empty level) would slip past unit tests but show
 * up here.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as tn from "../../../ts-sdk/src/index.ts";
import { NodeRuntime } from "../../../ts-sdk/src/index.ts";

import { assertNamed, setTestContext } from "../../_shared/assertions.js";
import { LogQuery } from "../../_shared/log_query.js";

test("C3: each severity verb stamps the correct level", async () => {
  setTestContext({ silo: "c3", test: "c3_severity_levels::each_verb" });

  const td = mkdtempSync(join(tmpdir(), "c3-sev-"));
  const yamlPath = join(td, "tn.yaml");
  const noderuntime = NodeRuntime.init(yamlPath);
  noderuntime.close();

  await tn.init(yamlPath);
  // Lower the level so debug isn't filtered.
  tn.setLevel("debug");

  try {
    tn.info("c3.sev.info", { marker: "info-marker" });
    tn.warning("c3.sev.warning", { marker: "warning-marker" });
    tn.error("c3.sev.error", { marker: "error-marker" });
    tn.debug("c3.sev.debug", { marker: "debug-marker" });
    tn.log("c3.sev.log", { marker: "log-marker" });

    const log = new LogQuery({ ceremonyPath: yamlPath });

    const cases: Array<{ et: string; expected: string; onMiss: string }> = [
      {
        et: "c3.sev.info",
        expected: "info",
        onMiss: "tn.info envelope's level field is wrong. Check ts-sdk/src/tn.ts:info severity arg.",
      },
      {
        et: "c3.sev.warning",
        expected: "warning",
        onMiss: "tn.warning envelope's level field is wrong.",
      },
      {
        et: "c3.sev.error",
        expected: "error",
        onMiss: "tn.error envelope's level field is wrong.",
      },
      {
        et: "c3.sev.debug",
        expected: "debug",
        onMiss: "tn.debug envelope's level field is wrong. Also verify setLevel('debug') was honored.",
      },
      {
        et: "c3.sev.log",
        expected: "",
        onMiss:
          "tn.log is severity-less — its envelope's level must be the empty string. Check ts-sdk/src/tn.ts:log instance method.",
      },
    ];

    for (const c of cases) {
      const env = log.assertContains({
        name: `level-${c.et.split(".").pop()}-stamped`,
        where: { event_type: c.et },
        onMiss: `tn.${c.et.split(".").pop()}(...) didn't produce its envelope. Check ts-sdk/src/index.ts bare-export wrappers.`,
      });
      assertNamed({
        name: `level-${c.et.split(".").pop()}-is-${c.expected || "empty"}`,
        expected: c.expected,
        observed: env.get("level"),
        onMiss: c.onMiss,
      });
    }
  } finally {
    // Reset level so it doesn't bleed into other tests.
    tn.setLevel("info");
    await tn.close();
  }
  // Silence unused-import warning from strict mode.
  void assert;
});
