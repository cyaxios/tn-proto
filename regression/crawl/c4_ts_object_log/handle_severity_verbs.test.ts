/**
 * SILO: C4 — TS object-level logging
 * TEST: each severity verb on a Tn instance stamps the correct level.
 * SEE: regression/crawl/c4_ts_object_log/README.md
 *
 * Parity with C2 (Python). The TS Tn instance methods info/warning/
 * error/debug/log must each stamp the correct level in the envelope.
 * Cross-language drift here would let a Python publisher and a TS
 * reader disagree about what level a warning is at.
 */
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn, setLevel } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";
import { LogQuery } from "../../_shared/log_query.js";

test("C4: Tn instance severity verbs stamp correct level", async () => {
  setTestContext({ silo: "c4", test: "c4_handle_severity_verbs::levels" });

  const td = mkdtempSync(join(tmpdir(), "c4-sev-"));
  const cwdBefore = process.cwd();
  process.chdir(td);

  // process-global level — debug verb wouldn't fire below threshold.
  setLevel("debug");

  let t: Tn | undefined;
  try {
    t = await Tn.use("ops");

    t.info("ops.sev.info", { marker: "info" });
    t.warning("ops.sev.warning", { marker: "warning" });
    t.error("ops.sev.error", { marker: "error" });
    t.debug("ops.sev.debug", { marker: "debug" });
    t.log("ops.sev.log", { marker: "log" });

    const log = new LogQuery({ ceremonyPath: t.yamlPath });

    const cases: Array<{ event: string; level: string }> = [
      { event: "ops.sev.info", level: "info" },
      { event: "ops.sev.warning", level: "warning" },
      { event: "ops.sev.error", level: "error" },
      { event: "ops.sev.debug", level: "debug" },
      { event: "ops.sev.log", level: "" }, // severity-less log → empty string
    ];
    for (const c of cases) {
      const tag = c.event.split(".").pop() ?? c.event;
      const env = log.assertContains({
        name: `handle-${tag}-stamped`,
        where: { event_type: c.event },
        onMiss:
          `Tn instance's ${tag}() didn't produce its envelope. ` +
          "Check ts-sdk/src/tn.ts:Tn.{info,warning,error,debug,log} methods.",
      });
      const observedLevel = env.get("level");
      assertNamed({
        name: `handle-${tag}-is-${c.level || "empty"}`,
        expected: c.level,
        observed: observedLevel,
        onMiss:
          `Tn instance's ${c.event} envelope has level=` +
          JSON.stringify(observedLevel) +
          ", expected " +
          JSON.stringify(c.level) +
          `. The ${tag}() method is passing the wrong level string.`,
      });
    }
  } finally {
    if (t !== undefined) await t.close();
    process.chdir(cwdBefore);
  }
});
