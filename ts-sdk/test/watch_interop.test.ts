import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../src/tn.js";

/**
 * Detect whether a Python interpreter with tn-protocol installed is available.
 * Returns the python binary path on success, null otherwise.
 */
function pickPython(): string | null {
  const candidates = [
    process.env["TN_PYTHON"],
    "python3",
    "python",
  ].filter((v): v is string => typeof v === "string" && v.length > 0);

  for (const bin of candidates) {
    try {
      const result = spawnSync(bin, ["-c", "import tn; print('ok')"], {
        encoding: "utf8",
        timeout: 10_000,
      });
      if (result.status === 0 && result.stdout.trim() === "ok") {
        return bin;
      }
    } catch {
      /* try next */
    }
  }
  return null;
}

test(
  "Python tn.watch sees entries written by TS Tn.info",
  {
    skip:
      pickPython() === null
        ? "Python tn-protocol not available locally; runs in CI"
        : false,
  },
  async () => {
    const python = pickPython()!;
    const tmp = mkdtempSync(join(tmpdir(), "tn-watch-interop-"));
    let tn: Tn | null = null;
    try {
      const yamlPath = join(tmp, "tn.yaml");
      tn = await Tn.init(yamlPath);
      tn.info("interop.alpha", { x: 1 });
      tn.info("interop.beta", { x: 2 });
      tn.info("interop.gamma", { x: 3 });
      await tn.close();
      tn = null;

      // Spawn `python -m tn.watch <yaml> --once --since start`. The helper
      // CLI already prints decoded entries as JSONL to stdout. We assert
      // the three event_types we emitted from TS appear in the Python
      // output in order.
      const result = spawnSync(
        python,
        ["-m", "tn.watch", yamlPath, "--once", "--since", "start"],
        { encoding: "utf8", timeout: 30_000 },
      );

      if (result.status !== 0) {
        throw new Error(
          `python -m tn.watch failed (status ${result.status}): ${result.stderr || result.stdout}`,
        );
      }

      const lines = result.stdout
        .trim()
        .split("\n")
        .filter((l) => l.length > 0);
      const eventTypes = lines
        .map((l) => {
          try {
            return JSON.parse(l).event_type as string;
          } catch {
            return null;
          }
        })
        .filter((s): s is string => s !== null);

      // The Python output should include all three events we emitted.
      // (May also include bootstrap / admin events; use includes() rather
      // than deepEqual to allow for those.)
      assert.ok(
        eventTypes.includes("interop.alpha"),
        `expected interop.alpha; got: ${eventTypes.join(", ")}`,
      );
      assert.ok(
        eventTypes.includes("interop.beta"),
        `expected interop.beta; got: ${eventTypes.join(", ")}`,
      );
      assert.ok(
        eventTypes.includes("interop.gamma"),
        `expected interop.gamma; got: ${eventTypes.join(", ")}`,
      );

      // Ordering check — alpha should come before beta which should come
      // before gamma in the Python decoded output.
      const idxA = eventTypes.indexOf("interop.alpha");
      const idxB = eventTypes.indexOf("interop.beta");
      const idxC = eventTypes.indexOf("interop.gamma");
      assert.ok(
        idxA < idxB && idxB < idxC,
        `expected alpha < beta < gamma; got indexes ${idxA}, ${idxB}, ${idxC}`,
      );
    } finally {
      if (tn) {
        try {
          await tn.close();
        } catch {
          /* ignore */
        }
      }
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);
