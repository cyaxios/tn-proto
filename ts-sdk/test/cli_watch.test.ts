import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../src/tn.js";

test("tn-js watch --once dumps the log and exits 0", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-watch-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    const tn = await Tn.init(yamlPath);
    tn.info("cli.event.1", { x: 1 });
    tn.info("cli.event.2", { x: 2 });
    await tn.close();

    // Disable session-start log rotation so the CLI's Tn.init() does not
    // roll the events we just wrote to <log>.1.  Same pattern used by
    // agents_policy_published.test.ts.
    const yamlText = readFileSync(yamlPath, "utf8");
    writeFileSync(yamlPath, yamlText.replace(/rotate_on_init: true/, "rotate_on_init: false"));

    const result = await new Promise<{ stdout: string; code: number }>((resolve, reject) => {
      const proc = spawn(
        "node",
        ["./bin/tn-js.mjs", "watch", "--yaml", yamlPath, "--since", "start", "--once"],
        { cwd: process.cwd() },
      );
      let out = "";
      proc.stdout.on("data", (d) => (out += d.toString()));
      proc.stderr.on("data", (d) => process.stderr.write(d));
      proc.on("close", (code) => resolve({ stdout: out, code: code ?? -1 }));
      proc.on("error", reject);
    });

    assert.equal(result.code, 0, "tn-js watch --once should exit 0");
    const lines = result.stdout.trim().split("\n").filter((l) => l.length > 0);
    const eventTypes = lines.map((l) => JSON.parse(l).event_type);
    assert.ok(eventTypes.includes("cli.event.1"), `expected cli.event.1 in stdout; got ${eventTypes.join(", ")}`);
    assert.ok(eventTypes.includes("cli.event.2"), `expected cli.event.2 in stdout; got ${eventTypes.join(", ")}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
