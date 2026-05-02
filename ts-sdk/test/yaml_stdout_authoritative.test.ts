// FINDINGS S0.4 cross-binding port — yaml handlers list must be
// authoritative for stdout, including for user-level emits. The previous
// behavior added a default StdoutHandler regardless of yaml content;
// removing `- kind: stdout` from yaml had no effect on TS user emits.

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Tn } from "../src/tn.js";

function captureStdout<T>(fn: () => T): { value: T; output: string } {
  const original = process.stdout.write.bind(process.stdout);
  let buf = "";
  // @ts-expect-error monkey-patch for capture
  process.stdout.write = (chunk: string | Uint8Array): boolean => {
    buf += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  };
  try {
    const value = fn();
    return { value, output: buf };
  } finally {
    process.stdout.write = original;
  }
}

test("removing stdout from yaml's handlers list silences user emits (FINDINGS S0.4)", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-s04-"));
  const yamlPath = join(root, "register.yaml");
  try {
    // Mint a fresh ceremony so we can edit its yaml.
    const c1 = await Tn.init(yamlPath);
    await c1.close();

    // Strip `- kind: stdout` from the yaml so the operator's intent is
    // "no stdout for ANY emit." We do a regex-level edit because yaml
    // isn't a dependency in this test and the line shape is stable
    // (createFreshCeremony writes it as a single line).
    const original = readFileSync(yamlPath, "utf8");
    const stripped = original.replace(/^- kind: stdout\s*\n/m, "");
    assert.notEqual(stripped, original, "expected to remove a stdout entry");
    writeFileSync(yamlPath, stripped, "utf8");

    // Don't let TN_NO_STDOUT mask the result.
    const priorEnv = process.env["TN_NO_STDOUT"];
    delete process.env["TN_NO_STDOUT"];

    try {
      // Pre-init c2 before captureStdout so the async init doesn't race
      // with stdout capture.
      const c2 = await Tn.init(yamlPath);
      let output = "";
      try {
        ({ output } = captureStdout(() => {
          c2.info("evt.silent", { marker: "should_not_appear" });
        }));
      } finally {
        await c2.close();
      }

      // ``event_type`` is a public envelope field — visible in the
      // stdout JSON line if any was emitted. Field values like the
      // marker are inside the encrypted ciphertext and aren't a
      // reliable presence check.
      assert.ok(
        !output.includes("evt.silent"),
        `yaml omitted stdout but TS still emitted JSON to stdout. ` +
          `First 400 chars: ${output.slice(0, 400)}`,
      );
    } finally {
      if (priorEnv !== undefined) process.env["TN_NO_STDOUT"] = priorEnv;
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("keeping stdout in yaml's handlers list lets stdout fire (S0.4 happy path)", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-s04-on-"));
  const yamlPath = join(root, "register.yaml");
  try {
    const c1 = await Tn.init(yamlPath);
    await c1.close();

    // Yaml comes with stdout enabled by default. Don't edit.
    const priorEnv = process.env["TN_NO_STDOUT"];
    delete process.env["TN_NO_STDOUT"];
    try {
      // Pre-init c2 before captureStdout.
      const c2 = await Tn.init(yamlPath);
      let output = "";
      try {
        ({ output } = captureStdout(() => {
          c2.info("evt.loud", { marker: "should_appear" });
        }));
      } finally {
        await c2.close();
      }
      assert.ok(
        output.includes("evt.loud"),
        `yaml kept stdout but no JSON line landed on stdout. ` +
          `First 400 chars: ${output.slice(0, 400)}`,
      );
    } finally {
      if (priorEnv !== undefined) process.env["TN_NO_STDOUT"] = priorEnv;
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
