import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../src/tn.js";

test("tn.agents.policy returns null when no policy file is present", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const policy = tn.agents.policy();
    assert.equal(policy, null);
  } finally {
    await tn.close();
  }
});

test("tn.agents.reloadPolicy returns null when no policy file is present", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const policy = await tn.agents.reloadPolicy();
    assert.equal(policy, null);
  } finally {
    await tn.close();
  }
});

test("tn.agents.addRuntime mints a kit bundle and returns the path", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-agents-test-"));
  try {
    const outPath = join(tmp, "runtime.tnpkg");
    const written = await tn.agents.addRuntime({
      runtimeDid: "did:key:zAgentRuntime",
      groups: ["default"],
      outPath,
    });
    assert.equal(written, outPath);
    assert.ok(statSync(outPath).size > 0, "kit bundle should be non-empty");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
