// Tests for `client.adminAddAgentRuntime()` per spec §2.8.

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { readTnpkg } from "../src/index.js";
import { Tn } from "../src/tn.js";

test("adminAddAgentRuntime: bundle contains N+1 kits (groups + tn.agents)", async () => {
  const tn = await Tn.ephemeral();
  try {
    const td = mkdtempSync(join(tmpdir(), "tn-agent-out-"));
    try {
      const out = await tn.agents.addRuntime({
        runtimeDid: "did:key:z6MkRuntimeAAA",
        groups: ["default"],
        outPath: join(td, "runtime.tnpkg"),
      });
      const { manifest, body } = readTnpkg(out);
      assert.equal(manifest.kind, "kit_bundle");
      assert.equal(manifest.toDid, "did:key:z6MkRuntimeAAA");
      const names = [...body.keys()].sort();
      // Must include both `default.btn.mykit` and `tn.agents.btn.mykit`.
      assert.ok(
        names.includes("body/default.btn.mykit"),
        `default kit missing — got ${JSON.stringify(names)}`,
      );
      assert.ok(
        names.includes("body/tn.agents.btn.mykit"),
        `tn.agents kit missing — got ${JSON.stringify(names)}`,
      );
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  } finally {
    await tn.close();
  }
});

test("adminAddAgentRuntime: dedup when caller passes tn.agents in groups", async () => {
  const tn = await Tn.ephemeral();
  try {
    const td = mkdtempSync(join(tmpdir(), "tn-agent-out-"));
    try {
      const out = await tn.agents.addRuntime({
        runtimeDid: "did:key:z6MkRuntimeBBB",
        groups: ["default", "tn.agents"],
        outPath: join(td, "runtime.tnpkg"),
      });
      const { body } = readTnpkg(out);
      // Exactly one tn.agents kit (no double-mint).
      const agentsCount = [...body.keys()].filter((n) => n.includes("tn.agents")).length;
      assert.equal(agentsCount, 1, "dedup: tn.agents must appear only once");
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  } finally {
    await tn.close();
  }
});

test("adminAddAgentRuntime: rejects unknown groups", async () => {
  const tn = await Tn.ephemeral();
  try {
    const td = mkdtempSync(join(tmpdir(), "tn-agent-out-"));
    try {
      await assert.rejects(
        () =>
          tn.agents.addRuntime({
            runtimeDid: "did:key:z6MkRuntimeCCC",
            groups: ["nonexistent"],
            outPath: join(td, "runtime.tnpkg"),
          }),
        /not declared in this ceremony/,
      );
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  } finally {
    await tn.close();
  }
});
