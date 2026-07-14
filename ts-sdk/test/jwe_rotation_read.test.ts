// jwe sibling of btn_rotation_read.test.ts, mirroring the Python
// tests/test_rotate_multi_kit.py::test_jwe_read_spans_rotation_boundary
// guarantee: rotation archives the reader key as `.jwe.mykey.revoked.<ts>`,
// and a read after re-init must still open pre-rotation entries via those
// prior keys instead of surfacing `$no_read_key`.
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AdminNamespace } from "../src/admin/index.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { readTnpkg } from "../src/tnpkg_io.js";

async function orderIds(rt: NodeRuntime): Promise<Set<string>> {
  const ids = new Set<string>();
  for await (const e of rt.readAsync()) {
    if (e.envelope["event_type"] !== "order.created") continue;
    const body = e.plaintext["default"] as Record<string, unknown> | undefined;
    if (body && body["order_id"] !== undefined) ids.add(String(body["order_id"]));
  }
  return ids;
}

test("jwe read spans a rotation boundary (rotated in place)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "jwe-rot-read-"));
  const yaml = join(dir, "tn.yaml");
  try {
    let rt = NodeRuntime.init(yaml, { cipher: "jwe" });
    const admin = new AdminNamespace(rt);
    await rt.emitAsync("info", "order.created", { order_id: "OLD" });
    await admin.rotate("default");
    await rt.emitAsync("info", "order.created", { order_id: "NEW" });

    const ks = rt.config.keystorePath;
    assert.ok(
      readdirSync(ks).some((f) => f.startsWith("default.jwe.mykey.revoked.")),
      "rotation should archive the prior jwe reader key",
    );

    // Same-process read: the refreshed in-memory keystore must span the boundary.
    const sameProcess = await orderIds(rt);
    assert.ok(sameProcess.has("NEW"), `post-rotation entry should read; saw ${[...sameProcess]}`);
    assert.ok(
      sameProcess.has("OLD"),
      `pre-rotation entry should read after rotate (same process); saw ${[...sameProcess]}`,
    );

    // Fresh init: the reloaded keystore must pick the archived keys back up.
    rt = NodeRuntime.init(yaml);
    const reloaded = await orderIds(rt);
    assert.ok(reloaded.has("NEW"), `post-rotation entry should read; saw ${[...reloaded]}`);
    assert.ok(
      reloaded.has("OLD"),
      `pre-rotation entry should read after rotate + re-init; saw ${[...reloaded]}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("self full_keystore restores current and historical JWE runtime state", async () => {
  const root = mkdtempSync(join(tmpdir(), "jwe-full-restore-"));
  const sourceYaml = join(root, "source", "tn.yaml");
  try {
    const source = NodeRuntime.init(sourceYaml, { cipher: "jwe" });
    await source.emitAsync("info", "order.created", { order_id: "OLD" });
    await new AdminNamespace(source).rotate("default");
    await source.emitAsync("info", "order.created", { order_id: "NEW" });
    const sourceLog = source.config.logPath;
    const ks = source.config.keystorePath;
    const backup = join(root, "jwe-full.tnpkg");
    source.exportPkg({ kind: "full_keystore", confirmIncludesSecrets: true }, backup);

    const bodyNames = [...readTnpkg(backup).body.keys()];
    for (const required of [
      "body/default.jwe.mykey",
      "body/default.jwe.sender",
      "body/default.jwe.recipients",
    ]) {
      assert.ok(bodyNames.includes(required), `full backup missing ${required}`);
    }
    assert.ok(bodyNames.some((name) => name.startsWith("body/default.jwe.mykey.revoked.")));
    assert.ok(bodyNames.some((name) => name.startsWith("body/default.jwe.sender.revoked.")));
    assert.ok(bodyNames.some((name) => name.startsWith("body/default.jwe.recipients.revoked.")));
    for (const name of readdirSync(ks)) {
      if (name.includes(".jwe.")) rmSync(join(ks, name), { force: true });
    }
    writeFileSync(sourceYaml, "# damaged before restore\n", "utf8");
    const receipt = source.absorbPkg(backup);
    assert.equal(receipt.rejectedReason, undefined);
    source.close();
    const restored = NodeRuntime.init(sourceYaml);
    const ids = new Set<string>();
    for await (const entry of restored.readAsync(sourceLog)) {
      const id = entry.plaintext["default"]?.["order_id"];
      if (typeof id === "string") ids.add(id);
    }
    assert.deepEqual(ids, new Set(["OLD", "NEW"]));
    restored.close();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
