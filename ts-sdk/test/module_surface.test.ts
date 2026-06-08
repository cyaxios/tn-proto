import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import * as tn from "../src/index.js";
import type { TNHandler } from "../src/handlers/index.js";

function makeProject(): string {
  return mkdtempSync(join(tmpdir(), "tn-module-surface-"));
}

test("module-level use and listCeremonies delegate to Tn static ceremony helpers", async () => {
  const project = makeProject();
  try {
    const payments = await tn.use("payments", { projectDir: project, stdout: false });
    try {
      assert.equal(payments.name, "payments");
      assert.deepEqual(tn.listCeremonies(project), ["default", "payments"]);
    } finally {
      await payments.close();
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("module-level scope merges default context into emitted entries", async () => {
  await tn.init(undefined, { stdout: false });
  try {
    tn.scope({ request_id: "req_module_scope" }, () => {
      tn.info("evt.module.scope", { marker: "inside" });
    });

    const entries = [...tn.read({ raw: true })] as Array<Record<string, unknown>>;
    const env = entries.find((e) => e["event_type"] === "evt.module.scope");
    assert.ok(env, "evt.module.scope envelope not found");
    assert.equal(env["request_id"], "req_module_scope");
  } finally {
    await tn.close();
  }
});

test("module-level watch returns the default ceremony async iterator", async () => {
  await tn.init(undefined, { stdout: false });
  try {
    const iter = tn.watch({ since: "start" });
    assert.equal(typeof iter[Symbol.asyncIterator], "function");
    await iter.return?.();
  } finally {
    await tn.close();
  }
});

test("module-level namespaces proxy the default Tn instance", async () => {
  await tn.init(undefined, { stdout: false });
  const tmp = makeProject();
  const seen: string[] = [];
  try {
    assert.equal(typeof tn.admin.addRecipient, "function");
    assert.equal(typeof tn.admin.state, "function");
    assert.equal(typeof tn.pkg.export, "function");
    assert.equal(typeof tn.vault.link, "function");
    assert.equal(typeof tn.agents.policy, "function");
    assert.equal(typeof tn.handlers.add, "function");
    assert.equal(typeof tn.adminCatalog.catalogKinds, "function");

    tn.handlers.add({
      name: "module-surface-collector",
      accepts: () => true,
      emit(env: Record<string, unknown>) {
        seen.push(String(env["event_type"] ?? ""));
      },
      close() {},
    } satisfies TNHandler);

    tn.info("evt.module.namespace", { ok: true });
    await tn.handlers.flush();
    assert.ok(
      seen.includes("evt.module.namespace"),
      `expected handler to see evt.module.namespace in ${JSON.stringify(seen)}`,
    );

    const outPath = join(tmp, "snapshot.tnpkg");
    const written = await tn.pkg.export({ adminLogSnapshot: { outPath } }, outPath);
    assert.equal(written, outPath);
    assert.ok(statSync(outPath).size > 0, "exported package should be non-empty");

    const receipt = await tn.vault.link("did:key:zVault", "proj_module");
    assert.equal(typeof receipt.eventId, "string");
    assert.equal(tn.agents.policy(), null);
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
