// Module-level surface parity — Finding 4.
//
// Python `import tn` exposes module-level use/watch/scope/read/log/admin/
// pkg/vault/... The TS module surface (`src/index.ts`) must offer the
// same shape AND `tn.admin` must resolve to the RUNTIME admin namespace
// (`tn.admin.addRecipient(...)`), not the static event catalog. The
// catalog moved to `tn.adminCatalog` to free the `admin` name.

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import * as tn from "../src/index.js";

function asRecord(v: unknown): Record<string, unknown> {
  return v as Record<string, unknown>;
}

test("module surface: verbs + runtime namespaces present and correctly bound", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-module-surface-"));
  let inst: Awaited<ReturnType<typeof tn.init>>;
  try {
    inst = await tn.init(join(dir, "tn.yaml"), { stdout: false });

    // --- bare verbs exist ---
    assert.equal(typeof tn.watch, "function", "tn.watch should be a function");
    assert.equal(typeof tn.scope, "function", "tn.scope should be a function");
    assert.equal(typeof tn.use, "function", "tn.use should be a function");
    assert.equal(typeof tn.listCeremonies, "function", "tn.listCeremonies should be a function");
    assert.equal(typeof tn.seal, "function", "tn.seal should be a function");
    assert.equal(typeof tn.unseal, "function", "tn.unseal should be a function");

    // --- tn.scope is bound to the default instance's context stack ---
    const inside = tn.scope({ scoped_field: 7 }, () => asRecord(tn.getContext()));
    assert.equal(inside["scoped_field"], 7, "scope body should see the layered field");
    assert.equal(
      asRecord(tn.getContext())["scoped_field"],
      undefined,
      "scope overlay should be popped after the body returns",
    );

    // --- tn.listCeremonies delegates to the static Tn.listCeremonies ---
    const ceremonies = tn.listCeremonies(dir);
    assert.ok(Array.isArray(ceremonies), "listCeremonies should return an array");

    // --- tn.admin is the RUNTIME namespace, not the static catalog ---
    assert.equal(
      typeof tn.admin.addRecipient,
      "function",
      "tn.admin.addRecipient proves the runtime AdminNamespace, not the catalog",
    );
    assert.equal(
      asRecord(tn.admin)["reduce"],
      undefined,
      "tn.admin must NOT expose the catalog's reduce() (collision resolved)",
    );

    // The proxy forwards to the live default instance: a method invoked
    // through `tn.admin` operates on the same runtime as `inst.admin`.
    assert.deepEqual(
      tn.admin.state(),
      inst.admin.state(),
      "tn.admin must resolve to the default instance's admin namespace",
    );

    // --- pkg / vault runtime namespaces present ---
    assert.equal(typeof tn.pkg.export, "function", "tn.pkg.export should be a function");
    assert.equal(typeof tn.pkg.absorb, "function", "tn.pkg.absorb should be a function");
    assert.equal(typeof tn.vault.link, "function", "tn.vault.link should be a function");
    assert.equal(typeof tn.vault.unlink, "function", "tn.vault.unlink should be a function");
  } finally {
    await tn.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("regression: static admin catalog reachable as tn.adminCatalog", () => {
  assert.equal(
    typeof tn.adminCatalog.reduce,
    "function",
    "catalog reduce() must survive under the new name",
  );
  assert.equal(typeof tn.adminCatalog.catalogKinds, "function");
  assert.equal(typeof tn.adminCatalog.validateEmit, "function");

  // It still works: catalogKinds() lists the tn.* admin event kinds.
  const kinds = tn.adminCatalog.catalogKinds();
  assert.ok(kinds.length >= 1);
  assert.ok(kinds.every((k) => k.event_type.startsWith("tn.")));
});
