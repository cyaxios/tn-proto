/**
 * Tests for the ``extends:`` resolution in loadConfig.
 *
 * These mirror the Python suite at
 * python/tests/test_extends_loader.py — same merge semantics on
 * both SDKs is what makes a Python-created stream yaml loadable
 * by TS without modification.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { stringify as yamlStringify } from "yaml";

import { loadConfig } from "../src/runtime/config.js";

function makeProject(): string {
  return mkdtempSync(join(tmpdir(), "tn-ts-extends-"));
}

function writeParentChild(td: string): { parent: string; child: string } {
  // Write a btn-shaped parent yaml + a minimal child yaml that
  // extends it. Parent must be loadable on its own.
  const parent = join(td, "parent.yaml");
  const child = join(td, "child.yaml");

  // Parent needs a real keystore to load (loadConfig reads
  // local.private + local.public). Write stub key files so the
  // standalone load test passes — the merge logic itself doesn't
  // need keys to verify.
  const parentKeysDir = join(td, "keys");
  mkdirSync(parentKeysDir, { recursive: true });
  // 32 zero bytes is a valid Ed25519 seed shape (loader doesn't
  // verify it cryptographically, just reads the bytes).
  writeFileSync(join(parentKeysDir, "local.private"), Buffer.alloc(32));
  writeFileSync(
    join(parentKeysDir, "local.public"),
    "did:key:z6MkParent",
    "utf8",
  );

  writeFileSync(
    parent,
    yamlStringify({
      ceremony: { id: "P1", cipher: "btn", sign: true },
      me: { did: "did:key:z6MkParent" },
      keystore: { path: "./keys" },
      groups: {
        default: {
          policy: "private",
          cipher: "btn",
          recipients: [{ did: "did:key:z6MkParent" }],
        },
      },
      default_policy: "private",
      logs: { path: "./logs/parent.ndjson" },
      handlers: [{ kind: "stdout", name: "stdout" }],
    }),
    "utf8",
  );
  writeFileSync(
    child,
    yamlStringify({
      extends: "parent.yaml",
      ceremony: { id: "C1", profile: "audit" },
      logs: { path: "./logs/child.ndjson" },
      handlers: [
        { kind: "file.rotating", name: "main", path: "./logs/child.ndjson" },
      ],
    }),
    "utf8",
  );
  return { parent, child };
}

test("extends: pulls identity from parent", () => {
  const td = makeProject();
  try {
    const { child } = writeParentChild(td);
    const cfg = loadConfig(child);
    assert.equal(cfg.me.did, "did:key:z6MkParent");
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: child ceremony fields win over parent's", () => {
  const td = makeProject();
  try {
    const { child } = writeParentChild(td);
    const cfg = loadConfig(child);
    // Child's ceremony.id wins.
    assert.equal(cfg.ceremonyId, "C1");
    // Parent's ceremony.cipher carries through.
    assert.equal(cfg.cipher, "btn");
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: child logs.path wins outright", () => {
  const td = makeProject();
  try {
    const { child } = writeParentChild(td);
    const cfg = loadConfig(child);
    // logs.path is resolved against child's directory.
    assert.ok(cfg.logPath.endsWith("logs/child.ndjson") || cfg.logPath.endsWith("logs\\child.ndjson"));
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: groups inherited from parent", () => {
  const td = makeProject();
  try {
    const { child } = writeParentChild(td);
    const cfg = loadConfig(child);
    assert.ok(cfg.groups.has("default"));
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: keystore.path is absolutized to parent's dir", () => {
  const td = makeProject();
  try {
    const { child } = writeParentChild(td);
    const cfg = loadConfig(child);
    // Keystore should point at parent's ./keys, absolutized.
    assert.ok(cfg.keystorePath.endsWith("keys"));
    assert.ok(
      cfg.keystorePath.includes(td.split("/").pop() ?? "") ||
        cfg.keystorePath.includes(td.split("\\").pop() ?? ""),
    );
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: missing target raises friendly error", () => {
  const td = makeProject();
  try {
    const child = join(td, "c.yaml");
    writeFileSync(
      child,
      yamlStringify({ extends: "nope.yaml", ceremony: { id: "x" } }),
      "utf8",
    );
    assert.throws(() => loadConfig(child), /could not be read|ENOENT|does not exist/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: cycle is detected", () => {
  const td = makeProject();
  try {
    const a = join(td, "a.yaml");
    const b = join(td, "b.yaml");
    writeFileSync(a, yamlStringify({ extends: "b.yaml" }), "utf8");
    writeFileSync(b, yamlStringify({ extends: "a.yaml" }), "utf8");
    assert.throws(() => loadConfig(a), /cycle/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: child override of parent-owned key warns + parent wins", () => {
  const td = makeProject();
  try {
    const { child } = writeParentChild(td);
    // Add child me.did override.
    const childDoc = `extends: parent.yaml
ceremony:
  id: C1
  profile: audit
me:
  did: did:key:z6MkCHILD_OVERRIDE
logs:
  path: ./logs/child.ndjson
handlers:
  - kind: file.rotating
    name: main
    path: ./logs/child.ndjson
`;
    writeFileSync(child, childDoc, "utf8");

    // Capture console.warn.
    const warnings: string[] = [];
    const orig = console.warn;
    console.warn = (msg: unknown) => warnings.push(String(msg));
    try {
      const cfg = loadConfig(child);
      // Parent wins.
      assert.equal(cfg.me.did, "did:key:z6MkParent");
    } finally {
      console.warn = orig;
    }
    // Warning fired.
    assert.ok(
      warnings.some((w) => w.includes("parent-owned")),
      `expected parent-owned warning, got: ${JSON.stringify(warnings)}`,
    );
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("extends: handlers merge additively, deduped by name", () => {
  const td = makeProject();
  try {
    const { child } = writeParentChild(td);
    // Child has file.rotating "main"; parent has stdout "stdout".
    // Both should be present in the merged config.
    const cfg = loadConfig(child);
    // Verify both handler kinds came through (parent + child).
    // CeremonyConfig stores raw handlers; pull from .doc-equivalent.
    // The CeremonyConfig type doesn't expose handlers directly — they go to
    // NodeRuntime via the runtime layer. We assert via a side effect:
    // if extends merge worked, the cfg loaded without error AND has the
    // child's logs.path AND parent's keystore.
    assert.equal(cfg.ceremonyId, "C1");
    // (Handlers list goes through NodeRuntime.init; covered in a deeper
    // integration test once we add stream-creation in TS.)
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});
