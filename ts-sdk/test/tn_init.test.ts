import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../src/tn.js";

test("fresh mint records the per-stream admin filename (parity with Python)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-mint-admin-"));
  const yamlPath = join(dir, "tn.yaml");
  try {
    const tn = await Tn.init(yamlPath);
    // An admin event so the admin log materializes on disk (a bare TS
    // init does not write one, unlike Python's tn.ceremony.init row).
    await tn.vault.link("did:web:vault.example.org", "proj_x");
    await tn.close();
    const yaml = readFileSync(yamlPath, "utf8");
    assert.match(
      yaml,
      /admin_log_location: \.\/\.tn\/tn\/admin\/default\.ndjson/,
      `minted yaml should use the per-stream admin filename; got:\n${yaml}`,
    );
    assert.ok(
      existsSync(join(dir, ".tn", "tn", "admin", "default.ndjson")),
      "admin events should land in admin/default.ndjson",
    );
    assert.ok(
      !existsSync(join(dir, ".tn", "tn", "admin", "admin.ndjson")),
      "the early-era admin.ndjson filename must not be minted",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Tn.ephemeral returns a working instance", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const receipt = tn.info("smoke.test", { ok: 1 });
    assert.equal(typeof receipt.eventId, "string");
    assert.equal(typeof receipt.rowHash, "string");
  } finally {
    await tn.close();
  }
});

test("Tn.usingRust reports the wasm-backed emit path before and after lazy attach", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    // The wasm core attaches lazily on the first emit, so usingRust is
    // truthfully false until then (mirrors Python's using_rust).
    assert.equal(tn.usingRust(), false);
    tn.info("using_rust.test", { ok: 1 });
    assert.equal(tn.usingRust(), true);
  } finally {
    await tn.close();
  }
});

test("Tn.setLevel filters emits below threshold", () => {
  Tn.setLevel("info");
  try {
    assert.equal(Tn.isEnabledFor("debug"), false);
    assert.equal(Tn.isEnabledFor("info"), true);
    assert.equal(Tn.isEnabledFor("warning"), true);
  } finally {
    Tn.setLevel("debug");
  }
});

test("Tn.read iterates emitted entries", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    tn.info("evt.a", { x: 1 });
    tn.info("evt.b", { x: 2 });
    const entries = [...tn.read()];
    assert.equal(entries.length, 2);
    const first = entries[0] as Record<string, unknown>;
    const second = entries[1] as Record<string, unknown>;
    assert.equal(first["event_type"], "evt.a");
    assert.equal(second["event_type"], "evt.b");
  } finally {
    await tn.close();
  }
});
