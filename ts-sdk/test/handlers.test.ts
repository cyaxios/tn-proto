import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { DeviceKey, FileHandler, NodeRuntime, OpenTelemetryHandler } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";

// ---------------------------------------------------------------------------
// Shared ceremony factory (mirrors node_runtime.test.ts)
// ---------------------------------------------------------------------------

function makeCeremony(extra = ""): { yamlPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-handlers-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 10;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");

  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i++) indexMaster[i] = (i * 7 + 3) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) btnSeed[i] = (i * 11 + 5) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  const yaml =
    `ceremony:\n  id: handlers_test\n  mode: local\n  cipher: btn\n` +
    `${extra}` +
    `logs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\n` +
    `me:\n  did: ${dk.did}\n` +
    `public_fields:\n- timestamp\n- event_id\n- event_type\n- level\n` +
    `default_policy: private\n` +
    `groups:\n  default:\n    policy: private\n    cipher: btn\n` +
    `    recipients:\n    - did: ${dk.did}\nfields: {}\n`;

  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return { yamlPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// ---------------------------------------------------------------------------
// Test 1: FileHandler receives emitted envelopes
// ---------------------------------------------------------------------------

test("FileHandler receives emitted envelopes", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const rt = NodeRuntime.init(yamlPath);
    const handlerLog = join(yamlPath, "..", ".tn/logs", "handler.ndjson");
    rt.addHandler(new FileHandler("handler-file", handlerLog));

    rt.emit("info", "order.created", { amount: 100 });
    rt.emit("info", "order.shipped", { tracking: "ABC" });
    rt.emit("error", "order.failed", { reason: "card declined" });

    rt.close();

    assert.ok(existsSync(handlerLog), "handler log file should exist");
    const lines = readFileSync(handlerLog, "utf8").trim().split("\n");
    assert.equal(lines.length, 3, `expected 3 lines, got ${lines.length}`);

    const first = JSON.parse(lines[0]!);
    assert.equal(first.event_type, "order.created");
    assert.equal(first.sequence, 1);

    const third = JSON.parse(lines[2]!);
    assert.equal(third.event_type, "order.failed");
    assert.equal(third.level, "error");
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Test 2: FileHandler + rt.read() roundtrip (the handler log is also readable)
// ---------------------------------------------------------------------------

test("FileHandler log is readable via NodeRuntime.read()", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const rt = NodeRuntime.init(yamlPath);
    const handlerLog = join(yamlPath, "..", ".tn/logs", "handler-read.ndjson");
    rt.addHandler(new FileHandler("read-test", handlerLog));

    rt.emit("info", "product.viewed", { sku: "X100", qty: 2 });
    rt.emit("info", "product.viewed", { sku: "X200", qty: 1 });
    rt.close();

    // Read back via a fresh runtime — proves chain continuity + decryption.
    const rt2 = NodeRuntime.init(yamlPath);
    const entries = Array.from(rt2.read(handlerLog));
    assert.equal(entries.length, 2);
    assert.equal(entries[0]!.plaintext["default"]!["sku"], "X100");
    assert.equal(entries[1]!.plaintext["default"]!["sku"], "X200");
    assert.equal(entries[0]!.envelope["event_type"], "product.viewed");
    assert.equal(entries[0]!.valid.signature, true);
    assert.equal(entries[0]!.valid.rowHash, true);
    assert.equal(entries[0]!.valid.chain, true);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Test 3: FileHandler filter — only matching events reach the handler log
// ---------------------------------------------------------------------------

test("FileHandler filter routes only matching events", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const rt = NodeRuntime.init(yamlPath);
    const handlerLog = join(yamlPath, "..", ".tn/logs", "errors-only.ndjson");
    rt.addHandler(
      new FileHandler("errors", handlerLog, {
        filter: { levelIn: ["error", "warning"] },
      }),
    );

    rt.emit("info", "order.created", { amount: 50 });
    rt.emit("warning", "order.delayed", { days: 3 });
    rt.emit("error", "payment.failed", { code: "E01" });
    rt.emit("info", "order.completed", { ok: true });
    rt.close();

    const lines = readFileSync(handlerLog, "utf8").trim().split("\n");
    assert.equal(lines.length, 2, "only warning+error should reach handler");
    assert.equal(JSON.parse(lines[0]!).event_type, "order.delayed");
    assert.equal(JSON.parse(lines[1]!).event_type, "payment.failed");
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Test 4: FileHandler size-based rotation
// ---------------------------------------------------------------------------

test("FileHandler rotates at maxBytes", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const rt = NodeRuntime.init(yamlPath);
    const handlerLog = join(yamlPath, "..", ".tn/logs", "rotating.ndjson");
    // 1 KB threshold so we hit rotation quickly
    rt.addHandler(new FileHandler("rotating", handlerLog, { maxBytes: 1024, backupCount: 3 }));

    for (let i = 0; i < 20; i++) {
      rt.emit("info", "batch.item", { index: i, pad: "x".repeat(80) });
    }
    rt.close();

    assert.ok(existsSync(handlerLog), "primary log must exist");
    const backup1 = `${handlerLog}.1`;
    assert.ok(existsSync(backup1), "at least one backup must exist after rotation");
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Test 5: OpenTelemetryHandler — full envelope (including groups) forwarded
// ---------------------------------------------------------------------------

test("OpenTelemetryHandler forwards full sealed envelope to OTel", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const rt = NodeRuntime.init(yamlPath);

    const received: Array<{ body: unknown; attributes: Record<string, unknown> }> = [];
    const fakeLogger = {
      emit(record: { body: unknown; attributes?: Record<string, unknown> }) {
        received.push({ body: record.body, attributes: record.attributes ?? {} });
      },
    };

    rt.addHandler(new OpenTelemetryHandler("otel", fakeLogger));

    rt.emit("info", "order.created", { amount: 42, currency: "EUR" });
    rt.emit("error", "payment.failed", { code: "402", retryable: false });
    rt.close();

    assert.equal(received.length, 2);

    // Body = full sealed envelope object — ciphertext group should be present.
    const body0 = received[0]!.body as Record<string, unknown>;
    assert.equal(body0["event_type"], "order.created");
    assert.ok("default" in body0, "ciphertext group 'default' must be in body");
    const group = body0["default"] as Record<string, unknown>;
    assert.ok(typeof group["ciphertext"] === "string", "ciphertext must be a string");

    // Attributes = flat queryable fields prefixed tn.*
    const attrs0 = received[0]!.attributes;
    assert.equal(attrs0["tn.event_type"], "order.created");
    assert.equal(attrs0["tn.level"], "info");
    assert.equal(attrs0["tn.sequence"], 1);

    // Second event
    const body1 = received[1]!.body as Record<string, unknown>;
    assert.equal(body1["event_type"], "payment.failed");
    assert.equal(body1["level"], "error");
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Test 6: OpenTelemetryHandler null logger is a no-op
// ---------------------------------------------------------------------------

test("OpenTelemetryHandler with null logger does not throw", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const rt = NodeRuntime.init(yamlPath);
    rt.addHandler(new OpenTelemetryHandler("otel-noop", null));
    rt.emit("info", "noop.test", { x: 1 });
    rt.close();
    // no assertion needed — must not throw
  } finally {
    cleanup();
  }
});
