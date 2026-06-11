// Tests for `Tn.read({verify})` — fail-closed verification, three modes.
//
// Migrated from the legacy `Tn.secureRead()` suite as part of the
// 0.4.0a1 read-side refactor. The forensic-mode test is dropped (no
// equivalent in the new surface — verify maps to false / true / "skip"
// only). The instructions-block test is dropped (instructions surfacing
// belongs to a separate concern that no longer ships through read).

import { strict as assert } from "node:assert";
import { readFileSync, writeFileSync } from "node:fs";
import { test } from "node:test";

import { VerifyError } from "../src/Entry.js";
import { Tn } from "../src/tn.js";

async function ephemeralClient(): Promise<{ client: Tn; close: () => Promise<void> }> {
  const client = await Tn.ephemeral();
  return { client, close: () => client.close() };
}

test("read({verify: 'skip'}) skips tampered rows + emits tn.read.tampered_row_skipped", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("evt.good", { x: 1 });
    const path = client.logPath;
    const text = readFileSync(path, "utf8");
    const lines = text.trim().split("\n");
    // Tamper the last line by replacing row_hash with a clearly-wrong value.
    const last = JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
    last["row_hash"] = "sha256:" + "0".repeat(64);
    lines[lines.length - 1] = JSON.stringify(last);
    writeFileSync(path, lines.join("\n") + "\n", "utf8");

    const out = [...client.read({ verify: "skip", allRuns: true })];
    // The tampered row is dropped.
    const tampered = out.find((e) => {
      if ("event_type" in e) return e.event_type === "evt.good";
      const r = e as Record<string, unknown>;
      return r["event_type"] === "evt.good";
    });
    assert.equal(tampered, undefined, "tampered row must be skipped");
  } finally {
    await close();
  }
});

test("read({verify: 'raise'}) throws VerifyError on tampered ciphertext", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("evt.good", { x: 1 });
    const path = client.logPath;
    const text = readFileSync(path, "utf8");
    const lines = text.trim().split("\n");
    const last = JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
    last["row_hash"] = "sha256:" + "0".repeat(64);
    lines[lines.length - 1] = JSON.stringify(last);
    writeFileSync(path, lines.join("\n") + "\n", "utf8");

    assert.throws(
      () => [...client.read({ verify: "raise", allRuns: true })],
      (e: unknown) => e instanceof VerifyError,
    );
  } finally {
    await close();
  }
});

test("read({verify: true}) is equivalent to verify: 'raise'", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("evt.good", { x: 1 });
    const path = client.logPath;
    const text = readFileSync(path, "utf8");
    const lines = text.trim().split("\n");
    const last = JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
    last["row_hash"] = "sha256:" + "0".repeat(64);
    lines[lines.length - 1] = JSON.stringify(last);
    writeFileSync(path, lines.join("\n") + "\n", "utf8");

    assert.throws(
      () => [...client.read({ verify: true, allRuns: true })],
      (e: unknown) => e instanceof VerifyError,
    );
  } finally {
    await close();
  }
});

test("read() throws on an invalid-JSON line, naming path:lineno", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("evt.good", { x: 1 });
    const path = client.logPath;
    const text = readFileSync(path, "utf8");
    // Append a structurally-broken ndjson line.
    writeFileSync(path, text + "{ this is not valid json\n", "utf8");
    assert.throws(
      () => [...client.read({ allRuns: true })],
      (e: unknown) => e instanceof Error && /invalid JSON/.test((e as Error).message),
    );
  } finally {
    await close();
  }
});

test("read with no verify option does not check integrity (default false)", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("evt.good", { x: 1 });
    const path = client.logPath;
    const text = readFileSync(path, "utf8");
    const lines = text.trim().split("\n");
    const last = JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
    last["row_hash"] = "sha256:" + "0".repeat(64);
    lines[lines.length - 1] = JSON.stringify(last);
    writeFileSync(path, lines.join("\n") + "\n", "utf8");

    // No throw, no skip. The entry comes through.
    const out = [...client.read({ allRuns: true })];
    const evt = out.find((e) => {
      if ("event_type" in e) return e.event_type === "evt.good";
      const r = e as Record<string, unknown>;
      return r["event_type"] === "evt.good";
    });
    assert.ok(evt, "verify=false (default) must not drop tampered rows");
  } finally {
    await close();
  }
});
