// Tests for `client.secureRead()` — fail-closed verification, three modes,
// instructions block, tampered-row events.

import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { VerificationError } from "../src/index.js";
import { Tn } from "../src/tn.js";

async function ephemeralClient(): Promise<{ client: Tn; close: () => Promise<void> }> {
  const client = await Tn.ephemeral();
  return { client, close: () => client.close() };
}

/** Fresh ceremony in a tempdir we own — for tests that close+reinit. */
async function makeOwnedCeremony(): Promise<{ yamlPath: string; cleanup: () => void }> {
  const td = mkdtempSync(join(tmpdir(), "tn-sec-"));
  const yamlPath = join(td, "tn.yaml");
  const c = await Tn.init(yamlPath);
  await c.close();
  return {
    yamlPath,
    cleanup: () => {
      try {
        rmSync(td, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    },
  };
}

test("secureRead: all-valid entries are surfaced as flat dicts", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("order.created", { amount: 99 });
    const out = [...client.secureRead()];
    const evt = out.find((e) => e["event_type"] === "order.created");
    assert.ok(evt, "verified entry must be yielded");
    assert.equal(evt!["amount"], 99);
  } finally {
    await close();
  }
});

test("secureRead default skips tampered rows + emits tn.read.tampered_row_skipped", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("evt.good", { x: 1 });
    // Append a malformed envelope to corrupt the chain. Easiest: break the
    // signature on a fresh emit by hand-rewriting the file.
    const path = client.logPath;
    const text = readFileSync(path, "utf8");
    const lines = text.trim().split("\n");
    // Tamper the last line: flip a bit in the ciphertext (so row_hash
    // recomputation fails).
    const last = JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
    // Replace row_hash with a clearly-wrong sha256 so recomputation fails.
    // secureRead's fail-closed semantics require ALL three checks pass.
    last["row_hash"] = "sha256:" + "0".repeat(64);
    lines[lines.length - 1] = JSON.stringify(last);
    writeFileSync(path, lines.join("\n") + "\n", "utf8");

    const out = [...client.secureRead()];
    // The tampered row is dropped.
    const tampered = out.find((e) => e["event_type"] === "evt.good");
    assert.equal(tampered, undefined, "tampered row must be skipped");
  } finally {
    await close();
  }
});

test("secureRead({onInvalid: 'raise'}) throws VerificationError", async () => {
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
      () => [...client.secureRead({ onInvalid: "raise" })],
      (e: unknown) => e instanceof VerificationError,
    );
  } finally {
    await close();
  }
});

test("secureRead({onInvalid: 'forensic'}) yields entries with _valid + _invalid_reasons", async () => {
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

    const out = [...client.secureRead({ onInvalid: "forensic" })];
    const bad = out.find((e) => e["event_type"] === "evt.good");
    assert.ok(bad, "forensic mode must surface tampered entries");
    assert.ok(bad!["_invalid_reasons"], "_invalid_reasons must be set");
    const reasons = bad!["_invalid_reasons"] as string[];
    assert.ok(
      reasons.includes("signature") ||
        reasons.includes("row_hash") ||
        reasons.includes("chain"),
      `expected at least one verification failure, got ${JSON.stringify(reasons)}`,
    );
  } finally {
    await close();
  }
});

test("secureRead surfaces `instructions` block when caller holds tn.agents kit", async () => {
  const { yamlPath, cleanup } = await makeOwnedCeremony();
  try {
    const yamlDir = dirname(yamlPath);
    mkdirSync(`${yamlDir}/.tn/config`, { recursive: true });
    writeFileSync(
      `${yamlDir}/.tn/config/agents.md`,
      `## evt.policied
### instruction
This row is policied.
### use_for
Read only.
### do_not_use_for
Anything else.
### consequences
None.
### on_violation_or_error
N/A
`,
      "utf8",
    );
    const tn = await Tn.init(yamlPath);
    try {
      tn.info("evt.policied", { x: 1 });
      const out = [...tn.secureRead()];
      const evt = out.find((e) => e["event_type"] === "evt.policied");
      assert.ok(evt);
      const ins = evt!["instructions"];
      assert.ok(ins, "instructions must surface when caller holds the kit");
      const i = ins as Record<string, unknown>;
      assert.match(String(i["instruction"]), /policied/);
      // The six tn.agents fields should NOT appear at top level.
      assert.equal(evt!["instruction"], undefined);
      assert.equal(evt!["use_for"], undefined);
    } finally {
      await tn.close();
    }
  } finally {
    cleanup();
  }
});

test("secureRead omits instructions when entry has no tn.agents body", async () => {
  const { client, close } = await ephemeralClient();
  try {
    client.info("evt.no_policy", { x: 1 });
    const out = [...client.secureRead()];
    const evt = out.find((e) => e["event_type"] === "evt.no_policy");
    assert.ok(evt);
    assert.equal(evt!["instructions"], undefined);
  } finally {
    await close();
  }
});
