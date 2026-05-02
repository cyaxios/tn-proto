// Tests for the reserved `tn.agents` group: namespace check, auto-inject,
// markdown policy loader + emit-side splice.

import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { loadConfig } from "../src/index.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { Tn } from "../src/tn.js";
import { parsePolicyText } from "../src/agents_policy.js";

async function ephemeralClient(): Promise<{ client: Tn; close: () => Promise<void> }> {
  const client = await Tn.ephemeral();
  return { client, close: () => client.close() };
}

/** Make a fresh ceremony in a tempdir we own (so it survives close+reinit). */
async function makeOwnedCeremony(): Promise<{ yamlPath: string; cleanup: () => void }> {
  const td = mkdtempSync(join(tmpdir(), "tn-owned-"));
  const yamlPath = join(td, "tn.yaml");
  // Use Tn.init to seed the ceremony, then close immediately so
  // we own the lifecycle. The init creates the keystore + yaml + log dir.
  const c = await Tn.init(yamlPath);
  await c.close();
  return {
    yamlPath,
    cleanup: () => {
      try {
        rmSync(td, { recursive: true, force: true });
      } catch {
        /* tempdir cleanup races with file handles on Windows */
      }
    },
  };
}

test("loadConfig rejects user-declared `tn.X` group names (reserved namespace)", async () => {
  // Reach into the inner ephemeral yaml + tweak it. Easier: write a yaml from
  // scratch into a tempdir and try to load it.
  const td = await Tn.ephemeral();
  try {
    const cfg = td.config() as CeremonyConfig;
    const yamlPath = cfg.yamlPath;
    // Replace the yaml with one that declares a forbidden tn.* group.
    const bad = `ceremony:
  id: bad_test
  mode: local
  cipher: btn
logs:
  path: ./.tn/logs/tn.ndjson
keystore:
  path: ./.tn/keys
me:
  did: ${cfg.me.did}
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - did: ${cfg.me.did}
  tn.bogus:
    policy: private
    cipher: btn
    recipients:
    - did: ${cfg.me.did}
fields: {}
`;
    writeFileSync(yamlPath, bad, "utf8");
    assert.throws(
      () => loadConfig(yamlPath),
      /reserved group name: tn\.bogus/,
      "loadConfig must reject tn.* groups other than tn.agents",
    );
  } finally {
    await td.close();
  }
});

test("a fresh ceremony auto-injects the tn.agents group", async () => {
  const { client, close } = await ephemeralClient();
  try {
    const cfg = client.config() as CeremonyConfig;
    assert.ok(
      cfg.groups.has("tn.agents"),
      "tn.agents must be auto-injected at fresh-create",
    );
    const g = cfg.groups.get("tn.agents")!;
    assert.equal(g.cipher, "btn");
  } finally {
    await close();
  }
});

test("the six tn.agents fields route exclusively to the tn.agents group", async () => {
  const { client, close } = await ephemeralClient();
  try {
    const cfg = client.config() as CeremonyConfig;
    const map = cfg.fieldToGroups;
    for (const f of [
      "instruction",
      "use_for",
      "do_not_use_for",
      "consequences",
      "on_violation_or_error",
      "policy",
    ]) {
      const groups = map.get(f);
      assert.ok(groups, `field ${f} must route somewhere`);
      assert.deepEqual(groups, ["tn.agents"], `field ${f} must route only to tn.agents`);
    }
  } finally {
    await close();
  }
});

test("parsePolicyText: extracts five subsections per event_type and computes content_hash", () => {
  const md = `# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## payment.completed

### instruction
This row records a completed payment.

### use_for
Aggregate reporting on amount and currency.

### do_not_use_for
Credit decisions, loan underwriting.

### consequences
customer_id is PII.

### on_violation_or_error
POST https://example.com/escalate.
`;
  const doc = parsePolicyText(md, ".tn/config/agents.md");
  const t = doc.templates.get("payment.completed");
  assert.ok(t, "must extract payment.completed template");
  assert.match(t!.instruction, /completed payment/);
  assert.match(t!.use_for, /Aggregate/);
  assert.match(t!.contentHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(t!.version, "1");
});

test("parsePolicyText raises when a section is missing required subsections", () => {
  const md = `## evt.bad

### instruction
text

### use_for
text
`;
  assert.throws(
    () => parsePolicyText(md, "x.md"),
    /missing required subsection/,
  );
});

test("emit-side splice: writer with .tn/config/agents.md fills tn.agents fields", async () => {
  const { yamlPath, cleanup } = await makeOwnedCeremony();
  try {
    const yamlDir = dirname(yamlPath);
    const policyDir = `${yamlDir}/.tn/config`;
    mkdirSync(policyDir, { recursive: true });
    writeFileSync(
      `${policyDir}/agents.md`,
      `## payment.completed

### instruction
This row records a completed payment.

### use_for
Aggregate reporting only.

### do_not_use_for
Credit decisions.

### consequences
PII exposure.

### on_violation_or_error
POST https://merchant.example.com/escalate.
`,
      "utf8",
    );

    const tn = await Tn.init(yamlPath);
    try {
      tn.info("payment.completed", { amount: 4999, currency: "USD" });
      const entries = [...tn.read({ raw: true })];
      const pay = entries.find((e) => e.envelope["event_type"] === "payment.completed");
      assert.ok(pay, "must emit payment.completed");
      const agents = pay!.plaintext["tn.agents"];
      assert.ok(agents, "tn.agents group plaintext must be present (writer holds the kit)");
      const a = agents as Record<string, unknown>;
      assert.match(String(a["instruction"]), /completed payment/);
      assert.match(String(a["use_for"]), /Aggregate/);
      assert.match(String(a["do_not_use_for"]), /Credit decisions/);
      assert.match(String(a["policy"]), /payment\.completed@/);
    } finally {
      await tn.close();
    }
  } finally {
    cleanup();
  }
});

test("emit-side splice: per-emit override wins over policy template", async () => {
  const { yamlPath, cleanup } = await makeOwnedCeremony();
  try {
    const yamlDir = dirname(yamlPath);
    mkdirSync(`${yamlDir}/.tn/config`, { recursive: true });
    writeFileSync(
      `${yamlDir}/.tn/config/agents.md`,
      `## evt.x
### instruction
default text
### use_for
default
### do_not_use_for
default
### consequences
default
### on_violation_or_error
default
`,
      "utf8",
    );
    const tn = await Tn.init(yamlPath);
    try {
      tn.info("evt.x", { instruction: "OVERRIDDEN" });
      const entries = [...tn.read({ raw: true })];
      const evt = entries.find((e) => e.envelope["event_type"] === "evt.x");
      const a = evt!.plaintext["tn.agents"] as Record<string, unknown>;
      assert.equal(a["instruction"], "OVERRIDDEN", "per-emit override wins");
    } finally {
      await tn.close();
    }
  } finally {
    cleanup();
  }
});
