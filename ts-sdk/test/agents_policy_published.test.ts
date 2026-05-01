// Tests for `tn.agents.policy_published` admin event behavior at init time.

import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { TNClient } from "../src/index.js";

const POLICY_MD = `## evt.published
### instruction
text-1
### use_for
text-2
### do_not_use_for
text-3
### consequences
text-4
### on_violation_or_error
text-5
`;

/** Make a fresh ceremony in a tempdir we own (so it survives close+reinit).
 *
 * The policy-published tests legitimately need cross-session continuation
 * (close, modify policy file, reinit, expect to see BOTH the prior and
 * new policy_published events in one log read). Session-start rotation
 * (the new default) would roll the prior session's events to `<log>.1`
 * and break the assertion. Pin `rotate_on_init: false` on the file
 * handler so the legacy "append everything" behavior applies for these
 * tests. */
function makeOwnedCeremony(): { yamlPath: string; cleanup: () => void } {
  const td = mkdtempSync(join(tmpdir(), "tn-policy-pub-"));
  const yamlPath = join(td, "tn.yaml");
  const c = TNClient.init(yamlPath);
  c.close();
  // Edit the just-created yaml to disable session rotation. The
  // generated file has `handlers: [{kind: file.rotating, ..., rotate_on_init: true}, {kind: stdout}]`;
  // rewrite the rotate_on_init line to false. Simple textual replace
  // — yaml structure is stable per `createFreshCeremony`.
  const original = readFileSync(yamlPath, "utf8");
  const tweaked = original.replace(/rotate_on_init: true/, "rotate_on_init: false");
  writeFileSync(yamlPath, tweaked, "utf8");
  return {
    yamlPath,
    cleanup: () => {
      try {
        rmSync(td, { recursive: true, force: true });
      } catch {
        /* tempdir cleanup races on Windows */
      }
    },
  };
}

test("init emits tn.agents.policy_published when a policy file is present", () => {
  const { yamlPath, cleanup } = makeOwnedCeremony();
  try {
    const yamlDir = dirname(yamlPath);
    mkdirSync(`${yamlDir}/.tn/config`, { recursive: true });
    writeFileSync(`${yamlDir}/.tn/config/agents.md`, POLICY_MD, "utf8");

    const client = TNClient.init(yamlPath);
    try {
      const entries = [...client.read({ raw: true })];
      const pub = entries.filter(
        (e) => e.envelope["event_type"] === "tn.agents.policy_published",
      );
      assert.equal(pub.length, 1, "exactly one policy_published event after first init");
      assert.equal(pub[0]!.envelope["policy_uri"], ".tn/config/agents.md");
      assert.match(String(pub[0]!.envelope["content_hash"]), /^sha256:/);
    } finally {
      client.close();
    }
  } finally {
    cleanup();
  }
});

test("idempotent: re-init on unchanged policy file does NOT re-emit", () => {
  const { yamlPath, cleanup } = makeOwnedCeremony();
  try {
    const yamlDir = dirname(yamlPath);
    mkdirSync(`${yamlDir}/.tn/config`, { recursive: true });
    writeFileSync(`${yamlDir}/.tn/config/agents.md`, POLICY_MD, "utf8");

    const c1 = TNClient.init(yamlPath);
    c1.close();

    const c2 = TNClient.init(yamlPath);
    try {
      // FINDINGS #4 parity: read({raw:true}) defaults to strict run_id
      // matching, so events emitted by c1 are filtered out from c2's
      // perspective. Use allRuns:true to see prior runs (matches the
      // Python `tn.read(all_runs=True)` shape).
      const entries = [...c2.read({ raw: true, allRuns: true })];
      const pub = entries.filter(
        (e) => e.envelope["event_type"] === "tn.agents.policy_published",
      );
      assert.equal(pub.length, 1, "second init must not re-emit on unchanged content_hash");
    } finally {
      c2.close();
    }
  } finally {
    cleanup();
  }
});

test("re-emits on policy content change", () => {
  const { yamlPath, cleanup } = makeOwnedCeremony();
  try {
    const yamlDir = dirname(yamlPath);
    mkdirSync(`${yamlDir}/.tn/config`, { recursive: true });
    writeFileSync(`${yamlDir}/.tn/config/agents.md`, POLICY_MD, "utf8");

    TNClient.init(yamlPath).close();

    const NEW_POLICY = POLICY_MD.replace("text-1", "text-1-MODIFIED");
    writeFileSync(`${yamlDir}/.tn/config/agents.md`, NEW_POLICY, "utf8");

    const c2 = TNClient.init(yamlPath);
    try {
      // FINDINGS #4 parity — see sibling test for explanation.
      const entries = [...c2.read({ raw: true, allRuns: true })];
      const pub = entries.filter(
        (e) => e.envelope["event_type"] === "tn.agents.policy_published",
      );
      assert.equal(pub.length, 2, "policy change must trigger a fresh policy_published");
    } finally {
      c2.close();
    }
  } finally {
    cleanup();
  }
});

test("no policy file present: no policy_published event ever", () => {
  const client = TNClient.ephemeral();
  try {
    const entries = [...client.read({ raw: true })];
    const pub = entries.filter(
      (e) => e.envelope["event_type"] === "tn.agents.policy_published",
    );
    assert.equal(pub.length, 0, "absent policy file → never emitted");
  } finally {
    client.close();
  }
});
