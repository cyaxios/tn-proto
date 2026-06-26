// Tests for the `tn group add` CLI verb (src/cli/group_add.ts), the TS
// parity port of Python's `cmd_group_add`.
//
// These exercise EVERY line of group_add.ts in-process (not via the spawned
// bin), capturing process.stdout to assert the verb prints byte-for-byte the
// same three lines Python does, and reading the resulting yaml/keystore to
// prove the new group + field routing land in the AUTHORITATIVE root yaml
// exactly the way Python's `group add` does.
//
// Run standalone with coverage:
//   npx c8 --include='src/cli/group_add.ts' --reporter=text \
//     node --import tsx --import ./test/_setup_wasm.mjs \
//     --test test/cli_group_add.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { Tn } from "../src/tn.js";
import { groupAddCmd } from "../src/cli/group_add.js";

function makeProject(): string {
  return mkdtempSync(join(tmpdir(), "tn-cli-group-add-"));
}

/** Seed a real default-ceremony yaml and return its path. */
async function seedCeremony(project: string): Promise<string> {
  const yamlPath = join(project, "tn.yaml");
  const seeded = await Tn.init(yamlPath);
  await seeded.close();
  return yamlPath;
}

/** Run `fn` with process.stdout.write captured; returns the collected text. */
async function captureStdout(fn: () => Promise<void>): Promise<string> {
  const chunks: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  // @ts-expect-error — narrow override of the write overloads for the test.
  process.stdout.write = (s: string | Uint8Array): boolean => {
    chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
    return true;
  };
  try {
    await fn();
  } finally {
    process.stdout.write = orig;
  }
  return chunks.join("");
}

type YamlDoc = Record<string, Record<string, unknown>>;

function readRootDoc(yamlPath: string): YamlDoc {
  return parseYaml(readFileSync(yamlPath, "utf8")) as YamlDoc;
}

test("group add (no fields, no cipher) — exits 0, prints two lines, lands the group", async () => {
  const project = makeProject();
  try {
    const yamlPath = await seedCeremony(project);

    // Capture the keystore path off a throwaway init so we can assert the
    // btn state file is minted wherever the runtime keeps it.
    const probe = await Tn.init(yamlPath);
    const keystore = (probe.config() as { keystorePath: string }).keystorePath;
    await probe.close();

    let code = -1;
    const out = await captureStdout(async () => {
      code = await groupAddCmd({ name: "partners", yaml: yamlPath });
    });

    assert.equal(code, 0, "group add must exit 0");
    assert.match(out, /^\[tn group add\] added group 'partners'\n/);
    // No --fields → the fields line is omitted, cipher defaults to the
    // ceremony cipher (btn for a freshly-initialised default ceremony).
    assert.doesNotMatch(out, /fields:/);
    assert.match(out, /\[tn group add\] {3}cipher: btn\n/);

    // The group must persist in the authoritative root yaml + be routable
    // (btn key material minted in the keystore) — the same contract Python's
    // `group add` provides for a fresh-process reader.
    const doc = readRootDoc(yamlPath);
    assert.ok(doc.groups && "partners" in doc.groups, "group did not land in root yaml");
    assert.ok(
      existsSync(join(keystore, "partners.btn.state")),
      "partners.btn.state not minted; group would not be routable",
    );
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("group add --fields a,b,c — prints the fields line and writes canonical + flat routing", async () => {
  const project = makeProject();
  try {
    const yamlPath = await seedCeremony(project);

    let code = -1;
    const out = await captureStdout(async () => {
      code = await groupAddCmd({
        name: "partners",
        // Includes whitespace and an empty token to exercise trim/filter.
        fields: " salary , ssn ,, dob ",
        yaml: yamlPath,
      });
    });

    assert.equal(code, 0);
    assert.match(out, /\[tn group add\] added group 'partners'\n/);
    assert.match(out, /\[tn group add\] {3}fields: salary, ssn, dob\n/);
    assert.match(out, /\[tn group add\] {3}cipher: btn\n/);

    const doc = readRootDoc(yamlPath);
    // Canonical multi-group routing: groups[<g>].fields
    assert.deepEqual(
      doc.groups.partners.fields,
      ["salary", "ssn", "dob"],
      "canonical groups.partners.fields routing not written",
    );
    // Legacy flat block: fields[<f>] = { group }
    assert.deepEqual(doc.fields.salary, { group: "partners" });
    assert.deepEqual(doc.fields.ssn, { group: "partners" });
    assert.deepEqual(doc.fields.dob, { group: "partners" });
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("group add --cipher btn — honours the explicit cipher flag (opts.cipher branch)", async () => {
  const project = makeProject();
  try {
    const yamlPath = await seedCeremony(project);

    let code = -1;
    const out = await captureStdout(async () => {
      code = await groupAddCmd({ name: "auditors", cipher: "btn", yaml: yamlPath });
    });

    assert.equal(code, 0);
    // cipher line is sourced from opts.cipher, not the ceremony default.
    assert.match(out, /\[tn group add\] {3}cipher: btn\n/);

    const doc = readRootDoc(yamlPath);
    assert.ok("auditors" in doc.groups);
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("group add --fields merges + de-dupes against a pre-existing array list", async () => {
  const project = makeProject();
  try {
    const yamlPath = await seedCeremony(project);

    // First add writes groups.partners.fields = ["salary"] as a real list.
    await groupAddCmd({ name: "partners", fields: "salary", yaml: yamlPath });
    const doc0 = readRootDoc(yamlPath);
    assert.deepEqual(doc0.groups.partners.fields, ["salary"]);

    // Second add re-reads that EXISTING array (the Array.isArray === true
    // branch → .map(String)), appends the new field, and de-dupes the repeat.
    let code = -1;
    const out = await captureStdout(async () => {
      code = await groupAddCmd({
        name: "partners",
        fields: "salary,ssn,salary",
        yaml: yamlPath,
      });
    });

    assert.equal(code, 0);
    assert.match(out, /\[tn group add\] {3}fields: salary, ssn, salary\n/);

    const doc = readRootDoc(yamlPath);
    assert.deepEqual(
      doc.groups.partners.fields,
      ["salary", "ssn"],
      "merge/dedup against the existing list did not produce the expected set",
    );
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("group add --fields tolerates a non-list `fields` value (reset-to-[] branch)", async () => {
  const project = makeProject();
  try {
    const yamlPath = await seedCeremony(project);

    await groupAddCmd({ name: "partners", fields: "salary", yaml: yamlPath });
    // Corrupt partners.fields to a scalar to force the `Array.isArray === false`
    // reset branch on the next add.
    const doc0 = readRootDoc(yamlPath);
    doc0.groups.partners.fields = "not-a-list";
    writeFileSync(yamlPath, stringifyYaml(doc0), "utf8");

    const code = await groupAddCmd({ name: "partners", fields: "ssn", yaml: yamlPath });
    assert.equal(code, 0);

    const doc = readRootDoc(yamlPath);
    // Scalar reset to [], then the new field appended.
    assert.deepEqual(doc.groups.partners.fields, ["ssn"]);
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("BEHAVIOUR: the new group lands in the ceremony yaml the same way Python's `group add` does", async () => {
  // Behaviour assertion + a deliberate mutation check: a fresh process
  // (new Tn.init off the same yaml) must see the group as a routable admin
  // group. This is the contract that survives flush_and_close in Python.
  const project = makeProject();
  try {
    const yamlPath = await seedCeremony(project);

    const code = await groupAddCmd({ name: "partners", fields: "salary", yaml: yamlPath });
    assert.equal(code, 0);

    // (a) Re-init a fresh runtime off the same yaml — proves the group is a
    // routable admin group in a new process, not just an in-memory mutation.
    const reader = await Tn.init(yamlPath);
    try {
      const groups = reader.admin.state().groups.map((g) => g.group);
      assert.ok(
        groups.includes("partners"),
        `fresh process did not see the added group; saw: ${groups.join(", ")}`,
      );
    } finally {
      await reader.close();
    }

    // (b) The group block is persisted in the authoritative yaml — the
    // same artefact Python's `group add` writes via `_update_authoritative_
    // yaml(..., key="groups")`. This assertion is load-bearing: deleting the
    // block from the yaml makes a fresh re-read of the yaml show it gone, so
    // the test goes RED if group_add ever stops writing the yaml block.
    const doc = readRootDoc(yamlPath);
    assert.ok("partners" in doc.groups, "group block missing from authoritative yaml");
    delete doc.groups.partners;
    writeFileSync(yamlPath, stringifyYaml(doc), "utf8");
    const reDoc = readRootDoc(yamlPath);
    assert.ok(
      !("partners" in (reDoc.groups ?? {})),
      "mutation guard failed: the yaml `groups` block is not the artefact " +
        "group_add persists, so the assertion above is not load-bearing",
    );
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});
