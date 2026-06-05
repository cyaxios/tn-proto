// Coverage for the top-level `tn add_recipient` CLI verb
// (src/cli/add_recipient.ts) — TS parity port of Python's cmd_add_recipient.
//
// We drive the exported `addRecipientCmd` directly (library-style) with
// captured stdout/stderr sinks, then verify the minted `.tnpkg` matches the
// Python add_recipient output shape: a signed manifest with kind=kit_bundle,
// recipient_identity=<did>, and a body kit named `<group>.btn.mykit`.
//
// Run:
//   cd ts-sdk && npx c8 --include='src/cli/add_recipient.ts' --reporter=text \
//     node --import tsx --import ./test/_setup_wasm.mjs \
//     --test test/cli_add_recipient.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve } from "node:path";
import { Tn } from "../src/tn.js";
import { readTnpkg } from "../src/tnpkg_io.js";
import { addRecipientCmd } from "../src/cli/add_recipient.js";

interface Sink {
  text: string;
  write(s: string): void;
}
function makeSink(): Sink {
  return {
    text: "",
    write(s: string) {
      this.text += s;
    },
  };
}

/** Mint a fresh ceremony yaml in a temp dir and return its path + dir. */
async function freshCeremony(): Promise<{ dir: string; yamlPath: string }> {
  const dir = mkdtempSync(join(tmpdir(), "ts-cli-addrec-"));
  const yamlPath = join(dir, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  await tn.close();
  return { dir, yamlPath };
}

test("add_recipient with explicit DID writes a kit_bundle .tnpkg", async () => {
  const { dir, yamlPath } = await freshCeremony();
  const stdout = makeSink();
  const stderr = makeSink();
  const did = "did:key:z6MkExplicitReader";
  const outPath = join(dir, "reader.tnpkg");
  try {
    const code = await addRecipientCmd({
      group: "default",
      recipient: did,
      out: outPath,
      yaml: yamlPath,
      stdout,
      stderr,
    });
    assert.equal(code, 0, `stderr=${stderr.text}`);
    assert.equal(stderr.text, "");

    // stdout mirrors Python's three lines.
    assert.match(stdout.text, /\[tn add_recipient\] wrote /);
    assert.match(stdout.text, /group:     default/);
    assert.match(stdout.text, new RegExp(`recipient: ${did}`));

    // Behaviour assertion: the .tnpkg matches Python add_recipient output —
    // kind=kit_bundle, recipient_identity=<did>, body has <group>.btn.mykit.
    assert.ok(existsSync(outPath), "tnpkg should exist");
    const { manifest, body } = readTnpkg(outPath);
    assert.equal(manifest.kind, "kit_bundle");
    assert.equal(manifest.toDid, did);
    assert.ok(body.has("body/default.btn.mykit"), `body keys: ${[...body.keys()].join(",")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("add_recipient with a friendly label synthesizes did:key:zLabel- and default out path", async () => {
  const { dir, yamlPath } = await freshCeremony();
  const stdout = makeSink();
  const prevCwd = process.cwd();
  process.chdir(dir); // default out path is ./<stem>.tnpkg in cwd
  try {
    const code = await addRecipientCmd({
      group: "default",
      recipient: "professor",
      yaml: yamlPath,
      stdout,
    });
    assert.equal(code, 0);
    assert.match(stdout.text, /recipient: did:key:zLabel-professor/);

    // Default filename is ./professor.tnpkg in the cwd.
    const expected = pathResolve(dir, "professor.tnpkg");
    assert.match(stdout.text, new RegExp(`wrote ${expected.replace(/\\/g, "\\\\")}`));
    assert.ok(existsSync(expected), "default ./professor.tnpkg should exist");

    const { manifest } = readTnpkg(expected);
    assert.equal(manifest.kind, "kit_bundle");
    assert.equal(manifest.toDid, "did:key:zLabel-professor");
  } finally {
    process.chdir(prevCwd);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("add_recipient sanitizes unsafe label chars into the default stem", async () => {
  const { dir, yamlPath } = await freshCeremony();
  const stdout = makeSink();
  const prevCwd = process.cwd();
  process.chdir(dir);
  try {
    // "a/b c" -> "a_b_c.tnpkg"
    const code = await addRecipientCmd({
      group: "default",
      recipient: "a/b c",
      yaml: yamlPath,
      stdout,
    });
    assert.equal(code, 0);
    const expected = pathResolve(dir, "a_b_c.tnpkg");
    assert.ok(existsSync(expected), `expected ${expected}; stdout=${stdout.text}`);
  } finally {
    process.chdir(prevCwd);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("add_recipient falls back to 'recipient' stem when label sanitizes to empty", async () => {
  const { dir, yamlPath } = await freshCeremony();
  const stdout = makeSink();
  const prevCwd = process.cwd();
  process.chdir(dir);
  try {
    // An empty label sanitizes to "" -> stem falls back to "recipient".
    const code = await addRecipientCmd({
      group: "default",
      recipient: "",
      yaml: yamlPath,
      stdout,
    });
    assert.equal(code, 0);
    assert.ok(existsSync(pathResolve(dir, "recipient.tnpkg")), `stdout=${stdout.text}`);
    // The synthetic DID still carries the (empty) raw label.
    assert.match(stdout.text, /recipient: did:key:zLabel-\n/);
  } finally {
    process.chdir(prevCwd);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("add_recipient --seal-for-recipient with a friendly label is rejected (exit 2)", async () => {
  const { dir, yamlPath } = await freshCeremony();
  const stdout = makeSink();
  const stderr = makeSink();
  try {
    const code = await addRecipientCmd({
      group: "default",
      recipient: "professor",
      yaml: yamlPath,
      sealForRecipient: true,
      stdout,
      stderr,
    });
    assert.equal(code, 2);
    assert.match(stderr.text, /--seal-for-recipient requires a real/);
    assert.equal(stdout.text, "", "no kit should be written on rejection");
    // Nothing written to disk.
    assert.ok(!existsSync(join(dir, "professor.tnpkg")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("add_recipient --seal-for-recipient with a did:key:zLabel- placeholder is rejected (exit 2)", async () => {
  const { dir, yamlPath } = await freshCeremony();
  const stderr = makeSink();
  try {
    // Passing the synthetic placeholder DID explicitly still hits the
    // recipientDid.startsWith("did:key:zLabel-") guard.
    const code = await addRecipientCmd({
      group: "default",
      recipient: "did:key:zLabel-ghost",
      yaml: yamlPath,
      sealForRecipient: true,
      stderr,
    });
    assert.equal(code, 2);
    assert.match(stderr.text, /seal step has nothing to wrap under/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("add_recipient default stderr/stdout sinks are used when not supplied", async () => {
  // Exercises the `?? process.stdout` / `?? process.stderr` defaults by
  // omitting the sinks entirely. We just assert it succeeds and writes.
  const { dir, yamlPath } = await freshCeremony();
  const outPath = join(dir, "nosink.tnpkg");
  try {
    const code = await addRecipientCmd({
      group: "default",
      recipient: "did:key:z6MkNoSink",
      out: outPath,
      yaml: yamlPath,
    });
    assert.equal(code, 0);
    assert.ok(existsSync(outPath));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
