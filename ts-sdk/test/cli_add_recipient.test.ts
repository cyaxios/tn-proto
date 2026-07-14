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
import { DeviceKey } from "../src/core/signing.js";
import { readTnpkg } from "../src/tnpkg_io.js";
import { addRecipientCmd } from "../src/cli/add_recipient.js";
import { absorbSealedKitBundle } from "../src/seal_bundle_producer.js";
import { readAsRecipient } from "../src/read_as_recipient.js";

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
    assert.match(stdout.text, /group: {5}default/);
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

test("add_recipient --seal-for-recipient with an UNRESOLVABLE did:key is rejected (exit 2, nothing written)", async () => {
  // `did:key:z6MkRealReaderForSeal` is shaped like a key-DID but its base58
  // body does not decode to a valid Ed25519 public key, so there is nothing
  // to wrap the BEK under. The verb refuses (exit 2) and writes nothing —
  // it never ships an unsealed bundle when sealing was asked for. (A genuine
  // key-DID seals for real; see the binding test in cli_add_recipient_seal.)
  const { dir, yamlPath } = await freshCeremony();
  const stdout = makeSink();
  const stderr = makeSink();
  const did = "did:key:z6MkRealReaderForSeal";
  const outPath = join(dir, "sealed-real.tnpkg");
  try {
    const code = await addRecipientCmd({
      group: "default",
      recipient: did,
      out: outPath,
      yaml: yamlPath,
      sealForRecipient: true,
      stdout,
      stderr,
    });
    assert.equal(code, 2, `expected exit 2; stderr=${stderr.text}`);
    assert.match(stderr.text, /--seal-for-recipient requires a real/);
    assert.equal(stdout.text, "", "no kit should be written on rejection");
    assert.ok(!existsSync(outPath), "no .tnpkg should be written on rejection");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("add_recipient --seal-for-recipient (REAL did:key) seals; named recipient decrypts, different recipient cannot", async () => {
  // The load-bearing proof: a genuine key-DID now SEALS for real. The named
  // recipient R recovers the BEK, installs the kit, and decrypts P's entry;
  // a different recipient X cannot unwrap and installs nothing.
  const { dir, yamlPath } = await freshCeremony();
  const stdout = makeSink();
  const stderr = makeSink();

  const rSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) rSeed[i] = (i * 17 + 9) & 0xff;
  const R = DeviceKey.fromSeed(rSeed);
  const xSeed = new Uint8Array(32).fill(123);
  const X = DeviceKey.fromSeed(xSeed);
  assert.notEqual(R.did, X.did);

  const outPath = join(dir, "sealed-addrec.tnpkg");
  // Seal FIRST (recipient-event mint can rotate the log), then P writes.
  const code = await addRecipientCmd({
    group: "default",
    recipient: R.did,
    out: outPath,
    yaml: yamlPath,
    sealForRecipient: true,
    stdout,
    stderr,
  });
  assert.equal(code, 0, `expected exit 0; stderr=${stderr.text}`);
  assert.equal(stderr.text, "");
  assert.match(stdout.text, /sealed for recipient/);

  // The bundle is sealed: encrypted body + recipient_wraps, no plaintext kit.
  const { manifest, body } = readTnpkg(outPath);
  assert.equal(manifest.kind, "kit_bundle");
  assert.equal(manifest.toDid, R.did);
  assert.ok(body.has("body/encrypted.bin"), "sealed body should be encrypted.bin");
  assert.ok(
    ![...body.keys()].some((k) => k.endsWith(".btn.mykit")),
    "sealed bundle must not carry a plaintext .btn.mykit",
  );

  // P writes an entry to decrypt.
  const tn = await Tn.init(yamlPath);
  let pLogPath: string;
  try {
    pLogPath = tn.logPath;
    tn.info("user.action", { shared_field: "addrec-sealed" });
  } finally {
    await tn.close();
  }

  // R absorbs into its own keystore and decrypts P's entry.
  const rKeystore = mkdtempSync(join(tmpdir(), "tn-addrec-R-"));
  try {
    const rReceipt = await absorbSealedKitBundle(outPath, { seed: rSeed, keystoreDir: rKeystore });
    assert.equal(rReceipt.rejectedReason, undefined, `R rejected: ${rReceipt.rejectedReason}`);
    assert.ok(rReceipt.acceptedCount >= 1, "R should install at least one kit");
    assert.ok(existsSync(join(rKeystore, "default.btn.mykit")), "R gets default.btn.mykit");

    const entries = Array.from(
      readAsRecipient(pLogPath, rKeystore, {
        group: "default",
        verifySignatures: true,
        trustedPublisherDids: [manifest.fromDid],
      }),
    ).filter((e) => e.envelope["event_type"] === "user.action");
    assert.ok(entries.length >= 1, `R should see P's info entry; got ${entries.length}`);
    const pt = entries[0]!.plaintext["default"] as Record<string, unknown> | undefined;
    assert.ok(pt !== undefined, "R should decrypt the default group");
    assert.ok(!("$no_read_key" in (pt ?? {})), "R must not get $no_read_key");
    assert.equal(pt?.["shared_field"], "addrec-sealed");

    // Different recipient X cannot unwrap: rejected, nothing installed.
    const xKeystore = mkdtempSync(join(tmpdir(), "tn-addrec-X-"));
    try {
      const xReceipt = await absorbSealedKitBundle(outPath, { seed: xSeed, keystoreDir: xKeystore });
      assert.ok(xReceipt.rejectedReason, "X MUST be rejected (wrap addressed to R)");
      assert.equal(xReceipt.acceptedCount, 0, "X installs nothing");
      assert.ok(!existsSync(join(xKeystore, "default.btn.mykit")), "X gets no usable kit");
    } finally {
      rmSync(xKeystore, { recursive: true, force: true });
    }
  } finally {
    rmSync(rKeystore, { recursive: true, force: true });
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
