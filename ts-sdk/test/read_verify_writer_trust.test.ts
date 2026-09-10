// Enforcing local reads (`read({verify: true | "raise"})`) must apply the
// writer-trust allowlist, not only the signature/row_hash/chain checks the
// pure-TS reader already runs. The check lives in the wasm core's secureRead
// (the single source of truth for the allowlist); Tn.read routes enforcing
// reads through it as a fail-closed gate. These tests pin both directions:
// a clean self-authored log passes untouched, and a chain-valid row from an
// untrusted writer fails the whole read closed.

import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Entry, VerifyError } from "../src/Entry.js";
import { Tn } from "../src/tn.js";

test("read({verify:true}) returns every row of a clean self-authored log", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-verify-clean-"));
  try {
    const tn = await Tn.init(join(root, "a.yaml"));
    tn.info("evt.ok", { marker: "one" });
    tn.info("evt.ok", { marker: "two" });

    // Every row is self-authored, so the writer-trust gate accepts them all —
    // an enforcing read must never falsely reject its own log.
    const markers = [...tn.read({ verify: true })]
      .filter((e): e is Entry => e instanceof Entry && e.event_type === "evt.ok")
      .map((e) => e.fields["marker"]);
    assert.deepEqual(markers.sort(), ["one", "two"]);

    await tn.close();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("read({verify:true}) rejects a chain-valid row from an untrusted writer", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-verify-intruder-"));
  const aliceDir = join(root, "alice");
  const bobDir = join(root, "bob");
  mkdirSync(aliceDir, { recursive: true });
  mkdirSync(bobDir, { recursive: true });

  try {
    const alice = await Tn.init(join(aliceDir, "alice.yaml"));
    alice.info("evt.ok", { marker: "alpha" });
    const aliceLog = alice.logPath;

    // Bob is a separate publisher; his DID is not in Alice's writer allowlist.
    // His FIRST `evt.intruder` row is a genesis row for that event_type
    // (prev_hash = zero). Alice never emits `evt.intruder`, so once the row is
    // spliced into her log it passes the signature + row_hash + chain checks —
    // only the writer-trust allowlist can reject it. That isolates the gate:
    // the pre-existing pure-TS checks alone would let this row through.
    const bob = await Tn.init(join(bobDir, "bob.yaml"));
    bob.info("evt.intruder", { marker: "forged" });
    const bobLog = bob.logPath;
    await bob.close();

    const intruderLine = readFileSync(bobLog, "utf8")
      .split("\n")
      .find((l) => l.includes('"evt.intruder"'));
    assert.ok(intruderLine, "expected an evt.intruder row in Bob's log");
    appendFileSync(aliceLog, intruderLine + "\n");

    // Default (no-verify) read still surfaces the intruder row unchanged —
    // proving it is present and passes the signature/row_hash/chain checks.
    const surfaced = [...alice.read()].filter(
      (e): e is Entry => e instanceof Entry && e.event_type === "evt.intruder",
    );
    assert.equal(surfaced.length, 1, "no-verify read should surface the intruder row");

    // Enforcing read fails closed: the intruder's writer is untrusted.
    assert.throws(
      () => [...alice.read({ verify: true })],
      (err: unknown) => {
        assert.ok(err instanceof VerifyError, `expected VerifyError, got ${String(err)}`);
        assert.ok(
          err.failed_checks.includes("writer_untrusted"),
          `expected writer_untrusted, got ${JSON.stringify(err.failed_checks)}`,
        );
        return true;
      },
    );

    await alice.close();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('read({verify:"skip"}) drops an untrusted writer\'s rows, keeps own rows', async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-verify-skip-"));
  const aliceDir = join(root, "alice");
  const bobDir = join(root, "bob");
  mkdirSync(aliceDir, { recursive: true });
  mkdirSync(bobDir, { recursive: true });

  try {
    const alice = await Tn.init(join(aliceDir, "alice.yaml"));
    alice.info("evt.ok", { marker: "alpha" });
    alice.info("evt.ok", { marker: "beta" });
    const aliceLog = alice.logPath;

    // Same untrusted-writer splice as the raise test — a genesis evt.intruder
    // row that passes sig/row_hash/chain, so only the writer-trust allowlist
    // can catch it.
    const bob = await Tn.init(join(bobDir, "bob.yaml"));
    bob.info("evt.intruder", { marker: "forged" });
    const bobLog = bob.logPath;
    await bob.close();

    const intruderLine = readFileSync(bobLog, "utf8")
      .split("\n")
      .find((l) => l.includes('"evt.intruder"'));
    assert.ok(intruderLine, "expected an evt.intruder row in Bob's log");
    appendFileSync(aliceLog, intruderLine + "\n");

    // Skip drops the untrusted-writer row without throwing, and leaves Alice's
    // own rows untouched.
    const events = [...alice.read({ verify: "skip" })]
      .filter((e): e is Entry => e instanceof Entry)
      .map((e) => e.event_type);
    assert.ok(
      !events.includes("evt.intruder"),
      `skip should drop the intruder row, got ${JSON.stringify(events)}`,
    );
    assert.equal(
      events.filter((t) => t === "evt.ok").length,
      2,
      "Alice's own rows must survive skip",
    );

    await alice.close();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
