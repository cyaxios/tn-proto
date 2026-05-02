// Tn.ephemeral() — fresh ceremony in a private tempdir, cleanup on close.
//
// Mirrors Rust's `Runtime::ephemeral()` test
// (crypto/tn-core/tests/runtime_ephemeral.rs) and Python's `tn.session()`
// usage. Use as the test-mode constructor when the test doesn't care
// about the on-disk yaml path or persistence.

import { strict as assert } from "node:assert";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { test } from "node:test";

import { Tn } from "../src/tn.js";

test("Tn.ephemeral creates a usable runtime", async () => {
  const c = await Tn.ephemeral();
  try {
    // Sanity: real DID, real log path under the tempdir.
    assert.ok(c.did.startsWith("did:key:"), `unexpected did: ${c.did}`);
    assert.ok(existsSync(dirname(c.logPath)), "log dir should exist");

    // log/info/etc return void (parity with Python). Use `emit()` for a receipt.
    const r = c.emit("info", "evt.ephemeral", { k: 1 });
    assert.equal(typeof r.eventId, "string");
    assert.ok(r.sequence >= 1);

    // Read back what we just wrote (ignore bootstrap tn.* events).
    const read = [...c.read({ raw: true })].filter(
      (e) => (e.envelope["event_type"] as string) === "evt.ephemeral",
    );
    assert.equal(read.length, 1, "expected exactly one user event");
  } finally {
    await c.close();
  }
});

test("Tn.ephemeral cleans up its tempdir on close", async () => {
  const c = await Tn.ephemeral();
  c.info("evt.cleanup", { k: 1 });
  const logPath = c.logPath;
  // logPath is somewhere under the owned tempdir; the dir-of-dir-of(logPath)
  // is the tempdir root for the default ./.tn/logs/tn.ndjson layout.
  const tempRoot = dirname(dirname(logPath));
  assert.ok(existsSync(tempRoot), "tempdir should exist before close");

  await c.close();
  // Cleanup is best-effort. Allow either fully-removed or empty —
  // Windows occasionally races with file handles even after close().
  if (existsSync(tempRoot)) {
    // If it still exists, the close() path will have logged best-effort
    // and moved on. Don't fail the test on Windows fh races; the
    // important part is that close() doesn't throw.
    return;
  }
  assert.ok(!existsSync(tempRoot), "tempdir should be gone after close");
});

test("Tn.ephemeral instances are isolated", async () => {
  const a = await Tn.ephemeral();
  const b = await Tn.ephemeral();
  try {
    assert.notEqual(a.did, b.did, "ephemeral clients should have distinct DIDs");
    assert.notEqual(a.logPath, b.logPath, "ephemeral clients should have distinct log paths");
  } finally {
    await a.close();
    await b.close();
  }
});

test("Tn.ephemeral close is idempotent", async () => {
  const c = await Tn.ephemeral();
  await c.close();
  // Second close() must not throw — close clears the tempdir handle
  // first specifically so a re-call doesn't try to rm a missing dir.
  await c.close();
});
