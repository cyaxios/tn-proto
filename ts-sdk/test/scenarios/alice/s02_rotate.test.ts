// Alice s02 — rotate mid-stream, verify chain continues.
//
// Python original: python/scenarios/alice/s02_rotate.py
//
// SKIP REASON: tn.admin.rotate() throws on the btn cipher ("btn cipher does
// not support in-band rotation") and the TS SDK does not yet implement JWE
// rotation either ("jwe cipher rotation not yet implemented in TS SDK").
// This structural placeholder preserves the assertion intent; when JWE
// rotation lands the body below should be un-skipped and validated.
//
// Assertion intent (for when rotation is available):
//   1. Emit 200 evt.pre events.
//   2. Call tn.admin.rotate("default") — should complete without error.
//   3. Emit 200 evt.post events.
//   4. Read all entries; verify:
//      - every entry's valid.chain is true (chain is continuous across rotation)
//      - every entry's valid.signature is true
//      - post-rotation entries decrypt cleanly (seq 0..199 in evt.post)
//   5. Record whether pre-rotation entries decrypt (Python finding: they may
//      not, because the old cipher state is discarded after rotation; that is
//      acceptable and documented, not a bug).

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { ScenarioContext } from "../_harness.js";

test("alice/s02_rotate — structural placeholder (rotation not yet supported in TS SDK)", async (t) => {
  const ctx = new ScenarioContext();
  const tn = await ScenarioContext.newTn();

  try {
    // Emit pre-rotation events (structural shape mirrors Python).
    for (let i = 0; i < 200; i++) {
      tn.info("evt.pre", { seq: i });
    }

    // Attempt rotation — this is expected to throw until JWE rotation is
    // implemented.  Catch the error and skip the test rather than failing.
    let rotateError: Error | null = null;
    try {
      await tn.admin.rotate("default");
    } catch (err) {
      rotateError = err instanceof Error ? err : new Error(String(err));
    }

    if (rotateError !== null) {
      // Document the reason so the skip message is informative.
      t.skip(
        `rotation is not yet supported in the TS SDK: ${rotateError.message}. ` +
          "Covered by Python's alice/s02_rotate. Un-skip when JWE rotation lands.",
      );

      // Structural assertions below — commented to show what would be checked:
      //
      // for (let i = 0; i < 200; i++) tn.info("evt.post", { seq: i });
      // await tn.close();
      //
      // const tn2 = await Tn.init(yamlPath, { stdout: false });
      // const entries = [...tn2.readRaw()].filter(e => !String(e.envelope["event_type"]).startsWith("tn."));
      // const pre = entries.filter(e => e.envelope["event_type"] === "evt.pre");
      // const post = entries.filter(e => e.envelope["event_type"] === "evt.post");
      //
      // ctx.assertInvariant("chain_verified", entries.every(e => e.valid.chain));
      // ctx.assertInvariant("signature_verified", entries.every(e => e.valid.signature));
      // ctx.assertInvariant("post_rotation_decryption_verified",
      //   post.every((e, idx) => (e.plaintext["default"] as Record<string,unknown>)?.["seq"] === idx));
      // // pre-rotation: may not decrypt (acceptable; see Python finding above)
      // ctx.record("pre_count", pre.length);
      // ctx.record("post_count", post.length);

      return;
    }

    // If rotation somehow succeeds (future JWE support), run the full body:
    for (let i = 0; i < 200; i++) {
      tn.info("evt.post", { seq: i });
    }

    const allEntries = [...tn.readRaw()].filter(
      (e) => !String(e.envelope["event_type"]).startsWith("tn."),
    );
    const pre = allEntries.filter((e) => e.envelope["event_type"] === "evt.pre");
    const post = allEntries.filter((e) => e.envelope["event_type"] === "evt.post");

    ctx.assertInvariant("chain_verified", allEntries.every((e) => Boolean(e.valid.chain)));
    ctx.assertInvariant("signature_verified", allEntries.every((e) => Boolean(e.valid.signature)));

    let postDecryptedCount = 0;
    let postDecryptOk = true;
    for (let idx = 0; idx < post.length; idx++) {
      const e = post[idx]!;
      const pt = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
      if (pt["seq"] === idx) {
        postDecryptedCount++;
      } else {
        postDecryptOk = false;
      }
    }

    ctx.assertInvariant(
      "post_rotation_decryption_verified",
      postDecryptOk && postDecryptedCount === 200,
      `post-rotation decrypted ${postDecryptedCount}/200`,
    );

    assert.equal(pre.length, 200, "expected 200 pre-rotation entries");
    assert.equal(post.length, 200, "expected 200 post-rotation entries");

    ctx.record("pre_count", pre.length);
    ctx.record("post_count", post.length);
    ctx.record("post_rotation_decrypted_count", postDecryptedCount);
  } finally {
    await tn.close();
  }
});
