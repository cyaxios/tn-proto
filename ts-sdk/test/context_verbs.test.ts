// FINDINGS Round 5 cross-binding parity — TS context verbs.
// Mirrors Python's `tn.set_context / update_context / clear_context /
// get_context`. The `scope()` closure form was already shipped; this
// adds the long-lived (middleware-style) form for parity with Python.

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { TNClient } from "../src/index.js";

test("setContext / updateContext / clearContext / getContext flow", () => {
  const c = TNClient.ephemeral({ stdout: false });
  try {
    // Empty by default.
    assert.deepEqual(c.getContext(), {});

    // setContext replaces the long-lived layer wholesale.
    c.setContext({ request_id: "req_abc", user_id: "u_42" });
    assert.deepEqual(c.getContext(), { request_id: "req_abc", user_id: "u_42" });

    // updateContext merges (additive); existing keys can be overwritten
    // by an explicit kwarg.
    c.updateContext({ trace_id: "tr_xyz", user_id: "u_43" });
    assert.deepEqual(c.getContext(), {
      request_id: "req_abc",
      user_id: "u_43",
      trace_id: "tr_xyz",
    });

    // clearContext drops everything.
    c.clearContext();
    assert.deepEqual(c.getContext(), {});
  } finally {
    c.close();
  }
});

test("scope() overlays compose with setContext (long-lived bottom layer)", () => {
  const c = TNClient.ephemeral({ stdout: false });
  try {
    c.setContext({ request_id: "req_outer" });

    let mid: Record<string, unknown> = {};
    c.scope({ sale_id: "s_1" }, () => {
      mid = c.getContext();
    });

    // Inside the scope: long-lived + overlay.
    assert.deepEqual(mid, { request_id: "req_outer", sale_id: "s_1" });
    // After the scope: long-lived survives, overlay is gone.
    assert.deepEqual(c.getContext(), { request_id: "req_outer" });
  } finally {
    c.close();
  }
});

test("setContext fields land on emitted entries", () => {
  const c = TNClient.ephemeral({ stdout: false });
  try {
    c.setContext({ request_id: "req_check", user_id: "u_check" });
    c.info("evt.ctx", { marker: "m1" });
    c.clearContext();

    // Find the emitted envelope.
    const entries = [...c.read({ raw: true })];
    const env = entries
      .map((e) => (e as { envelope: Record<string, unknown> }).envelope)
      .find((e) => e["event_type"] === "evt.ctx");
    assert.ok(env, "evt.ctx envelope not found");

    // request_id is in DEFAULT_PUBLIC_FIELDS so it lands at the
    // envelope top level. user_id routes into the default group's
    // ciphertext (not directly readable from the raw envelope unless
    // we traverse plaintext). The envelope-level check is the easier
    // assertion and proves setContext fields propagate.
    assert.equal(env["request_id"], "req_check", "request_id missing on envelope");
  } finally {
    c.close();
  }
});
