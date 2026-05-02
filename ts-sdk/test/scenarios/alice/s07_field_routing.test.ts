// Alice s07 — route fields into pii / ops / finance groups.
//
// Python original: python/scenarios/alice/s07_field_routing.py
//
// SKIP REASON: Python's tn.ensure_group(cfg, "pii", fields=["email", "ip"])
// wires field-to-group routing at ceremony setup time.  The TS SDK's
// tn.admin.ensureGroup(name) does NOT accept a field-list; field-to-group
// routing is a yaml-only configuration that cannot be set programmatically
// via the current TS admin namespace.
//
// Covered by Python's alice/s07_field_routing and Python's
// test_multi_group_routing.py.  Un-skip and complete when the TS admin
// namespace exposes field routing (e.g. ensureGroup(name, { fields: [...] })).
//
// Assertion intent (for when the API exists):
//   1. ensureGroup("pii",     { fields: ["email", "ip"] })
//   2. ensureGroup("ops",     { fields: ["latency_ms", "country"] })
//   3. ensureGroup("finance", { fields: ["amount"] })
//   4. Emit 100 user.signup events with all 5 fields.
//   5. readRaw(): for each entry verify:
//      - plaintext["pii"]["email"]  === `u${idx}@ex.com`
//      - plaintext["pii"]["ip"]     === "10.0.0.1"
//      - plaintext["ops"]["latency_ms"] === 42
//      - plaintext["ops"]["country"]    === "ES"
//      - plaintext["finance"]["amount"] === 1000 + idx
//   6. assertInvariant: each per-group count === 100.

import { test } from "node:test";
import { Tn } from "../../../src/tn.js";
import { ScenarioContext } from "../_harness.js";

test("alice/s07_field_routing — structural placeholder (yaml-driven field routing not yet in TS admin API)", async (t) => {
  // Document that the API gap prevents a clean port.
  t.skip(
    "requires yaml-driven field routing not yet exposed on the TS admin namespace " +
      "(tn.admin.ensureGroup does not accept a field-list). " +
      "Covered by Python's alice/s07_field_routing. " +
      "Un-skip when TS admin API supports ensureGroup(name, { fields: [...] }).",
  );

  // Structural placeholder — the code below reflects the intended port and
  // will be activated when the API gap is closed.
  const ctx = new ScenarioContext();
  const tn = await Tn.ephemeral({ stdout: false });

  try {
    // When field routing is available:
    // await tn.admin.ensureGroup("pii",     { fields: ["email", "ip"] });
    // await tn.admin.ensureGroup("ops",     { fields: ["latency_ms", "country"] });
    // await tn.admin.ensureGroup("finance", { fields: ["amount"] });

    for (let i = 0; i < 100; i++) {
      tn.info("user.signup", {
        email: `u${i}@ex.com`,
        ip: "10.0.0.1",
        amount: 1000 + i,
        country: "ES",
        latency_ms: 42,
      });
    }

    const entries = [...tn.readRaw()].filter(
      (e) => e.envelope["event_type"] === "user.signup",
    );

    // When field routing works, each entry's plaintext would have per-group
    // buckets.  Without routing, all fields land in plaintext["default"].
    // The assertions below are the TARGET state, not the current behavior:
    //
    // const piiOk = entries.every((e, idx) => {
    //   const pii = (e.plaintext["pii"] ?? {}) as Record<string, unknown>;
    //   return pii["email"] === `u${idx}@ex.com` && pii["ip"] === "10.0.0.1";
    // });
    // const opsOk = entries.every(e => {
    //   const ops = (e.plaintext["ops"] ?? {}) as Record<string, unknown>;
    //   return ops["latency_ms"] === 42 && ops["country"] === "ES";
    // });
    // const finOk = entries.every((e, idx) => {
    //   const fin = (e.plaintext["finance"] ?? {}) as Record<string, unknown>;
    //   return fin["amount"] === 1000 + idx;
    // });
    // ctx.assertInvariant("chain_verified", entries.every(e => e.valid.chain));
    // ctx.assertInvariant("signature_verified", entries.every(e => e.valid.signature));
    // ctx.assertInvariant("decryption_verified_pii", piiOk);
    // ctx.assertInvariant("decryption_verified_ops", opsOk);
    // ctx.assertInvariant("decryption_verified_finance", finOk);

    ctx.record("log_count", entries.length);
    ctx.record("group_count", 3);
  } finally {
    await tn.close();
  }
});
