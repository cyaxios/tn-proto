/**
 * SILO: C4 — TS object-level logging
 * TEST: two Tn handles (payments + billing) don't cross-contaminate.
 * SEE: regression/crawl/c4_ts_object_log/README.md
 *
 * TS-side analogue of C2's multi-ceremony isolation test. The TS
 * registry interns by `(projectDir, name)` (Bug 8 fix in tn.ts:Tn.use).
 * If interning regresses, both handles share a single NodeRuntime and
 * writes cross-stream.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

test("C4: two Tn handles do not cross-contaminate", async () => {
  setTestContext({ silo: "c4", test: "c4_multi_ceremony_isolation::no_cross" });

  const td = mkdtempSync(join(tmpdir(), "c4-isolation-"));
  const cwdBefore = process.cwd();
  process.chdir(td);

  let payments: Tn | undefined;
  let billing: Tn | undefined;

  try {
    payments = await Tn.use("payments");
    billing = await Tn.use("billing");

    assertNamed({
      name: "payments-and-billing-have-distinct-yamls",
      expected: true,
      observed: payments.yamlPath !== billing.yamlPath,
      onMiss:
        "Both handles report the same yamlPath (" +
        JSON.stringify(payments.yamlPath) +
        "). The TS registry should mint distinct .tn/payments/ and " +
        ".tn/billing/ subdirs. Check ts-sdk/src/tn.ts:Tn.use cache " +
        "key (must include the name segment).",
    });

    payments.info("payments.charge", { amount: 1000 });
    billing.info("billing.invoice", { invoice_id: "INV-42" });

    const paymentsEvents = Array.from(payments.read())
      .map((e: { event_type?: string }) => e.event_type)
      .filter((s): s is string => typeof s === "string")
      .sort();
    const billingEvents = Array.from(billing.read())
      .map((e: { event_type?: string }) => e.event_type)
      .filter((s): s is string => typeof s === "string")
      .sort();

    assertNamed({
      name: "payments-read-has-payments-event",
      expected: true,
      observed: paymentsEvents.includes("payments.charge"),
      onMiss:
        "payments.read() missing 'payments.charge'. Got " +
        JSON.stringify(paymentsEvents),
    });

    assertNamed({
      name: "payments-read-does-not-have-billing-event",
      expected: false,
      observed: paymentsEvents.includes("billing.invoice"),
      onMiss:
        "payments.read() yielded 'billing.invoice' — cross-stream " +
        "contamination. The two handles are sharing a NodeRuntime. " +
        "Check the TS registry in tn.ts:Tn.use — cache key must include " +
        "the name. payments=" +
        JSON.stringify(paymentsEvents),
    });

    assertNamed({
      name: "billing-read-has-billing-event",
      expected: true,
      observed: billingEvents.includes("billing.invoice"),
      onMiss:
        "billing.read() missing 'billing.invoice'. Got " +
        JSON.stringify(billingEvents),
    });

    assertNamed({
      name: "billing-read-does-not-have-payments-event",
      expected: false,
      observed: billingEvents.includes("payments.charge"),
      onMiss:
        "billing.read() yielded 'payments.charge' — same cross-stream " +
        "contamination as above. billing=" +
        JSON.stringify(billingEvents),
    });

    assert.ok(true, "all asserts above");
  } finally {
    if (payments !== undefined) await payments.close();
    if (billing !== undefined) await billing.close();
    process.chdir(cwdBefore);
  }
});
