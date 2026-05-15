/**
 * SILO: C4 — TS object-level logging
 * TEST: Tn.use(name) returns a handle that round-trips info+read.
 * SEE: regression/crawl/c4_ts_object_log/README.md
 *
 * Mirrors C2 on the Python side. The bare module-level surface is
 * already covered by C3; this silo exercises the class-level surface.
 *
 * Flow:
 *   1. Hop into a per-test tmpdir + chdir so Tn.use's discovery mints
 *      at <tmpdir>/.tn/<name>/.
 *   2. const t = await Tn.use("payments");
 *   3. t.info("payments.charge", { amount: 1000, currency: "USD" });
 *   4. Array.from(t.read()) yields the entry.
 *   5. await t.close().
 *
 * Asserts (named):
 *   - "handle-name-is-payments"
 *   - "handle-yaml-points-at-payments-dir"
 *   - "handle-info-event-on-disk"
 *   - "handle-read-returns-entry"
 *   - "fields-preserved-amount"
 *   - "fields-preserved-currency"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";
import { LogQuery } from "../../_shared/log_query.js";

test("C4: Tn.use(name) handle round-trip", async () => {
  setTestContext({ silo: "c4", test: "c4_handle_round_trip::round_trip" });

  const td = mkdtempSync(join(tmpdir(), "c4-handle-"));
  const cwdBefore = process.cwd();
  process.chdir(td);

  let t: Tn | undefined;
  try {
    t = await Tn.use("payments");

    assertNamed({
      name: "handle-name-is-payments",
      expected: "payments",
      observed: t.name,
      onMiss:
        "Tn.use('payments') returned handle.name=" +
        JSON.stringify(t.name) +
        ". Check ts-sdk/src/tn.ts:Tn.use registry interning + name getter.",
    });

    const yamlPath = t.yamlPath;
    assertNamed({
      name: "handle-yaml-points-at-payments-dir",
      expected: true,
      observed: yamlPath.includes(".tn") && yamlPath.includes("payments"),
      onMiss:
        "Tn.use('payments').yamlPath=" +
        JSON.stringify(yamlPath) +
        " — should resolve to <cwd>/.tn/payments/tn.yaml. " +
        "Check ts-sdk/src/multi.ts:ceremonyYamlPath.",
    });

    t.info("payments.charge", { amount: 1000, currency: "USD" });

    // Style-1: LogQuery against the on-disk envelope.
    const log = new LogQuery({ ceremonyPath: yamlPath });
    log.assertContains({
      name: "handle-info-event-on-disk",
      where: { event_type: "payments.charge" },
      onMiss:
        "t.info('payments.charge', ...) didn't produce an attested envelope " +
        "on disk. Check ts-sdk/src/tn.ts:Tn.info instance method + " +
        "ts-sdk/src/runtime/node_runtime.ts emit pipeline.",
    });

    // Round-trip via the handle's own read().
    const entries = Array.from(t.read()) as Array<{
      event_type?: string;
      fields?: Record<string, unknown>;
    }>;
    const ours = entries.find((e) => e.event_type === "payments.charge");
    assertNamed({
      name: "handle-read-returns-entry",
      expected: true,
      observed: ours !== undefined,
      onMiss:
        "t.read() on the payments handle didn't yield the just-written entry. " +
        "Got " +
        String(entries.length) +
        " total entries. Check ts-sdk/src/tn.ts:Tn.read.",
    });
    assert.ok(ours, "narrowing: named assert above caught it");

    assertNamed({
      name: "fields-preserved-amount",
      expected: 1000,
      observed: ours.fields?.amount,
      onMiss:
        "Field 'amount' came back wrong. Check wasm wire-format round-trip in ts-sdk/src/runtime/node_runtime.ts.",
    });
    assertNamed({
      name: "fields-preserved-currency",
      expected: "USD",
      observed: ours.fields?.currency,
      onMiss: "Field 'currency' came back wrong.",
    });
  } finally {
    if (t !== undefined) await t.close();
    process.chdir(cwdBefore);
  }
});
