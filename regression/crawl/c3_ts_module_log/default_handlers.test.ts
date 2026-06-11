/**
 * SILO: C3 — TS module-level logging
 * TEST: tn.init() + tn.info() round-trip through the bare module-level surface
 * SEE: regression/crawl/c3_ts_module_log/README.md
 *
 * This test mirrors C1 (Python) on the TS side. The bare-export surface
 * was added in the same PR — before that, TS had only the `Tn` class.
 * The critic log log entry (.tn-internal/critic log
 * 2026-05-14 — C3) records the gap that was fixed.
 *
 * Flow:
 *   1. Fresh tmpdir; mint a valid ceremony via NodeRuntime so the yaml
 *      exists for the bare `tn.init` to load.
 *   2. `await tn.init(yamlPath)` via the bare module-level surface.
 *   3. `tn.info("c3.hello", { a: 1, b: "two" })`.
 *   4. `Array.from(tn.read())` round-trips the entry back.
 *   5. Cleanup: `await tn.close()`.
 *
 * Asserts (named, identical shape to C1):
 *   - "init-returns-tn-instance": tn.init resolves to a Tn-like object
 *   - "log-event-on-disk": attested log contains the c3.hello envelope
 *   - "read-returns-entry": tn.read() surfaces the just-written entry
 *   - "fields-preserved-int" / "fields-preserved-str": field types round-trip
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as tn from "../../../ts-sdk/src/index.ts";
import { NodeRuntime } from "../../../ts-sdk/src/index.ts";

import { assertNamed, setTestContext } from "../../_shared/assertions.js";
import { LogQuery } from "../../_shared/log_query.js";

test("C3: bare module-level init + info + read round-trip", async () => {
  setTestContext({ silo: "c3", test: "c3_default_handlers::round_trip" });

  // Step 1: mint a real ceremony on disk via NodeRuntime (this is just
  // a valid yaml + keystore source — the actual test below uses the
  // bare-module surface).
  const td = mkdtempSync(join(tmpdir(), "c3-default-"));
  const yamlPath = join(td, "tn.yaml");
  const noderuntime = NodeRuntime.init(yamlPath);
  noderuntime.close();

  // Step 2: drive everything through the BARE MODULE SURFACE.
  const inst = await tn.init(yamlPath);

  assertNamed({
    name: "init-returns-tn-instance",
    expected: "Tn",
    observed: inst?.constructor?.name ?? "undefined",
    onMiss:
      "tn.init() did not return a Tn instance. Check ts-sdk/src/index.ts:init bare-export wrapper.",
  });

  try {
    tn.info("c3.hello", { a: 1, b: "two" });

    // Style-1: TN-native log query (same DSL as C1).
    const log = new LogQuery({ ceremonyPath: yamlPath });
    log.assertContains({
      name: "log-event-on-disk",
      where: { event_type: "c3.hello" },
      onMiss:
        "tn.info('c3.hello', ...) didn't produce an attested envelope on disk. " +
        "Check ts-sdk/src/index.ts:info bare-export wrapper and ts-sdk/src/tn.ts:info instance method.",
    });

    // Round-trip via the bare-module read.
    const entries = Array.from(tn.read()) as Array<{
      event_type?: string;
      fields?: Record<string, unknown>;
    }>;

    const ours = entries.find((e) => e.event_type === "c3.hello");
    assertNamed({
      name: "read-returns-entry",
      expected: "found",
      observed: ours === undefined ? "not-found" : "found",
      onMiss:
        "tn.read() did not surface the just-written c3.hello envelope. " +
        "Check ts-sdk/src/index.ts:read bare-export wrapper and ts-sdk/src/tn.ts:read instance method.",
    });

    assert.ok(ours, "narrowing: ours not undefined (named assert above caught it)");

    assertNamed({
      name: "fields-preserved-int",
      expected: 1,
      observed: ours.fields?.a,
      onMiss:
        "Field 'a' came back wrong. Check the wasm wire-format round-trip in ts-sdk/src/runtime/node_runtime.ts emit pipeline.",
    });
    assertNamed({
      name: "fields-preserved-str",
      expected: "two",
      observed: ours.fields?.b,
      onMiss: "Field 'b' came back wrong. Same code paths as fields-preserved-int.",
    });
  } finally {
    await tn.close();
  }
});
