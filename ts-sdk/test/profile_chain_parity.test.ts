/**
 * Parity test for the per-profile `ceremony.chain` flag.
 *
 * The profile catalog declares `secure_log.chains === false` and
 * `telemetry.chains === false`; `transaction`/`audit` are `true`. The
 * Rust/wasm core honours `ceremony.chain`: when false it advances the
 * per-(publisher, event_type) sequence but writes `prev_hash: ""`
 * (the "no linkage claim" sentinel) instead of linking the prior row.
 *
 * This test pins the end-to-end behaviour for both yaml-writing paths
 * the TS SDK owns:
 *   - named streams (`_createStreamYaml` via Tn.use)
 *   - default / as-root ceremonies (`createFreshCeremony`)
 *
 * Regression guard: before the fix, both writers dropped the chains
 * flag (stream omitted it; default hardcoded `chain: true`), so the
 * Rust core saw its `true` default and chained every row regardless
 * of profile — diverging from Python, which stamps `ceremony.chain =
 * profile.chains` in both paths.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { Tn } from "../src/tn.js";
import { createFreshCeremony } from "../src/runtime/node_runtime.js";

function makeProject(): string {
  return mkdtempSync(join(tmpdir(), "tn-chain-parity-"));
}

/** Emit `count` rows of the same event_type and return the on-disk
 *  (prev_hash, row_hash, sequence) triples in write order. */
function emitAndScan(
  tn: Tn,
  eventType: string,
  count: number,
): Array<{ prevHash: string; rowHash: string; sequence: number }> {
  for (let i = 0; i < count; i += 1) {
    tn.info(eventType, { n: i });
  }
  const rows: Array<{ prevHash: string; rowHash: string; sequence: number }> = [];
  for (const env of tn.read({ raw: true })) {
    const e = env as Record<string, unknown>;
    if (e["event_type"] !== eventType) continue;
    rows.push({
      prevHash: String(e["prev_hash"] ?? ""),
      rowHash: String(e["row_hash"] ?? ""),
      sequence: Number(e["sequence"] ?? 0),
    });
  }
  return rows;
}

test("secure_log stream: chains=false -> empty prev_hash, sequence still advances", async () => {
  const project = makeProject();
  try {
    const tn = await Tn.use("secure", { projectDir: project, profile: "secure_log" });
    try {
      const rows = emitAndScan(tn, "user.action", 3);
      assert.equal(rows.length, 3, "expected 3 user.action rows");

      // prev_hash is the empty sentinel on every row (NOT genesis zero-hash).
      assert.deepEqual(
        rows.map((r) => r.prevHash),
        ["", "", ""],
        "secure_log must write empty prev_hash on every row",
      );

      // Sequence still increments per (publisher, event_type).
      assert.deepEqual(
        rows.map((r) => r.sequence),
        [1, 2, 3],
        "sequence must advance even when unchained",
      );

      // No row links to its predecessor.
      const prevLinks = rows.slice(1).map((r, i) => r.prevHash === rows[i]!.rowHash);
      assert.deepEqual(prevLinks, [false, false], "secure_log rows must not chain");
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("transaction stream: chains=true -> linked prev_hash, sequence advances", async () => {
  const project = makeProject();
  try {
    const tn = await Tn.use("ledger", { projectDir: project, profile: "transaction" });
    try {
      const rows = emitAndScan(tn, "payment.made", 3);
      assert.equal(rows.length, 3, "expected 3 payment.made rows");

      assert.deepEqual(
        rows.map((r) => r.sequence),
        [1, 2, 3],
        "sequence must advance",
      );

      // Every row carries a non-empty prev_hash, and rows 2+ link to the
      // prior row's row_hash.
      assert.ok(
        rows.every((r) => r.prevHash !== ""),
        "transaction rows must carry a non-empty prev_hash",
      );
      const prevLinks = rows.slice(1).map((r, i) => r.prevHash === rows[i]!.rowHash);
      assert.deepEqual(prevLinks, [true, true], "transaction rows must chain");
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("createFreshCeremony default ceremony honours secure_log chains=false", async () => {
  const project = makeProject();
  try {
    // The default / as-root writer mints its own keystore + full yaml.
    // The profile's chains flag must reach the written ceremony block.
    const yamlPath = join(project, "tn.yaml");
    createFreshCeremony(yamlPath, {
      profile: "secure_log",
      keystoreDir: join(project, "keys"),
      logPath: join(project, "logs", "tn.ndjson"),
      adminLogPath: join(project, "admin", "admin.ndjson"),
    });

    const tn = await Tn.init(yamlPath);
    try {
      const rows = emitAndScan(tn, "secret.read", 3);
      assert.equal(rows.length, 3, "expected 3 secret.read rows");
      assert.deepEqual(
        rows.map((r) => r.prevHash),
        ["", "", ""],
        "default secure_log must write empty prev_hash on every row",
      );
      assert.deepEqual(
        rows.map((r) => r.sequence),
        [1, 2, 3],
        "sequence must advance even when unchained",
      );
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});
