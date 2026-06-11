// Signature-forgery + chain-break tamper coverage for `secure_read`
// (`Tn.read({verify})`) — the security hole the read_watch audit found
// (docs/cli-test-plans/read_watch.md §5.2, §5.3, §7.2).
//
// The existing secure_read.test.ts mutates `row_hash` ONLY. A regression
// that quietly dropped the Ed25519 signature check or the prev_hash chain
// check — while still recomputing row_hash — would pass that suite green.
// The two negative tests below exercise the signature path and the chain
// path IN ISOLATION so they bite the real verifier and nothing else.
//
// CLI gap: `readCmd` in bin/tn-js.mjs has NO `--verify` flag — secure_read
// is a library-only surface on the TS CLI today (only `watch --verify`
// runs verification). So these drive the SDK `Tn.read({verify})` API
// directly, matching how secure_read.test.ts already tests it. There is
// deliberately no spawned-CLI secure_read test here.
//
// Mechanism (see src/runtime/node_runtime.ts::read + src/core/chain.ts):
//   * row_hash commits to device_identity/timestamp/event_id/event_type/
//     level/prev_hash + public fields + per-group ciphertext+field_hashes.
//     It does NOT commit to sequence, row_hash itself, or signature.
//   * signature = Ed25519 over row_hash bytes.
//   * chain = entry.prev_hash === previous-same-event_type.row_hash.
//
// So replacing `signature` leaves row_hash valid (isolates the sig path);
// re-deriving entry #1's row_hash + signature after touching its `level`
// keeps entry #1 fully valid but staleens entry #2's prev_hash (isolates
// the chain path on entry #2).

import { strict as assert } from "node:assert";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { rowHash as computeRowHash } from "../src/core/chain.js";
import { DeviceKey, signatureB64 } from "../src/core/signing.js";
import { asDid, asRowHash, type GroupHashInput } from "../src/core/types.js";
import { VerifyError } from "../src/Entry.js";
import { Tn } from "../src/tn.js";

const RESERVED = new Set([
  "device_identity",
  "timestamp",
  "event_id",
  "event_type",
  "level",
  "sequence",
  "prev_hash",
  "row_hash",
  "signature",
]);

function readEnvelopes(path: string): Record<string, unknown>[] {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

function writeEnvelopes(path: string, envs: Record<string, unknown>[]): void {
  writeFileSync(path, envs.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
}

/** Split an on-disk envelope into (publicFields, groups) the same way the
 * verifier does, so a recompute here matches it byte-for-byte. The verifier
 * keys public fields off config.publicFields; we only ever re-sign after
 * touching `level` (a reserved field that IS part of row_hash), so the
 * public-field set is whatever it already was on disk. */
function splitForHash(env: Record<string, unknown>): {
  publicFields: Record<string, unknown>;
  groups: Record<string, GroupHashInput>;
} {
  const publicFields: Record<string, unknown> = {};
  const groups: Record<string, GroupHashInput> = {};
  for (const [k, v] of Object.entries(env)) {
    if (RESERVED.has(k)) continue;
    if (v && typeof v === "object" && "ciphertext" in (v as object)) {
      const g = v as { ciphertext: string; field_hashes?: Record<string, string> };
      groups[k] = {
        ciphertext: new Uint8Array(Buffer.from(g.ciphertext, "base64")),
        fieldHashes: g.field_hashes ?? {},
      };
    } else {
      publicFields[k] = v;
    }
  }
  return { publicFields, groups };
}

/** Recompute env.row_hash from its current fields and re-sign with `device`
 * so the envelope is internally valid (rowHashOk AND signatureOk). */
function resignInPlace(env: Record<string, unknown>, device: DeviceKey): void {
  const { publicFields, groups } = splitForHash(env);
  const newRowHash = computeRowHash({
    device_identity: asDid(String(env["device_identity"])),
    timestamp: String(env["timestamp"]),
    eventId: String(env["event_id"]),
    eventType: String(env["event_type"]),
    level: String(env["level"] ?? ""),
    prevHash: asRowHash(String(env["prev_hash"])),
    publicFields,
    groups,
  });
  env["row_hash"] = newRowHash;
  env["signature"] = device.signB64(new Uint8Array(Buffer.from(newRowHash, "utf8")));
}

function loadDeviceKey(client: Tn): DeviceKey {
  // `client.config` is the WasmRuntime config accessor (not the resolved
  // config object); the resolved ceremony config lives on the private
  // NodeRuntime at `_rt.config`, which carries `keystorePath`.
  const keystore = (client as unknown as { _rt: { config: { keystorePath: string } } })._rt.config
    .keystorePath;
  const seed = new Uint8Array(readFileSync(join(keystore, "local.private")));
  return DeviceKey.fromSeed(seed);
}

/** Read raw {envelope, plaintext, valid} triples by re-binding the same
 * ceremony from disk in a SECOND client (one tn flow per writer; the reader
 * is a fresh bind). verify is off so nothing is dropped — we want every
 * row's per-check booleans. */
async function readTriples(client: Tn): Promise<
  Array<{ envelope: Record<string, unknown>; valid: { signature: boolean; rowHash: boolean; chain: boolean } }>
> {
  // The NodeRuntime read recomputes valid per-row; reach it via the private
  // runtime so we can inspect the exact booleans the verify gate sees.
  const rt = (client as unknown as { _rt: { read(p?: string): Iterable<{ envelope: Record<string, unknown>; valid: { signature: boolean; rowHash: boolean; chain: boolean } }> } })._rt;
  return [...rt.read()];
}

// ---------------------------------------------------------------------------
// Happy path — genuine entries verify clean (parity with the Python suite).
// ---------------------------------------------------------------------------

test("secure_read happy path: genuine entries verify clean (no throw, no drop)", async () => {
  const client = await Tn.ephemeral();
  try {
    client.info("order.created", { amount: 100, order_id: "A100" });
    client.info("order.created", { amount: 200, order_id: "A200" });

    // verify:"raise" must not throw on clean rows.
    const raised = [...client.read({ verify: "raise", allRuns: true })];
    const hits = raised.filter(
      (e) => "event_type" in e && (e as { event_type: string }).event_type === "order.created",
    );
    assert.equal(hits.length, 2, "both genuine rows must verify");

    // Every genuine row's per-check valid block is all-True.
    const triples = await readTriples(client);
    const orderRows = triples.filter((t) => t.envelope["event_type"] === "order.created");
    assert.equal(orderRows.length, 2);
    for (const t of orderRows) {
      assert.equal(t.valid.signature, true);
      assert.equal(t.valid.rowHash, true);
      assert.equal(t.valid.chain, true);
    }
  } finally {
    await client.close();
  }
});

// ---------------------------------------------------------------------------
// §5.2 — FORGED SIGNATURE (valid row_hash). The key gap.
// ---------------------------------------------------------------------------

test("forged signature with valid row_hash is rejected (isolates the signature path)", async () => {
  const client = await Tn.ephemeral();
  try {
    client.info("order.created", { amount: 100, order_id: "A100" });

    const path = client.logPath;
    const envs = readEnvelopes(path);
    assert.equal(envs.length, 1);
    const target = envs[0]!;
    const goodRowHash = target["row_hash"];

    // Forge: a structurally-real Ed25519 signature (right length, real key)
    // but over a DIFFERENT message, so it cannot verify against row_hash.
    // row_hash is left untouched -> rowHashOk stays true.
    const forger = DeviceKey.generate();
    const bogus = forger.sign(new Uint8Array(Buffer.from("not the row hash", "utf8")));
    target["signature"] = signatureB64(bogus);
    assert.equal(target["row_hash"], goodRowHash, "row_hash must stay valid");
    writeEnvelopes(path, envs);

    // 1) Per-check isolation: ONLY signature fails.
    const triples = await readTriples(client);
    const row = triples.find((t) => t.envelope["event_type"] === "order.created");
    assert.ok(row, "must find the row");
    assert.equal(
      row!.valid.rowHash,
      true,
      "row_hash must stay valid — otherwise this doesn't isolate the signature path",
    );
    assert.equal(row!.valid.chain, true);
    assert.equal(row!.valid.signature, false, "forged signature must fail the sig check");

    // 2) verify:"raise" must throw, citing signature (not row_hash).
    assert.throws(
      () => [...client.read({ verify: "raise", allRuns: true })],
      (e: unknown) => {
        assert.ok(e instanceof VerifyError);
        assert.ok(e.failed_checks.includes("signature"));
        assert.ok(!e.failed_checks.includes("row_hash"));
        return true;
      },
    );

    // 3) verify:"skip" must DROP the forged row.
    const skipped = [...client.read({ verify: "skip", allRuns: true })];
    assert.ok(
      !skipped.some(
        (e) => "event_type" in e && (e as { event_type: string }).event_type === "order.created",
      ),
      "forged-signature row must be skipped",
    );

    // 4) Plain read (no verify) must STILL surface it — proves verify is what
    //    rejects it, not the parser.
    const plain = [...client.read({ allRuns: true })];
    assert.ok(
      plain.some(
        (e) => "event_type" in e && (e as { event_type: string }).event_type === "order.created",
      ),
      "plain read must still surface the forged row",
    );
  } finally {
    await client.close();
  }
});

// ---------------------------------------------------------------------------
// §5.3 — BROKEN prev_hash CHAIN (isolated from row_hash + signature).
// ---------------------------------------------------------------------------

test("broken prev_hash chain is rejected (isolates the chain path)", async () => {
  const client = await Tn.ephemeral();
  try {
    client.info("order.created", { amount: 100, order_id: "A100" });
    client.info("order.created", { amount: 200, order_id: "A200" });

    const device = loadDeviceKey(client);
    const path = client.logPath;
    const envs = readEnvelopes(path);
    const rows = envs.filter((e) => e["event_type"] === "order.created");
    assert.equal(rows.length, 2);
    const [row1, row2] = rows as [Record<string, unknown>, Record<string, unknown>];
    assert.equal(row2["prev_hash"], row1["row_hash"], "precondition: chain intact");

    // Touch a field on row #1 that IS part of row_hash (level), then re-derive
    // row1.row_hash + signature so row #1 stays fully self-valid. Its new
    // row_hash no longer matches row #2's prev_hash -> chain breaks at row #2
    // while row #2's own row_hash + signature stay valid.
    const oldRow1Hash = row1["row_hash"];
    row1["level"] = "warning"; // was "info"
    resignInPlace(row1, device);
    assert.notEqual(row1["row_hash"], oldRow1Hash, "row #1's row_hash must change");
    assert.equal(row2["prev_hash"], oldRow1Hash, "row #2 untouched: prev_hash now stale");
    assert.notEqual(row2["prev_hash"], row1["row_hash"]);
    writeEnvelopes(path, envs);

    // Per-check isolation: row #1 fully valid; row #2 fails ONLY on chain.
    const triples = await readTriples(client);
    const bySeq = new Map(triples.map((t) => [Number(t.envelope["sequence"]), t.valid]));
    const v1 = bySeq.get(1)!;
    const v2 = bySeq.get(2)!;
    assert.equal(v1.rowHash, true, "row #1 row_hash valid after re-sign");
    assert.equal(v1.signature, true, "row #1 signature valid after re-sign");
    assert.equal(v1.chain, true, "row #1 chain valid (first in chain)");
    assert.equal(
      v2.rowHash,
      true,
      "row #2 row_hash must stay valid — otherwise this doesn't isolate the chain path",
    );
    assert.equal(v2.signature, true, "row #2 signature must stay valid");
    assert.equal(v2.chain, false, "the broken chain link must be flagged");

    // verify:"raise" must throw, citing chain.
    assert.throws(
      () => [...client.read({ verify: "raise", allRuns: true })],
      (e: unknown) => {
        assert.ok(e instanceof VerifyError);
        assert.ok(e.failed_checks.includes("chain"));
        return true;
      },
    );

    // verify:"skip" drops only the chain-broken row #2.
    const skipped = [...client.read({ verify: "skip", allRuns: true })];
    const amounts = skipped
      .filter(
        (e) => "event_type" in e && (e as { event_type: string }).event_type === "order.created",
      )
      .map((e) => (e as { fields: Record<string, unknown> }).fields["amount"])
      .sort();
    assert.deepEqual(amounts, [100], "only the chain-broken row should be dropped");
  } finally {
    await client.close();
  }
});

// ---------------------------------------------------------------------------
// §5.1 — baseline: tampered row_hash is rejected (parity with secure_read.test.ts).
// ---------------------------------------------------------------------------

test("tampered row_hash is rejected; plain read still surfaces it", async () => {
  const client = await Tn.ephemeral();
  try {
    client.info("order.created", { amount: 100 });
    const path = client.logPath;
    const envs = readEnvelopes(path);
    envs[0]!["row_hash"] = "sha256:" + "0".repeat(64);
    writeEnvelopes(path, envs);

    assert.throws(
      () => [...client.read({ verify: "raise", allRuns: true })],
      (e: unknown) => {
        assert.ok(e instanceof VerifyError);
        assert.ok(e.failed_checks.includes("row_hash"));
        return true;
      },
    );

    const skipped = [...client.read({ verify: "skip", allRuns: true })];
    assert.ok(
      !skipped.some(
        (e) => "event_type" in e && (e as { event_type: string }).event_type === "order.created",
      ),
    );

    const plain = [...client.read({ allRuns: true })];
    assert.ok(
      plain.some(
        (e) => "event_type" in e && (e as { event_type: string }).event_type === "order.created",
      ),
      "plain read must still surface the tampered row",
    );
  } finally {
    await client.close();
  }
});
