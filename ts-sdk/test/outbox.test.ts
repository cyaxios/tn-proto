import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DurableOutbox, OutboxWorker } from "../src/handlers/outbox.js";

// Port parity with python/tn/handlers/outbox.py: crash-safe durable queue
// (ack-after-publish, reappear-on-crash) + retry worker with backoff.

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "tn-outbox-"));
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

test("put/claim/ack is FIFO and removes the item", () => {
  const dir = tmp();
  const q = new DurableOutbox(dir);
  q.put({ envelope: { event_type: "a" }, raw: "ra" });
  q.put({ envelope: { event_type: "b" }, raw: "rb" });
  assert.equal(q.size(), 2);

  const first = q.claimNext();
  assert.equal(first?.item.envelope["event_type"], "a");
  const second = q.claimNext();
  assert.equal(second?.item.envelope["event_type"], "b");

  q.ack(first!.claim);
  q.ack(second!.claim);
  assert.equal(q.size(), 0);
  assert.equal(q.claimNext(), null);
});

test("nack returns a claimed item to the pending pool", () => {
  const dir = tmp();
  const q = new DurableOutbox(dir);
  q.put({ envelope: { event_type: "x" }, raw: "r" });
  const c = q.claimNext();
  assert.ok(c);
  q.nack(c!.claim);
  assert.equal(q.size(), 1);
  // Reclaimable after nack.
  const again = q.claimNext();
  assert.equal(again?.item.raw, "r");
});

test("crash recovery: a left-behind .processing item is reclaimed on construct", () => {
  const dir = tmp();
  const q1 = new DurableOutbox(dir);
  q1.put({ envelope: { event_type: "survive" }, raw: "r" });
  // Simulate a crash mid-publish: claim (marks .processing) then "die".
  const claimed = q1.claimNext();
  assert.ok(claimed);
  // Files on disk: one .processing item, no pending.
  assert.ok(readdirSync(dir).some((n) => n.endsWith(".processing.json")));

  // New process opens the same dir -> the in-flight item is reset to pending.
  const q2 = new DurableOutbox(dir);
  assert.equal(q2.size(), 1);
  const reclaimed = q2.claimNext();
  assert.equal(reclaimed?.item.envelope["event_type"], "survive");
});

test("worker delivers all items in order, then drains to empty", async () => {
  const dir = tmp();
  const q = new DurableOutbox(dir);
  const delivered: string[] = [];
  const worker = new OutboxWorker(q, (_env, raw) => {
    delivered.push(raw);
  }, { name: "t", pollMs: 20 });
  worker.start();

  for (const r of ["1", "2", "3"]) q.put({ envelope: {}, raw: r });
  // Wait for drain.
  for (let i = 0; i < 50 && q.size() > 0; i++) await sleep(20);
  await worker.stop({ timeoutMs: 1000 });

  assert.deepEqual(delivered, ["1", "2", "3"]);
  assert.equal(q.size(), 0);
});

test("worker retries on publish failure, then succeeds (at-least-once)", async () => {
  const dir = tmp();
  const q = new DurableOutbox(dir);
  let attempts = 0;
  const worker = new OutboxWorker(
    q,
    () => {
      attempts += 1;
      if (attempts < 3) throw new Error("transient");
    },
    { name: "retry", pollMs: 20, backoffInitialMs: 10, backoffMaxMs: 50, jitter: () => 1.0 },
  );
  worker.start();
  q.put({ envelope: {}, raw: "payload" });

  for (let i = 0; i < 100 && q.size() > 0; i++) await sleep(20);
  await worker.stop({ timeoutMs: 1000 });

  assert.ok(attempts >= 3, `expected >=3 attempts, got ${attempts}`);
  assert.equal(q.size(), 0, "item should be acked after eventual success");
});

test("worker gives up after maxRetries (item left for a future pass)", async () => {
  const dir = tmp();
  const q = new DurableOutbox(dir);
  let attempts = 0;
  const worker = new OutboxWorker(
    q,
    () => {
      attempts += 1;
      throw new Error("always fails");
    },
    { name: "giveup", pollMs: 20, maxRetries: 3, backoffInitialMs: 5, backoffMaxMs: 20, jitter: () => 1.0 },
  );
  worker.start();
  q.put({ envelope: {}, raw: "doomed" });
  await sleep(300);
  await worker.stop({ timeoutMs: 500 });

  // Hit the retry ceiling and nacked (item still queued, not lost).
  assert.ok(attempts >= 3, `expected >=3 attempts, got ${attempts}`);
  assert.ok(q.size() >= 1, "doomed item stays durably queued, not dropped");
});
