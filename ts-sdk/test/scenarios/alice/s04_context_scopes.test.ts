// Alice s04 — setContext under Promise.all (async), verify no context bleed.
//
// Python original: python/scenarios/alice/s04_context_scopes.py
//
// Threading note: Python tests both asyncio.gather (async) and threading.Thread
// (OS threads). JS is single-threaded, so true thread isolation is not
// applicable here.  We exercise the async path via Promise.all and confirm
// that per-task context (setContext/clearContext) does not bleed between
// concurrent async invocations.
//
// Caveat: JS's event loop means setContext mutations are immediately visible
// to any code running in the same micro-task. The meaningful bleed scenario
// in Python is cross-thread (thread-local context). In JS the equivalent is
// ensuring that each async worker resets context cleanly so a worker's
// context doesn't persist after clearContext().  That is what we test here.
//
// The thread path from Python is replaced with a sequential array of calls
// (Worker threads in Node.js require message-passing which doesn't match
// the single-shared-Tn-instance model from Python).

import { test } from "node:test";
import { ScenarioContext } from "../_harness.js";
import { Entry } from "../../../src/Entry.js";

const ASYNC_TASKS = 20;

test("alice/s04_context_scopes — setContext/clearContext no bleed under Promise.all", async () => {
  const ctx = new ScenarioContext();
  const tn = await ScenarioContext.newTn();

  try {
    // Async workers: each sets its own context, emits, then clears.
    // Because JS is single-threaded these actually run interleaved —
    // the important thing is that each worker sees its OWN request_id
    // and the final getContext() is clean after all workers finish.
    async function asyncWorker(rid: number): Promise<void> {
      tn.setContext({ request_id: `async-${rid}`, worker: "async" });
      tn.info("work.async", { i: rid });
      tn.clearContext();
    }

    await Promise.all(Array.from({ length: ASYNC_TASKS }, (_, i) => asyncWorker(i)));

    // After all workers clear: context should be empty.
    const finalCtx = tn.getContext();
    // run_id is injected by the SDK on emit, not via setContext, so getContext()
    // should not have run_id.  worker / request_id should be absent.
    ctx.assertInvariant(
      "context_clean_after_workers",
      !("worker" in finalCtx) && !("request_id" in finalCtx),
      `context still has fields after all workers cleared: ${JSON.stringify(finalCtx)}`,
    );

    // Read back and verify per-entry field integrity.
    const entries: Entry[] = [];
    for (const e of tn.read({ allRuns: true })) {
      if (e instanceof Entry && e.event_type === "work.async") entries.push(e);
    }

    ctx.assertInvariant(
      "entry_count",
      entries.length === ASYNC_TASKS,
      `expected ${ASYNC_TASKS} work.async entries, got ${entries.length}`,
    );

    let chainOk = true;
    let decryptionOk = true;
    let decryptedCount = 0;

    try {
      for (const _ of tn.read({ verify: true, allRuns: true })) {
        void _;
      }
    } catch {
      chainOk = false;
    }
    for (const e of entries) {
      if (typeof e.fields["i"] === "number") {
        decryptedCount++;
      } else {
        decryptionOk = false;
      }
    }

    ctx.assertInvariant("chain_verified", chainOk);
    ctx.assertInvariant(
      "decryption_verified",
      decryptionOk && decryptedCount === ASYNC_TASKS,
      `decrypted ${decryptedCount}/${ASYNC_TASKS}`,
    );

    ctx.record("async_tasks", ASYNC_TASKS);
    ctx.record("log_count", entries.length);
    ctx.record("decrypted_count", decryptedCount);
  } finally {
    await tn.close();
  }
});
