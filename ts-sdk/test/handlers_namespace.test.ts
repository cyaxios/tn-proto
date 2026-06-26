import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Tn } from "../src/tn.js";
import type { TNHandler } from "../src/handlers/index.js";

test("tn.handlers.add registers a handler that sees subsequent emits", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const seen: string[] = [];
  try {
    tn.handlers.add({
      name: "test-collector",
      accepts: () => true,
      emit(env: Record<string, unknown>) {
        seen.push(String(env["event_type"] ?? ""));
      },
      close() {},
    } satisfies TNHandler);
    tn.info("test.event", { ok: 1 });
    await tn.handlers.flush();
    assert.ok(seen.includes("test.event"), `expected test.event in ${JSON.stringify(seen)}`);
  } finally {
    await tn.close();
  }
});

test("tn.handlers.list returns registered handlers", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const before = tn.handlers.list();
    tn.handlers.add({
      name: "noop",
      accepts: () => false,
      emit() {},
      close() {},
    } satisfies TNHandler);
    const after = tn.handlers.list();
    assert.equal(after.length, before.length + 1);
  } finally {
    await tn.close();
  }
});

test("tn.handlers.flush resolves without error when no handler has flush()", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    // Should not throw even if handlers don't expose flush().
    await assert.doesNotReject(() => tn.handlers.flush());
  } finally {
    await tn.close();
  }
});

test("Tn.close({ timeoutMs }) drains async handlers via closeAsync with the timeout (parity with Python flush_and_close timeout)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  let drainedWith: number | "UNSET" = "UNSET";
  let syncCloseCalled = false;
  const fake = {
    name: "drain-probe",
    accepts: () => false,
    emit() {},
    close() {
      syncCloseCalled = true;
    },
    async closeAsync(opts: { timeoutMs?: number }) {
      drainedWith = opts?.timeoutMs ?? -1;
    },
  };
  tn.handlers.add(fake as unknown as TNHandler);
  await tn.close({ timeoutMs: 1234 });
  assert.equal(drainedWith, 1234, "close awaited handler.closeAsync with the timeout");
  assert.equal(syncCloseCalled, false, "bounded async-drain path used, not the sync close()");
});
