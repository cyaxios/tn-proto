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
