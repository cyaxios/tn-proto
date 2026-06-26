// Parity with Python read.py `_passes_selector_filter`: tn.read accepts a
// positional-equivalent `selector` (exact event_type) and a declarative
// `filter` (event_type_in / event_type_prefix / level_in), applied as the
// authoritative client-side gate. tn.watch shares the same gate.

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { Tn } from "../src/tn.js";

function eventTypes(c: Tn, opts: Parameters<Tn["read"]>[0]): string[] {
  const out: string[] = [];
  for (const e of c.read({ raw: true, ...opts })) {
    const t = (e as Record<string, unknown>)["event_type"];
    if (typeof t === "string") out.push(t);
  }
  return out;
}

test("read selector keeps only the exact event_type", async () => {
  const c = await Tn.ephemeral({ stdout: false });
  try {
    c.info("evt.alpha", { n: 1 });
    c.info("evt.beta", { n: 2 });
    c.info("evt.alpha", { n: 3 });

    const got = eventTypes(c, { selector: "evt.alpha" });
    assert.deepEqual(got, ["evt.alpha", "evt.alpha"]);

    // null/undefined selector reads every event_type.
    assert.equal(eventTypes(c, { selector: null }).length, 3);
    assert.equal(eventTypes(c, {}).length, 3);
  } finally {
    await c.close();
  }
});

test("read filter event_type_in / event_type_prefix", async () => {
  const c = await Tn.ephemeral({ stdout: false });
  try {
    c.info("order.created", { n: 1 });
    c.info("order.shipped", { n: 2 });
    c.info("user.login", { n: 3 });

    assert.deepEqual(eventTypes(c, { filter: { event_type_in: ["order.created", "user.login"] } }), [
      "order.created",
      "user.login",
    ]);
    assert.deepEqual(eventTypes(c, { filter: { event_type_prefix: "order." } }), [
      "order.created",
      "order.shipped",
    ]);
  } finally {
    await c.close();
  }
});

test("read filter level_in gates on the envelope level", async () => {
  const c = await Tn.ephemeral({ stdout: false });
  try {
    c.info("evt.i", { n: 1 });
    c.warning("evt.w", { n: 2 });
    c.error("evt.e", { n: 3 });

    const kept = eventTypes(c, { filter: { level_in: ["warning", "error"] } });
    assert.deepEqual(kept.sort(), ["evt.e", "evt.w"]);
  } finally {
    await c.close();
  }
});

test("selector + filter compose (both must pass)", async () => {
  const c = await Tn.ephemeral({ stdout: false });
  try {
    c.info("order.created", { n: 1 });
    c.warning("order.created", { n: 2 });

    // selector matches both event_types, level_in narrows to the warning.
    const kept = [];
    for (const e of c.read({ raw: true, selector: "order.created", filter: { level_in: ["warning"] } })) {
      kept.push((e as Record<string, unknown>)["level"]);
    }
    assert.deepEqual(kept, ["warning"]);
  } finally {
    await c.close();
  }
});
