// End-to-end write path: the TS runtime seals a `cipher: jwe` group via
// emitAsync (panva/jose is async) and reads it back with readAsync. Uses a
// temp copy of the committed jwe ceremony so the fixture is never mutated.
import { strict as assert } from "node:assert";
import { cpSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { NodeRuntime } from "../src/runtime/node_runtime.js";

const HERE = dirname(fileURLToPath(import.meta.url));

test("emitAsync seals a jwe group and readAsync reads it back", async () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-emit-"));
  cpSync(join(HERE, "fixtures", "jwe_ceremony"), work, { recursive: true });
  const rt = NodeRuntime.init(join(work, "tn.yaml"));

  const receipt = await rt.emitAsync("info", "order.created", { amount: 7777, currency: "GBP" });
  assert.ok(receipt.eventId, "emitAsync returned no receipt");

  const opened: Record<string, unknown>[] = [];
  for await (const e of rt.readAsync()) {
    if (e.envelope["event_type"] !== "order.created") continue;
    const body = e.plaintext["default"];
    assert.ok(body && !("$no_read_key" in body) && !("$decrypt_error" in body), "jwe group did not open");
    assert.equal(e.valid.signature, true);
    assert.equal(e.valid.rowHash, true);
    opened.push(body);
  }
  // the two fixture orders plus the one we just sealed
  const amounts = opened.map((o) => Number(o["amount"]));
  assert.ok(amounts.includes(7777), `emitAsync entry not read back (got ${amounts.join(",")})`);
});

test("emitAsync binds an aad marker that readAsync verifies", async () => {
  const work = mkdtempSync(join(tmpdir(), "jwe-emit-aad-"));
  cpSync(join(HERE, "fixtures", "jwe_ceremony"), work, { recursive: true });
  const rt = NodeRuntime.init(join(work, "tn.yaml"));

  await rt.emitAsync("info", "order.created", { amount: 555 }, { policy: "finra-oba" });
  let sawMarked = false;
  for await (const e of rt.readAsync()) {
    if (e.envelope["event_type"] !== "order.created") continue;
    const body = e.plaintext["default"];
    if (Number((body as Record<string, unknown>)["amount"]) === 555) {
      // opened → the aad reconstructed from the public tn_aad echo verified
      assert.ok(!("$decrypt_error" in body) && !("$no_read_key" in body));
      assert.equal(e.envelope["tn_aad"] !== undefined, true, "tn_aad echo missing");
      sawMarked = true;
    }
  }
  assert.ok(sawMarked, "marked entry not found");
});
