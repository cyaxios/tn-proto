// End-to-end: the TS runtime opens a `cipher: jwe` ceremony emitted by the
// Python SDK (checked-in fixture) and decrypts it through `readAsync()`. This
// is the production read path for jwe groups — panva/jose is async, so the
// sync `read()` cannot open them, but `readAsync()` awaits the JOSE decrypt.
import { strict as assert } from "node:assert";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { NodeRuntime } from "../src/runtime/node_runtime.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const YAML = join(HERE, "fixtures", "jwe_ceremony", "tn.yaml");

test("readAsync decrypts a Python-emitted jwe log", async () => {
  const rt = NodeRuntime.init(YAML);
  const orders: Record<string, unknown>[] = [];
  for await (const e of rt.readAsync()) {
    if (e.envelope["event_type"] !== "order.created") continue;
    // jwe group opened: the default group's plaintext is real, not a marker.
    const body = e.plaintext["default"];
    assert.ok(body && !("$no_read_key" in body) && !("$decrypt_error" in body), "jwe group did not open");
    orders.push(body);
    // full pipeline verified alongside decrypt
    assert.equal(e.valid.signature, true, "signature");
    assert.equal(e.valid.rowHash, true, "row_hash");
  }
  assert.equal(orders.length, 2, "expected 2 order.created entries");
  const amounts = orders.map((o) => Number(o["amount"])).sort((a, b) => a - b);
  assert.deepEqual(amounts, [42, 999]);
  const currencies = orders.map((o) => o["currency"]).sort();
  assert.deepEqual(currencies, ["EUR", "USD"]);
});
