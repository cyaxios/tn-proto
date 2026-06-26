import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { localRead } from "../src/local/read.js";
import { fromText } from "../src/local/file_handle.js";
import { parseKeystore } from "../src/local/keystore.js";
import type { Entry } from "../src/Entry.js";

function makeLine(seq: number, event_type: string): string {
  return JSON.stringify({
    event_type,
    timestamp: "2026-01-01T10:00:00.000Z",
    level: "info",
    device_identity: "did:key:zFoo",
    sequence: seq,
    event_id: `ev${seq}`,
    run_id: "run1",
    prev_hash: "0000",
    row_hash: `h${seq}`,
    signature: `s${seq}`,
  });
}

const LOG = makeLine(1, "app.start") + "\n" + makeLine(2, "app.stop") + "\n";
const EMPTY_KS = parseKeystore(JSON.stringify({ keystores: [] }));

describe("localRead", () => {
  test("yields all entries", async () => {
    const entries: Entry[] = [];
    for await (const e of localRead(fromText(LOG), { keystore: EMPTY_KS })) entries.push(e);
    assert.equal(entries.length, 2);
    assert.equal(entries[0]!.event_type, "app.start");
    assert.equal(entries[1]!.sequence, 2);
  });

  test("where filter", async () => {
    const entries: Entry[] = [];
    for await (const e of localRead(fromText(LOG), {
      keystore: EMPTY_KS,
      where: (e) => e.event_type === "app.stop",
    })) entries.push(e);
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.event_type, "app.stop");
  });

  test("empty file yields nothing", async () => {
    const entries: Entry[] = [];
    for await (const e of localRead(fromText(""), {})) entries.push(e);
    assert.equal(entries.length, 0);
  });

  test("no keystore still yields public fields", async () => {
    const entries: Entry[] = [];
    for await (const e of localRead(fromText(LOG), {})) entries.push(e);
    assert.equal(entries.length, 2);
    assert.equal(entries[0]!.device_identity, "did:key:zFoo");
  });
});
