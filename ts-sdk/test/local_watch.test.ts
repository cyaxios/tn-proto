import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { localWatch } from "../src/local/watch.js";
import { parseKeystore } from "../src/local/keystore.js";
import type { Entry } from "../src/Entry.js";

const EMPTY_KS = parseKeystore(JSON.stringify({ keystores: [] }));

function makeLine(seq: number): string {
  return JSON.stringify({
    event_type: "test.event",
    timestamp: "2026-01-01T10:00:00.000Z",
    level: "info",
    device_identity: "did:key:zFoo",
    sequence: seq,
    event_id: `ev${seq}`,
    run_id: "run1",
    prev_hash: "0000",
    row_hash: `h${seq}`,
    signature: `s${seq}`,
  }) + "\n";
}

function growable(initial: string) {
  const enc = new TextEncoder();
  let bytes = enc.encode(initial);
  return {
    handle: {
      name: "t.log",
      async text() { return new TextDecoder().decode(bytes); },
      async slice(s: number, e?: number) { return new TextDecoder().decode(bytes.slice(s, e)); },
      async size() { return bytes.length; },
    },
    append(line: string) {
      const extra = enc.encode(line);
      const next = new Uint8Array(bytes.length + extra.length);
      next.set(bytes); next.set(extra, bytes.length);
      bytes = next;
    },
  };
}

describe("localWatch", () => {
  test("since=start yields existing then new entries", async () => {
    const { handle, append } = growable(makeLine(1) + makeLine(2));
    const ac = new AbortController();
    const entries: Entry[] = [];

    // Append AFTER the generator has processed initial entries and captured offset.
    // Synchronous append inside the handler fires before offset = handle.size() runs,
    // causing the watcher to capture a post-append offset and poll forever.
    setTimeout(() => append(makeLine(3)), 80);

    for await (const e of localWatch(handle, {
      keystore: EMPTY_KS, since: "start", pollMs: 10, signal: ac.signal,
    })) {
      entries.push(e);
      if (entries.length === 3) ac.abort();
    }

    assert.equal(entries.length, 3);
    assert.equal(entries[0]!.sequence, 1);
    assert.equal(entries[2]!.sequence, 3);
  });

  test("since=now skips existing, yields only new", async () => {
    const { handle, append } = growable(makeLine(1) + makeLine(2));
    const ac = new AbortController();
    const entries: Entry[] = [];
    const iter = (async () => {
      for await (const e of localWatch(handle, {
        keystore: EMPTY_KS, since: "now", pollMs: 10, signal: ac.signal,
      })) {
        entries.push(e);
        if (entries.length === 1) ac.abort();
      }
    })();
    await new Promise(r => setTimeout(r, 25));
    append(makeLine(3));
    await iter;
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.sequence, 3);
  });
});
