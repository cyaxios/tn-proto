/**
 * Stdout pretty format tests — mirrors python/tests/test_stdout_handler.py.
 *
 * Pins that:
 *   - default format is pretty (header + truncated id/did + public fields)
 *   - crypto keys, full DID, ciphertext blocks are suppressed
 *   - TN_STDOUT_FORMAT=json forces canonical NDJSON
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";

import { StdoutHandler } from "../src/handlers/stdout.js";

function captured(): { buf: string[]; sink: (s: string) => void } {
  const buf: string[] = [];
  return { buf, sink: (s: string) => buf.push(s) };
}

test("pretty format prints headers + public fields, hides crypto", () => {
  const orig = process.env.TN_STDOUT_FORMAT;
  delete process.env.TN_STDOUT_FORMAT;
  try {
    const cap = captured();
    const h = new StdoutHandler({ write: cap.sink });
    h.emit(
      {
        did: "did:key:z6MkLongIdentifierStringHere",
        timestamp: "2026-05-05T22:27:23.712506Z",
        event_type: "page_viewed",
        level: "info",
        sequence: 12,
        event_id: "abc123def456",
        row_hash: "sha256:bde8e3deadbeef",
        signature: "UcTuis0SignatureBytesHere",
        default: { ciphertext: "AAAA...", field_hashes: {} },
      },
      "raw line bytes irrelevant in pretty mode\n",
    );

    const text = cap.buf.join("");
    assert.match(text, /22:27:23\.712/);
    assert.match(text, /INFO/);
    assert.match(text, /seq=12/);
    assert.match(text, /page_viewed/);
    assert.match(text, /id=abc123de/); // truncated event_id
    assert.match(text, /did=did:key:z6MkLong/); // truncated DID
    // Crypto suppressed.
    assert.equal(text.includes("sha256:bde8e3"), false);
    assert.equal(text.includes("UcTuis0SignatureBytesHere"), false);
    assert.equal(text.includes("ciphertext"), false);
    // Single line.
    assert.equal(text.endsWith("\n"), true);
    assert.equal((text.match(/\n/g) ?? []).length, 1);
  } finally {
    if (orig !== undefined) process.env.TN_STDOUT_FORMAT = orig;
  }
});

test("pretty format shows public fields as key=value", () => {
  const orig = process.env.TN_STDOUT_FORMAT;
  delete process.env.TN_STDOUT_FORMAT;
  try {
    const cap = captured();
    const h = new StdoutHandler({ write: cap.sink });
    h.emit(
      {
        timestamp: "2026-05-06T10:00:00.000000Z",
        event_type: "order.created",
        level: "info",
        sequence: 5,
        amount: 4999,
        order_id: "A100",
      },
      "irrelevant\n",
    );
    const text = cap.buf.join("");
    assert.match(text, /amount=4999/);
    assert.match(text, /order_id='A100'/);
  } finally {
    if (orig !== undefined) process.env.TN_STDOUT_FORMAT = orig;
  }
});

test("TN_STDOUT_FORMAT=json forces canonical NDJSON", () => {
  process.env.TN_STDOUT_FORMAT = "json";
  try {
    const cap = captured();
    const h = new StdoutHandler({ write: cap.sink });
    const raw = '{"event_type":"x","sequence":1}\n';
    h.emit({ event_type: "x", sequence: 1 }, raw);
    assert.equal(cap.buf.join(""), raw);
  } finally {
    delete process.env.TN_STDOUT_FORMAT;
  }
});

test("severity-less log renders as LOG", () => {
  const orig = process.env.TN_STDOUT_FORMAT;
  delete process.env.TN_STDOUT_FORMAT;
  try {
    const cap = captured();
    const h = new StdoutHandler({ write: cap.sink });
    h.emit(
      {
        timestamp: "2026-05-06T10:00:00.000Z",
        event_type: "evt",
        level: "",
        sequence: 1,
      },
      "irrelevant\n",
    );
    const text = cap.buf.join("");
    assert.match(text, /LOG/);
  } finally {
    if (orig !== undefined) process.env.TN_STDOUT_FORMAT = orig;
  }
});
