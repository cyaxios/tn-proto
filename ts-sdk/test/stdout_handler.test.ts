// Tests for `StdoutHandler` and the `TNClient.init({stdout})` default.
//
// Mirrors `python/tests/test_stdout_handler.py` and the Rust handler's
// behavior: emit a JSON line per envelope, opt-out via `TN_NO_STDOUT=1`
// env var or `{stdout: false}` kwarg.

import { strict as assert } from "node:assert";
import { test } from "node:test";

// Import StdoutHandler directly so the unit tests don't require the
// `tn-wasm` package (which gates TNClient via raw.ts). Integration tests
// for `TNClient.init({stdout})` live in test/client.test.ts and run after
// the wasm package is built.
import { StdoutHandler } from "../src/handlers/stdout.js";

// ----------------------------------------------------------------------
// Unit tests against the handler in isolation.
// ----------------------------------------------------------------------

test("StdoutHandler writes the raw line to its sink", () => {
  const captured: string[] = [];
  const h = new StdoutHandler({ write: (s) => captured.push(s) });
  h.emit({ event_type: "test.evt" }, '{"event_type":"test.evt"}\n');
  assert.deepEqual(captured, ['{"event_type":"test.evt"}\n']);
});

test("StdoutHandler appends newline if missing", () => {
  const captured: string[] = [];
  const h = new StdoutHandler({ write: (s) => captured.push(s) });
  h.emit({ event_type: "a" }, '{"event_type":"a"}');
  h.emit({ event_type: "b" }, '{"event_type":"b"}');
  const total = captured.join("");
  assert.equal(total.split("\n").filter((s) => s.length > 0).length, 2);
});

test("StdoutHandler honors filter spec", () => {
  const captured: string[] = [];
  const h = new StdoutHandler({
    write: (s) => captured.push(s),
    filter: { eventTypePrefix: "kept." },
  });
  if (h.accepts({ event_type: "kept.a" })) {
    h.emit({ event_type: "kept.a" }, '{"event_type":"kept.a"}\n');
  }
  if (h.accepts({ event_type: "dropped.b" })) {
    h.emit({ event_type: "dropped.b" }, '{"event_type":"dropped.b"}\n');
  }
  const all = captured.join("");
  assert.match(all, /kept\.a/);
  assert.equal(all.includes("dropped.b"), false);
});

// Integration tests (`TNClient.init({stdout})`) live in test/client.test.ts
// where the TNClient import chain (which transitively requires `tn-wasm`)
// is already in scope.
