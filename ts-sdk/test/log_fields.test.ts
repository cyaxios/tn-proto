// Unit tests for `normalizeLogFields` — the helper backing the
// positional-`message` ergonomic on `TNClient.log/info/warning/error/debug`.
//
// Lives in its own file (and tests the helper directly) so the shape
// transformation is verifiable without standing up a TNClient ceremony
// (which transitively requires `tn-wasm`). End-to-end coverage of the
// same shapes via a real client lives in test/client.test.ts.
//
// Mirrors the kwargs splice in python/tn/_logger.py and Rust's
// equivalent (see crypto/tn-core).

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { normalizeLogFields } from "../src/_log_fields.js";

test("normalizeLogFields: undefined → {}", () => {
  assert.deepEqual(normalizeLogFields(undefined, undefined), {});
});

test("normalizeLogFields: bare string → {message: <str>}", () => {
  assert.deepEqual(normalizeLogFields("name = hi", undefined), {
    message: "name = hi",
  });
});

test("normalizeLogFields: string + fields → message merged with kwargs", () => {
  assert.deepEqual(
    normalizeLogFields("starting", { port: 8080, host: "0.0.0.0" }),
    { message: "starting", port: 8080, host: "0.0.0.0" },
  );
});

test("normalizeLogFields: object only → returned as-is (no message injected)", () => {
  assert.deepEqual(normalizeLogFields({ port: 8080 }, undefined), {
    port: 8080,
  });
});

test("normalizeLogFields: explicit `message` kwarg wins over positional string", () => {
  // Per Python parity: caller-supplied `message` in the fields dict
  // overrides the positional string. Practical reading: the kwargs
  // dict is the last write into the merged record.
  assert.deepEqual(
    normalizeLogFields("positional", { message: "explicit", port: 1 }),
    { message: "explicit", port: 1 },
  );
});

test("normalizeLogFields: empty string is preserved as message=''", () => {
  // A bare empty string is still a positional message — the user
  // explicitly asked for `message: ""`. The form `(undefined, undefined)`
  // is the "no fields" case, not the empty-string case.
  assert.deepEqual(normalizeLogFields("", undefined), { message: "" });
});
