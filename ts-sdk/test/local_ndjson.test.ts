import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { parseNdjson } from "../src/local/ndjson.js";

describe("parseNdjson", () => {
  test("parses two complete lines", () => {
    assert.deepEqual(parseNdjson('{"a":1}\n{"b":2}\n'), [{ a: 1 }, { b: 2 }]);
  });

  test("skips blank lines", () => {
    assert.deepEqual(parseNdjson('{"a":1}\n\n{"b":2}'), [{ a: 1 }, { b: 2 }]);
  });

  test("skips malformed lines without throwing", () => {
    assert.deepEqual(parseNdjson('{"a":1}\nnot-json\n{"b":2}'), [{ a: 1 }, { b: 2 }]);
  });

  test("returns empty array for empty string", () => {
    assert.deepEqual(parseNdjson(""), []);
  });

  test("handles file with no trailing newline", () => {
    assert.deepEqual(parseNdjson('{"a":1}\n{"b":2}'), [{ a: 1 }, { b: 2 }]);
  });
});
