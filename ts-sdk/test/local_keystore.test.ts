import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { parseKeystore } from "../src/local/keystore.js";

// AAEC in base64 decodes to [0, 1, 2]
const VALID_KS = JSON.stringify({
  keystores: [{ publisher_id: "deadbeef", kits: ["AAEC"] }],
});

describe("parseKeystore", () => {
  test("parses a valid keystore JSON", () => {
    assert.ok(parseKeystore(VALID_KS));
  });

  test("kitsForPublisher returns decoded Uint8Array kits", () => {
    const kits = parseKeystore(VALID_KS).kitsForPublisher("deadbeef");
    assert.equal(kits.length, 1);
    assert.ok(kits[0] instanceof Uint8Array);
    assert.deepEqual(Array.from(kits[0]!), [0, 1, 2]);
  });

  test("kitsForPublisher returns empty for unknown publisher", () => {
    assert.deepEqual(parseKeystore(VALID_KS).kitsForPublisher("unknown"), []);
  });

  test("throws on invalid JSON", () => {
    assert.throws(() => parseKeystore("not-json"), /invalid/i);
  });

  test("throws if keystores field is missing", () => {
    assert.throws(() => parseKeystore("{}"), /keystores/i);
  });
});
