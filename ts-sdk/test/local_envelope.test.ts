import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { extractGroupCts, buildGroupKitsMap } from "../src/local/envelope.js";
import type { KeystoreHandle } from "../src/local/keystore.js";

describe("extractGroupCts", () => {
  test("extracts group ciphertext blocks", () => {
    const envelope = {
      event_type: "test",
      timestamp: "2026-01-01T00:00:00Z",
      my_group: { ciphertext: "AAEC" },
      plain_field: "hello",
    };
    const result = extractGroupCts(envelope);
    assert.deepEqual(Object.keys(result), ["my_group"]);
    assert.ok(result["my_group"]!.ct instanceof Uint8Array);
  });

  test("returns empty object for envelope with no groups", () => {
    assert.deepEqual(Object.keys(extractGroupCts({ event_type: "t", level: "i" })), []);
  });

  test("ignores reserved envelope keys", () => {
    const envelope = {
      timestamp: "...",
      device_identity: "did:key:z...",
      my_group: { ciphertext: "AAEC" },
    };
    assert.deepEqual(Object.keys(extractGroupCts(envelope)), ["my_group"]);
  });
});

describe("buildGroupKitsMap", () => {
  test("maps group name to kits by publisher", () => {
    const fakeKit = new Uint8Array([0xaa, 0xbb]);
    const ks: KeystoreHandle = {
      kitsForPublisher(id) { return id === "abcd" ? [fakeKit] : []; },
    };
    const groupCts = new Map([["my_group", { ct: new Uint8Array([0x01, 0x02]) }]]);
    // inject mock so test doesn't need real WASM — returns 0xab 0xcd = "abcd"
    const mockPub = () => new Uint8Array([0xab, 0xcd]);
    const result = buildGroupKitsMap(groupCts, ks, mockPub);
    assert.deepEqual(result.get("my_group")!.kits, [fakeKit]);
    assert.equal(result.get("my_group")!.cipher, "btn");
  });

  test("returns empty kits when publisher unknown", () => {
    const ks: KeystoreHandle = { kitsForPublisher: () => [] };
    const groupCts = new Map([["g", { ct: new Uint8Array([0x01]) }]]);
    const result = buildGroupKitsMap(groupCts, ks, () => new Uint8Array([0xff]));
    assert.deepEqual(result.get("g")!.kits, []);
  });
});
