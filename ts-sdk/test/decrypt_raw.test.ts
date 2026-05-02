import { test } from "node:test";
import { strict as assert } from "node:assert";
import { decryptGroupRaw, decryptGroup } from "../src/core/decrypt.js";

test("decryptGroupRaw returns $no_read_key when no kits", () => {
  const result = decryptGroupRaw(
    { ct: new Uint8Array([1, 2, 3]) },
    { cipher: "btn", kits: [] },
  );
  assert.deepEqual(result, { $no_read_key: true });
});

test("decryptGroup and decryptGroupRaw share marker shapes on failure", () => {
  const cipher = { ct: new Uint8Array([1, 2, 3]) };
  const kits = { cipher: "btn" as const, kits: [] };
  assert.deepEqual(decryptGroup(cipher, kits), decryptGroupRaw(cipher, kits));
});
