import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { decryptBodyBlob, packBodyPlaintextZip } from "../src/index.js";
import { unzipSync } from "fflate";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO = resolve(__dirname, "..", "..");
const FIXTURES = resolve(REPO, "tests", "fixtures", "body_encryption");

function readJson(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(FIXTURES, name), "utf-8")) as Record<string, unknown>;
}

function readHex(name: string): Uint8Array {
  return new Uint8Array(Buffer.from(readFileSync(resolve(FIXTURES, name), "utf-8").trim(), "hex"));
}

test("packBodyPlaintextZip is a standard STORED zip", () => {
  const fixture = readJson("vector.json");
  const bodyUtf8 = fixture["body_utf8"] as Record<string, string>;
  const body: Record<string, Uint8Array> = {};
  for (const [name, value] of Object.entries(bodyUtf8)) {
    body[name] = new TextEncoder().encode(value);
  }

  const plaintext = packBodyPlaintextZip(body);
  const recovered = unzipSync(plaintext);
  assert.deepEqual(Object.keys(recovered).sort(), Object.keys(body).sort());
  for (const [name, data] of Object.entries(body)) {
    assert.deepEqual(recovered[name], data);
  }
});

test("decryptBodyBlob matches shared fixture", async () => {
  const fixture = readJson("vector.json");
  const key = new Uint8Array(Buffer.from(fixture["key_hex"] as string, "hex"));
  const blob = readHex("sealed_blob.hex");

  const recovered = await decryptBodyBlob(blob, key);
  const recoveredUtf8: Record<string, string> = {};
  for (const [name, value] of recovered) {
    recoveredUtf8[name] = new TextDecoder().decode(value);
  }

  assert.deepEqual(recoveredUtf8, fixture["body_utf8"]);
});
