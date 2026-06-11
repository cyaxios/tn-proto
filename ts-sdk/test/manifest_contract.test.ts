import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  fromWireDict,
  KNOWN_KINDS,
  manifestSigningBytes,
  verifyManifest,
  type Manifest,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO = resolve(__dirname, "..", "..");
const FIXTURES = resolve(REPO, "tests", "fixtures", "manifest");

function readJson(name: string): unknown {
  return JSON.parse(readFileSync(resolve(FIXTURES, name), "utf-8")) as unknown;
}

function readHex(name: string): string {
  return readFileSync(resolve(FIXTURES, name), "utf-8").trim();
}

test("manifest kind catalog matches shared fixture", () => {
  const expected = readJson("kinds.json") as string[];
  assert.deepEqual([...KNOWN_KINDS].sort(), [...expected].sort());
});

test("project_seed manifest fixture canonical bytes", () => {
  const manifest = fromWireDict(readJson("project_seed_unsigned.json")) as Manifest;

  assert.equal(manifest.kind, "project_seed");
  assert.equal(manifest.toDid, manifest.fromDid);
  assert.equal((manifest.state?.["project"] as Record<string, unknown>)["name"], "payroll");

  const got = Buffer.from(manifestSigningBytes(manifest)).toString("hex");
  assert.equal(got, readHex("project_seed_unsigned.canonical.hex"));
});

test("manifest signing bytes strip signature field", () => {
  const doc = readJson("project_seed_unsigned.json") as Record<string, unknown>;
  const unsigned = Buffer.from(manifestSigningBytes(fromWireDict(doc))).toString("hex");

  doc["manifest_signature_b64"] = "not-a-real-signature";
  const signedShape = Buffer.from(manifestSigningBytes(fromWireDict(doc))).toString("hex");

  assert.equal(signedShape, unsigned);
});

test("manifest missing required field is rejected", () => {
  const doc = readJson("project_seed_unsigned.json") as Record<string, unknown>;
  delete doc["publisher_identity"];

  assert.throws(() => fromWireDict(doc), /missing required keys/);
});

test("manifest unknown kind is rejected", () => {
  const doc = readJson("project_seed_unsigned.json") as Record<string, unknown>;
  doc["kind"] = "future_experimental_kind";

  assert.throws(() => fromWireDict(doc), /unknown kind/);
});

test("signed project_seed manifest fixture verifies", () => {
  const manifest = fromWireDict(readJson("project_seed_signed.json")) as Manifest;

  assert.equal(typeof manifest.manifestSignatureB64, "string");
  assert.equal(
    Buffer.from(manifestSigningBytes(manifest)).toString("hex"),
    readHex("project_seed_signed.canonical.hex"),
  );
  assert.doesNotThrow(() => verifyManifest(manifest));
});

test("signed project_seed manifest rejects tampering", () => {
  const doc = readJson("project_seed_signed.json") as Record<string, unknown>;
  doc["event_count"] = 3;

  assert.throws(() => verifyManifest(fromWireDict(doc) as Manifest), /signature does not verify/);
});
