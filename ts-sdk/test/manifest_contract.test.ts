import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  computeBodySha256,
  fromWireDict,
  KNOWN_KINDS,
  manifestSigningBytes,
  signManifestWithBody,
  verifyManifestBodyIndex,
  verifyManifest,
  type BodyContents,
  type Manifest,
  DeviceKey,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO = resolve(__dirname, "..", "..");
const FIXTURES = resolve(REPO, "tests", "fixtures", "manifest");
const BODY_INDEX_FIXTURE = resolve(
  REPO,
  "tests",
  "fixtures",
  "trust",
  "v1",
  "package_body_index.json",
);

const EXPECTED_BODY_SHA256 = {
  "body/metadata.json": "sha256:c94350b6169c800eb2fab2666d1caaf7c07b81227da9a49942ce307f187ced99",
  "body/package.json": "sha256:ccae14e62acb7dcab2e5ad0491d3b40d7fb577b5fedec86543b6c2eeb8e95249",
};

function readJson(name: string): unknown {
  return JSON.parse(readFileSync(resolve(FIXTURES, name), "utf-8")) as unknown;
}

function readHex(name: string): string {
  return readFileSync(resolve(FIXTURES, name), "utf-8").trim();
}

interface BodyIndexCase {
  canonical_b64: string;
  id: string;
  input: {
    body_members_b64: Record<string, string>;
    manifest_b64: string;
  };
}

function bodyIndexCase(caseId: string): BodyIndexCase {
  const fixture = JSON.parse(readFileSync(BODY_INDEX_FIXTURE, "utf-8")) as {
    cases: BodyIndexCase[];
  };
  const found = fixture.cases.find((entry) => entry.id === caseId);
  assert.ok(found, `missing fixture case ${caseId}`);
  return found;
}

function decodeBodyIndexCase(caseId: string): {
  manifest: Manifest;
  body: BodyContents;
  canonical: Uint8Array;
} {
  const fixtureCase = bodyIndexCase(caseId);
  const manifest = fromWireDict(
    JSON.parse(Buffer.from(fixtureCase.input.manifest_b64, "base64").toString("utf-8")),
  );
  const body = Object.fromEntries(
    Object.entries(fixtureCase.input.body_members_b64).map(([name, encoded]) => [
      name,
      new Uint8Array(Buffer.from(encoded, "base64")),
    ]),
  );
  return {
    manifest,
    body,
    canonical: new Uint8Array(Buffer.from(fixtureCase.canonical_b64, "base64")),
  };
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

for (const [label, malformed] of [
  ["null", null],
  ["array", []],
  ["string", "sha256:not-an-index"],
] as const) {
  test(`manifest rejects ${label} body_sha256 shape`, () => {
    const doc = readJson("project_seed_unsigned.json") as Record<string, unknown>;
    doc["body_sha256"] = malformed;

    assert.throws(() => fromWireDict(doc), /body_sha256 must be a JSON object/);
  });
}

test("signed project_seed manifest fixture verifies", () => {
  const manifest = fromWireDict(readJson("project_seed_signed.json")) as Manifest;

  assert.equal(typeof manifest.manifestSignatureB64, "string");
  assert.equal(
    Buffer.from(manifestSigningBytes(manifest)).toString("hex"),
    readHex("project_seed_signed.canonical.hex"),
  );
  assert.doesNotThrow(() => verifyManifest(manifest));
});

test("manifest signature requires canonical standard padded base64", () => {
  const manifest = fromWireDict(readJson("project_seed_signed.json")) as Manifest;
  const canonical = manifest.manifestSignatureB64!;
  manifest.manifestSignatureB64 = canonical
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  assert.notEqual(manifest.manifestSignatureB64, canonical);
  assert.throws(() => verifyManifest(manifest), /signature does not verify/);
});

test("signed project_seed manifest rejects tampering", () => {
  const doc = readJson("project_seed_signed.json") as Record<string, unknown>;
  doc["event_count"] = 3;

  assert.throws(() => verifyManifest(fromWireDict(doc) as Manifest), /signature does not verify/);
});

test("offer body-index fixture pins exact digests, signing bytes, and signature", () => {
  const { manifest, body, canonical } = decodeBodyIndexCase("valid_offer_body_index");

  assert.deepEqual(manifest.bodySha256, EXPECTED_BODY_SHA256);
  assert.deepEqual(computeBodySha256(body), EXPECTED_BODY_SHA256);
  assert.deepEqual(manifestSigningBytes(manifest), canonical);
  assert.doesNotThrow(() => verifyManifest(manifest));
  assert.doesNotThrow(() => verifyManifestBodyIndex(manifest, body, true));
});

for (const caseId of [
  "substituted_offer_body",
  "missing_indexed_body",
  "extra_unindexed_body",
  "malformed_body_digest",
  "missing_body_index",
]) {
  test(`offer body-index fixture rejects ${caseId}`, () => {
    const { manifest, body, canonical } = decodeBodyIndexCase(caseId);

    assert.deepEqual(manifestSigningBytes(manifest), canonical);
    assert.doesNotThrow(() => verifyManifest(manifest));
    assert.throws(() => verifyManifestBodyIndex(manifest, body, true), /body_digest_mismatch/);
  });
}

test("signManifestWithBody indexes final bytes before signing", () => {
  const device = DeviceKey.fromSeed(new Uint8Array(32).fill(31));
  const body = {
    "body/a.bin": new TextEncoder().encode("final stored bytes\0"),
    "body/nested/b.json": new TextEncoder().encode('{"ok":true}\n'),
  };
  const manifest: Manifest = {
    kind: "offer",
    version: 1,
    fromDid: device.did,
    ceremonyId: "body-index-builder",
    asOf: "2026-07-11T14:00:00Z",
    scope: "default",
    clock: {},
    eventCount: 0,
  };

  const signed = signManifestWithBody(manifest, body, device);

  assert.equal(signed, manifest);
  assert.deepEqual(signed.bodySha256, computeBodySha256(body));
  assert.doesNotThrow(() => verifyManifest(signed));
});
