import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  DeviceKey,
  fromWireDict,
  packTnpkg,
  readTnpkg,
  readTnpkgVerified,
  signManifestWithBody,
  toWireDict,
  writeTnpkg,
  type BodyContents,
  type Manifest,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO = resolve(__dirname, "..", "..");
const MANIFEST_FIXTURES = resolve(REPO, "tests", "fixtures", "manifest");
const BODY_INDEX_FIXTURE = resolve(
  REPO,
  "tests",
  "fixtures",
  "trust",
  "v1",
  "package_body_index.json",
);

function signedProjectSeedManifest(): Manifest {
  const doc = JSON.parse(
    readFileSync(resolve(MANIFEST_FIXTURES, "project_seed_signed.json"), "utf-8"),
  );
  return fromWireDict(doc) as Manifest;
}

function manifestEntry(): Uint8Array {
  const raw = readFileSync(resolve(MANIFEST_FIXTURES, "project_seed_signed.json"), "utf-8");
  return new TextEncoder().encode(raw);
}

interface BodyIndexCase {
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

function bodyIndexPackage(caseId: string): {
  bytes: Uint8Array;
  body: BodyContents;
} {
  const fixtureCase = bodyIndexCase(caseId);
  const body = Object.fromEntries(
    Object.entries(fixtureCase.input.body_members_b64).map(([name, encoded]) => [
      name,
      new Uint8Array(Buffer.from(encoded, "base64")),
    ]),
  );
  const entries = [
    {
      name: "manifest.json",
      data: new Uint8Array(Buffer.from(fixtureCase.input.manifest_b64, "base64")),
    },
    ...Object.entries(body).map(([name, data]) => ({ name, data })),
  ];
  return { bytes: packTnpkg(entries), body };
}

function bodySignedProjectSeedManifest(body: BodyContents): Manifest {
  const device = DeviceKey.fromSeed(new Uint8Array(32).fill(29));
  const manifest: Manifest = {
    kind: "project_seed",
    version: 1,
    fromDid: device.did,
    toDid: device.did,
    ceremonyId: "payroll",
    asOf: "2026-07-11T14:00:00Z",
    scope: "admin",
    clock: {},
    eventCount: 0,
  };
  return signManifestWithBody(manifest, body, device);
}

test("tnpkg reader accepts manifest and body members", () => {
  const dir = mkdtempSync(join(tmpdir(), "tnpkg-container-"));
  const pkg = join(dir, "ok.tnpkg");
  const body = {
    "body/tn.yaml": new TextEncoder().encode("ceremony:\n  id: payroll\n"),
    "body/keys/local.public": new TextEncoder().encode("did:key:zBodyIndexedPublisher"),
  };
  const manifest = bodySignedProjectSeedManifest(body);

  writeTnpkg(pkg, manifest, body);

  const got = readTnpkgVerified(pkg);

  assert.equal(got.manifest.kind, "project_seed");
  assert.deepEqual([...got.body.keys()].sort(), ["body/keys/local.public", "body/tn.yaml"]);
});

for (const badName of [
  "README.txt",
  "keys/local.private",
  "body/",
  "body/../manifest.json",
  "body\\keys\\local.private",
]) {
  test(`tnpkg reader rejects invalid member ${JSON.stringify(badName)}`, () => {
    const bytes = packTnpkg([
      { name: "manifest.json", data: manifestEntry() },
      { name: badName, data: new TextEncoder().encode("bad") },
    ]);

    assert.throws(() => readTnpkg(bytes), /invalid package member/);
  });
}

test("tnpkg reader rejects duplicate manifest entries", () => {
  const manifest = manifestEntry();
  const bytes = packTnpkg([
    { name: "manifest.json", data: manifest },
    { name: "manifest.json", data: manifest },
    { name: "body/tn.yaml", data: new TextEncoder().encode("ceremony:\n  id: payroll\n") },
  ]);

  assert.throws(() => readTnpkg(bytes), /exactly one/);
});

test("verified reader rejects duplicate body entries before map collapse", () => {
  const data = new TextEncoder().encode("same named member");
  const body = { "body/payload.bin": data };
  const manifest = bodySignedProjectSeedManifest(body);
  const manifestBytes = new TextEncoder().encode(JSON.stringify(toWireDict(manifest, true)));
  const bytes = packTnpkg([
    { name: "manifest.json", data: manifestBytes },
    { name: "body/payload.bin", data },
    { name: "body/payload.bin", data },
  ]);

  assert.throws(() => readTnpkgVerified(bytes), /duplicate package member/);
});

test("tnpkg writer rejects invalid body members", () => {
  const dir = mkdtempSync(join(tmpdir(), "tnpkg-container-"));
  const manifest = signedProjectSeedManifest();

  assert.throws(
    () => writeTnpkg(join(dir, "bad.tnpkg"), manifest, { "root.txt": new Uint8Array([1]) }),
    /invalid package member/,
  );
});

test("verified reader accepts shared body-index fixture", () => {
  const { bytes, body } = bodyIndexPackage("valid_offer_body_index");

  const got = readTnpkgVerified(bytes);

  assert.equal(got.manifest.kind, "offer");
  assert.deepEqual(Object.fromEntries(got.body), body);
});

for (const [label, malformed] of [
  ["null", null],
  ["array", []],
  ["string", "sha256:not-an-index"],
] as const) {
  test(`verified reader rejects ${label} body_sha256 before body dispatch`, () => {
    const fixtureCase = bodyIndexCase("valid_offer_body_index");
    const manifestDoc = JSON.parse(
      Buffer.from(fixtureCase.input.manifest_b64, "base64").toString("utf-8"),
    ) as Record<string, unknown>;
    manifestDoc["body_sha256"] = malformed;
    const entries = [
      {
        name: "manifest.json",
        data: new TextEncoder().encode(JSON.stringify(manifestDoc)),
      },
      ...Object.entries(fixtureCase.input.body_members_b64).map(([name, encoded]) => ({
        name,
        data: new Uint8Array(Buffer.from(encoded, "base64")),
      })),
    ];
    const bytes = packTnpkg(entries);
    const corruptTarget = new Uint8Array(
      Buffer.from(fixtureCase.input.body_members_b64["body/package.json"]!, "base64"),
    );
    const offset = Buffer.from(bytes).indexOf(Buffer.from(corruptTarget.subarray(0, 16)));
    assert.notEqual(offset, -1, "stored body prefix not found");
    bytes[offset] ^= 0xff;
    const dispatched: string[] = [];

    const dispatchAfterVerification = (): void => {
      const got = readTnpkgVerified(bytes);
      dispatched.push(...got.body.keys());
    };

    assert.throws(dispatchAfterVerification, (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      assert.match(message, /body_sha256 must be a JSON object/);
      assert.doesNotMatch(message, /CRC|body_digest_mismatch/);
      return true;
    });
    assert.deepEqual(dispatched, []);
  });
}

for (const caseId of [
  "substituted_offer_body",
  "missing_indexed_body",
  "extra_unindexed_body",
  "malformed_body_digest",
  "missing_body_index",
]) {
  test(`verified reader rejects shared body-index mismatch ${caseId}`, () => {
    const { bytes } = bodyIndexPackage(caseId);

    assert.throws(() => readTnpkgVerified(bytes), /body_digest_mismatch/);
  });
}

test("verified reader checks manifest signature before corrupt body bytes", () => {
  const { bytes, body } = bodyIndexPackage("manifest_signature_mutated");
  const prefix = body["body/package.json"]!.subarray(0, 16);
  const offset = Buffer.from(bytes).indexOf(Buffer.from(prefix));
  assert.notEqual(offset, -1, "stored body prefix not found");
  bytes[offset] ^= 0xff;

  assert.throws(
    () => readTnpkgVerified(bytes),
    (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      assert.match(message, /signature/i);
      assert.doesNotMatch(message, /CRC/i);
      return true;
    },
  );
});

test("verified reader checks body index before body reaches kind parser", () => {
  const { bytes } = bodyIndexPackage("substituted_offer_body");
  const parsedOrApplied: string[] = [];

  const parseOfferAfterVerification = (): void => {
    const got = readTnpkgVerified(bytes);
    const parsed = JSON.parse(
      new TextDecoder().decode(got.body.get("body/package.json")),
    ) as Record<string, unknown>;
    parsedOrApplied.push(String(parsed["package_kind"]));
  };

  assert.throws(parseOfferAfterVerification, /body_digest_mismatch/);
  assert.deepEqual(parsedOrApplied, []);
});

test("low-level reader preserves named legacy unverified inspection boundary", () => {
  const bytes = packTnpkg([
    { name: "manifest.json", data: manifestEntry() },
    { name: "body/tn.yaml", data: new TextEncoder().encode("ceremony:\n  id: payroll\n") },
  ]);

  const got = readTnpkg(bytes);

  assert.equal(got.manifest.kind, "project_seed");
  assert.equal(
    new TextDecoder().decode(got.body.get("body/tn.yaml")),
    "ceremony:\n  id: payroll\n",
  );
});

test("tnpkg writer rejects a signed manifest for different body bytes", () => {
  const dir = mkdtempSync(join(tmpdir(), "tnpkg-container-"));
  const body = { "body/payload.bin": new TextEncoder().encode("final bytes") };
  const manifest = bodySignedProjectSeedManifest(body);

  assert.throws(
    () =>
      writeTnpkg(join(dir, "substituted-at-write.tnpkg"), manifest, {
        "body/payload.bin": new TextEncoder().encode("different bytes"),
      }),
    /body_digest_mismatch/,
  );
});
