import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { fromWireDict, packTnpkg, readTnpkg, writeTnpkg, type Manifest } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO = resolve(__dirname, "..", "..");
const MANIFEST_FIXTURES = resolve(REPO, "tests", "fixtures", "manifest");

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

test("tnpkg reader accepts manifest and body members", () => {
  const dir = mkdtempSync(join(tmpdir(), "tnpkg-container-"));
  const pkg = join(dir, "ok.tnpkg");
  const manifest = signedProjectSeedManifest();

  writeTnpkg(pkg, manifest, {
    "body/tn.yaml": new TextEncoder().encode("ceremony:\n  id: payroll\n"),
    "body/keys/local.public": new TextEncoder().encode(manifest.fromDid),
  });

  const got = readTnpkg(pkg);

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

test("tnpkg writer rejects invalid body members", () => {
  const dir = mkdtempSync(join(tmpdir(), "tnpkg-container-"));
  const manifest = signedProjectSeedManifest();

  assert.throws(
    () => writeTnpkg(join(dir, "bad.tnpkg"), manifest, { "root.txt": new Uint8Array([1]) }),
    /invalid package member/,
  );
});
