// Tests for the identity_seed and project_seed manifest kinds in the
// TS SDK — Bug 1 + Bug 2 + Bug 3 from the 0.4.0a2 brief.
//
// Coverage:
//
// * project_seed real-fixture round-trip (Agentic20.project.tnpkg minted
//   by the dashboard) — every body/keys/* file lands in <keystore>/<rel>.
// * project_seed hand-built round-trip via NodeRuntime.absorbPkg.
// * identity_seed round-trip via NodeRuntime.absorbPkg (mirror of
//   Python tn.export_identity_seed → absorb).
// * Bug 3 dirt-easy bootstrap: Tn.absorb(file) on a fresh dir installs
//   tn.yaml + keystore so a follow-up Tn.init() picks them up.
// * Bug 3 init+absorb: Tn.init creates fresh ceremony, then absorb of a
//   different identity succeeds (zero user events emitted yet);
//   re-absorbing after a real user emit is rejected.
// * Tamper guard: mutating body/keys/local.private without re-signing
//   the manifest is rejected.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { test } from "node:test";

import {
  DeviceKey,
  newManifest,
  packTnpkg,
  parseTnpkg,
  readTnpkg,
  signManifestWithBody,
  writeTnpkg,
} from "../src/index.js";
import { Tn } from "../src/tn.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";

const FIXTURE = pathResolve(
  dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")),
  "fixtures",
  "Agentic20.project.tnpkg",
);

function mkTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function buildProjectSeedTnpkg(outPath: string, device: DeviceKey): string {
  const yamlText =
    `ceremony:\n  id: synthetic_proj\n  cipher: btn\n` +
    `device:\n  device_identity: ${device.did}\n` +
    `groups:\n  default:\n    cipher: btn\n    recipients:\n      - recipient_identity: ${device.did}\n` +
    `keystore:\n  path: ./.tn/tn/keys\n`;
  const body: Record<string, Uint8Array> = {
    "body/tn.yaml": new TextEncoder().encode(yamlText),
    "body/keys/local.private": new Uint8Array(device.seed),
    "body/keys/local.public": new TextEncoder().encode(device.did),
    "body/keys/index_master.key": new Uint8Array(32),
    "body/keys/default.btn.state": new TextEncoder().encode("FAKE_BTN_STATE_DEFAULT"),
    "body/keys/default.btn.mykit": new TextEncoder().encode("FAKE_BTN_MYKIT_DEFAULT"),
    "body/keys/tn.agents.btn.state": new TextEncoder().encode("FAKE_BTN_STATE_TNAGENTS"),
    "body/keys/tn.agents.btn.mykit": new TextEncoder().encode("FAKE_BTN_MYKIT_TNAGENTS"),
  };
  const manifest = newManifest({
    kind: "project_seed",
    fromDid: device.did,
    ceremonyId: "synthetic_proj",
    scope: "project",
    toDid: device.did,
  });
  manifest.state = {
    project: {
      schema: "tn-project-seed-v1",
      project_id: "synthetic_proj",
      ceremony_id: "synthetic_proj",
    },
  };
  signManifestWithBody(manifest, body, device);
  return writeTnpkg(outPath, manifest, body);
}

// DeviceKey doesn't publicly expose its seed, but tests need to
// produce body/keys/local.private. Generate a known seed up front and
// rebuild the device from it.
function deviceWithKnownSeed(): { device: DeviceKey; seed: Uint8Array } {
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 31 + 7) & 0xff;
  return { device: DeviceKey.fromSeed(seed), seed };
}

function buildIdentitySeedTnpkg(outPath: string, device: DeviceKey, seed: Uint8Array): string {
  const yamlText = `# identity_seed stub\nidentity:\n  did: ${device.did}\n`;
  const body: Record<string, Uint8Array> = {
    "body/local.private": new Uint8Array(seed),
    "body/local.public": new TextEncoder().encode(device.did),
    "body/tn.yaml": new TextEncoder().encode(yamlText),
  };
  const manifest = newManifest({
    kind: "identity_seed",
    fromDid: device.did,
    ceremonyId: "_identity_seed",
    scope: "identity",
    toDid: device.did,
  });
  manifest.state = {
    identity: {
      schema: "tn-identity-seed-v1",
      nickname: null,
    },
  };
  signManifestWithBody(manifest, body, device);
  return writeTnpkg(outPath, manifest, body);
}

// ---------------------------------------------------------------------
// project_seed
// ---------------------------------------------------------------------

test("legacy project_seed fixture without body index fails closed", async () => {
  if (!existsSync(FIXTURE)) {
    // Real dashboard-minted fixture not checked in for this run.
    return;
  }
  const { manifest } = readTnpkg(FIXTURE);
  assert.equal(
    manifest.bodySha256,
    undefined,
    "legacy fixture must remain intentionally unindexed",
  );
  const dir = mkTempDir("tn-bootstrap-real-");
  try {
    await assert.rejects(() => Tn.absorb(FIXTURE, { cwd: dir }), /body_digest_mismatch/);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("project_seed hand-built bundle round-trips via absorbBootstrap", async () => {
  const { device, seed } = deviceWithKnownSeed();
  const dir = mkTempDir("tn-bootstrap-hand-");
  try {
    const pkgPath = join(dir, "synth.project.tnpkg");
    // We have to inject the seed manually since DeviceKey doesn't
    // expose it.
    buildProjectSeedTnpkg(pkgPath, device);

    const work = join(dir, "fresh");
    mkdirSync(work, { recursive: true });
    // Hand-built bundles ship synthetic ``FAKE_BTN_STATE_*`` bytes that
    // don't load as a real btn publisher. Use the ``absorbBootstrap``
    // file-only path for these — ``Tn.absorb`` runs an implicit init
    // that requires a loadable keystore.
    const { absorbBootstrap } = await import("../src/runtime/absorb_bootstrap.js");
    const receipt = absorbBootstrap(pkgPath, { cwd: work });
    assert.equal(receipt.kind, "project_seed");
    assert.equal(receipt.rejectedReason, undefined);
    assert.ok(receipt.acceptedCount >= 8); // yaml + 7 key files

    assert.ok(existsSync(join(work, "tn.yaml")));
    assert.ok(existsSync(join(work, ".tn/tn/keys/local.private")));
    assert.ok(existsSync(join(work, ".tn/tn/keys/default.btn.state")));
    assert.deepEqual(
      Buffer.from(readFileSync(join(work, ".tn/tn/keys/local.private"))),
      Buffer.from(seed),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("project_seed hand-built bundle is idempotent on re-absorb", async () => {
  const { device } = deviceWithKnownSeed();
  const dir = mkTempDir("tn-bootstrap-idem-");
  try {
    const pkgPath = join(dir, "synth.project.tnpkg");
    buildProjectSeedTnpkg(pkgPath, device);

    const work = join(dir, "fresh");
    mkdirSync(work, { recursive: true });
    const { absorbBootstrap } = await import("../src/runtime/absorb_bootstrap.js");
    const r1 = absorbBootstrap(pkgPath, { cwd: work });
    assert.ok(r1.acceptedCount > 0);

    const r2 = absorbBootstrap(pkgPath, { cwd: work });
    assert.equal(r2.acceptedCount, 0);
    assert.equal(r2.dedupedCount, r1.acceptedCount);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("project_seed rejects swapped local.private (tamper guard)", async () => {
  const { device } = deviceWithKnownSeed();
  const otherSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) otherSeed[i] = (i * 11 + 3) & 0xff;
  const dir = mkTempDir("tn-bootstrap-tamper-");
  try {
    const pkgPath = join(dir, "tamper.project.tnpkg");
    buildProjectSeedTnpkg(pkgPath, device);

    // Re-write the zip with a swapped local.private.
    const entries = parseTnpkg(new Uint8Array(readFileSync(pkgPath)));
    const tampered = packTnpkg(
      entries.map((entry) =>
        entry.name === "body/keys/local.private" ? { name: entry.name, data: otherSeed } : entry,
      ),
    );
    writeFileSync(pkgPath, tampered);

    const work = join(dir, "fresh");
    mkdirSync(work, { recursive: true });
    await assert.rejects(() => Tn.absorb(pkgPath, { cwd: work }), /body_digest_mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------
// identity_seed
// ---------------------------------------------------------------------

test("identity_seed bootstrap absorb in a fresh dir", async () => {
  const { device, seed } = deviceWithKnownSeed();
  const dir = mkTempDir("tn-id-seed-");
  try {
    const pkgPath = join(dir, "id.tnpkg");
    buildIdentitySeedTnpkg(pkgPath, device, seed);

    const work = join(dir, "fresh");
    mkdirSync(work, { recursive: true });
    const tn = await Tn.absorb(pkgPath, { cwd: work });
    const receipt = tn.lastAbsorbReceipt!;
    assert.equal(receipt.kind, "identity_seed");
    assert.equal(receipt.rejectedReason, undefined);
    assert.equal(receipt.acceptedCount, 1);
    assert.ok(existsSync(join(work, "tn.yaml")));
    assert.ok(existsSync(join(work, ".tn/tn/keys/local.private")));
    // After implicit-init promotes the stub yaml to a real ceremony,
    // the keystore's local.private holds the absorbed seed (the
    // identity is preserved across the stub-to-real transition).
    assert.deepEqual(
      Buffer.from(readFileSync(join(work, ".tn/tn/keys/local.private"))),
      Buffer.from(seed),
    );
    // The runtime is bound — emit + read should work end-to-end.
    assert.equal(tn.did, device.did);
    tn.info("hello.world");
    await tn.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("identity_seed dispatch via NodeRuntime.absorbPkg installs into existing keystore", async () => {
  // Stand up a Tn instance with its own ceremony, then absorb a
  // different identity_seed. With zero user events the absorb
  // succeeds (Bug 3 fresh-init logic).
  const dir = mkTempDir("tn-id-overwrite-");
  try {
    const yamlPath = join(dir, "tn.yaml");
    const tn = await Tn.init(yamlPath);
    const beforeKey = tn.did;

    const { device: other, seed: otherSeed } = deviceWithKnownSeed();
    assert.notEqual(other.did, beforeKey);

    const pkgPath = join(dir, "other.id.tnpkg");
    buildIdentitySeedTnpkg(pkgPath, other, otherSeed);

    const receipt = await tn.pkg.absorb(pkgPath);
    assert.equal(receipt.rejectedReason, undefined, `got: ${receipt.rejectedReason}`);
    assert.equal(receipt.acceptedCount, 1);
    await tn.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("identity_seed dispatch refuses overwrite once user events exist", async () => {
  const dir = mkTempDir("tn-id-refuse-");
  try {
    const yamlPath = join(dir, "tn.yaml");
    const tn = await Tn.init(yamlPath);
    tn.info("hello.user", { marker: "real" });
    await tn.close();

    // Fresh instance reading the populated log.
    const tn2 = await Tn.init(yamlPath);

    const { device: other, seed: otherSeed } = deviceWithKnownSeed();
    const pkgPath = join(dir, "other.id.tnpkg");
    buildIdentitySeedTnpkg(pkgPath, other, otherSeed);

    const receipt = await tn2.pkg.absorb(pkgPath);
    assert.ok(receipt.rejectedReason, "expected rejection after user emit");
    assert.match(receipt.rejectedReason!.toLowerCase(), /refusing to overwrite/);
    await tn2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------
// signature checking via the runtime
// ---------------------------------------------------------------------

test("project_seed signature must verify (manifest tamper rejected)", async () => {
  const { device } = deviceWithKnownSeed();
  const dir = mkTempDir("tn-proj-sigfail-");
  try {
    const pkgPath = join(dir, "p.project.tnpkg");
    buildProjectSeedTnpkg(pkgPath, device);

    // Tamper with the manifest by mutating its state in-place and
    // re-zipping without re-signing.
    const { manifest, body } = readTnpkg(pkgPath);
    manifest.eventCount = 999;
    const bodyObj: Record<string, Uint8Array> = {};
    for (const [k, v] of body) bodyObj[k] = v;
    writeTnpkg(pkgPath, manifest, bodyObj);

    const work = join(dir, "fresh");
    mkdirSync(work, { recursive: true });
    await assert.rejects(() => Tn.absorb(pkgPath, { cwd: work }), /signature does not verify/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Suppress unused-import lint: NodeRuntime is referenced via Tn.init.
void NodeRuntime;
