// Dirt-easy lifecycle tests — the headline UX for the TS SDK.
//
// After ``Tn.absorb`` of a self-contained bootstrap bundle (project_seed
// or identity_seed) the returned Tn is ready to emit/read. The user
// does not need a separate ``Tn.init`` step.
//
// Mirrors ``python/tests/test_dirt_easy_flow.py``.

import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { test } from "node:test";

import { Tn } from "../src/tn.js";
import { DeviceKey, newManifest, signManifestWithBody, writeTnpkg } from "../src/index.js";

const FIXTURE = pathResolve(
  dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")),
  "fixtures",
  "Agentic20.project.tnpkg",
);

function mkTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function buildIdentitySeedTnpkg(outPath: string): {
  device: DeviceKey;
  seed: Uint8Array;
} {
  // Generate a fresh device key; export_identity_seed-style stub yaml.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 7 + 3) & 0xff;
  const device = DeviceKey.fromSeed(seed);
  const stubYaml =
    `# Identity seed stub written by Tn.absorb tests.\n` + `identity:\n  did: ${device.did}\n`;
  const body: Record<string, Uint8Array> = {
    "body/local.private": new Uint8Array(seed),
    "body/local.public": new TextEncoder().encode(device.did),
    "body/tn.yaml": new TextEncoder().encode(stubYaml),
  };
  const manifest = newManifest({
    kind: "identity_seed",
    fromDid: device.did,
    ceremonyId: "_identity_seed",
    scope: "identity",
    toDid: device.did,
  });
  manifest.state = {
    identity: { schema: "tn-identity-seed-v1", nickname: null },
  };
  signManifestWithBody(manifest, body, device);
  writeTnpkg(outPath, manifest, body);
  return { device, seed };
}

test("dirt-easy: legacy project_seed fixture without body index fails closed", async () => {
  if (!existsSync(FIXTURE)) {
    // Real dashboard-minted fixture not checked in for this run.
    return;
  }
  const dir = mkTempDir("tn-dirt-proj-");
  try {
    await assert.rejects(() => Tn.absorb(FIXTURE, { cwd: dir }), /body_digest_mismatch/);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dirt-easy: identity_seed bootstrap returns a usable Tn", async () => {
  const dir = mkTempDir("tn-dirt-id-");
  try {
    const pkgPath = join(dir, "id.tnpkg");
    const { device } = buildIdentitySeedTnpkg(pkgPath);

    const work = join(dir, "fresh");
    mkdirSync(work, { recursive: true });
    const tn = await Tn.absorb(pkgPath, { cwd: work });
    assert.equal(tn.lastAbsorbReceipt?.kind, "identity_seed");
    // The runtime adopted the absorbed identity.
    assert.equal(tn.did, device.did);
    tn.info("first.event");
    let count = 0;
    for (const _ of tn.read()) count += 1;
    assert.ok(count >= 1, `expected at least one entry; saw ${count}`);
    await tn.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Tn.init() discovery picks up legacy ./tn.yaml", async () => {
  const dir = mkTempDir("tn-dirt-disc-");
  try {
    // Mint a legacy-layout ceremony at <dir>/tn.yaml.
    const yamlPath = join(dir, "tn.yaml");
    const tn1 = await Tn.init(yamlPath);
    await tn1.close();

    // No-args init in the same cwd should rediscover the legacy file
    // (NOT mint a fresh ceremony in .tn/default/ or elsewhere).
    const prior = process.cwd();
    process.chdir(dir);
    try {
      const tn2 = await Tn.init();
      const cfg = tn2.config() as { yamlPath: string; yamlDir?: string };
      const resolvedYaml = pathResolve((cfg as { yamlPath: string }).yamlPath);
      assert.equal(resolvedYaml, pathResolve(yamlPath));
      // No .tn/default appeared.
      assert.ok(!existsSync(join(dir, ".tn", "default", "tn.yaml")));
      await tn2.close();
    } finally {
      process.chdir(prior);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Tn.init() discovery picks up multi-ceremony ./.tn/default/tn.yaml", async () => {
  const dir = mkTempDir("tn-dirt-disc-multi-");
  try {
    // Mint at the multi-ceremony layout.
    const multiYaml = join(dir, ".tn", "default", "tn.yaml");
    const tn1 = await Tn.init(multiYaml);
    await tn1.close();

    const prior = process.cwd();
    process.chdir(dir);
    try {
      const tn2 = await Tn.init();
      const cfg = tn2.config() as { yamlPath: string };
      assert.equal(pathResolve(cfg.yamlPath), pathResolve(multiYaml));
      await tn2.close();
    } finally {
      process.chdir(prior);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Tn.init() creates project-root layout from cwd name when nothing exists", async () => {
  const dir = mkTempDir("tn-dirt-project-root-");
  try {
    const prior = process.cwd();
    process.chdir(dir);
    try {
      const projectName = dir.split(/[\\/]/).pop() ?? "";
      const tn = await Tn.init(undefined, { stdout: false });
      const cfg = tn.config() as { yamlPath: string; logPath?: string };
      assert.equal(
        pathResolve(cfg.yamlPath),
        pathResolve(join(dir, ".tn", projectName, "tn.yaml")),
      );
      assert.ok(existsSync(join(dir, ".tn", projectName, "streams", "default.yaml")));
      assert.ok(!existsSync(join(dir, ".tn", "default", "tn.yaml")));
      await tn.close();
    } finally {
      process.chdir(prior);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Tn.absorb on a non-bootstrap bundle throws a helpful error", async () => {
  const dir = mkTempDir("tn-dirt-nonboot-");
  try {
    // Build a non-bootstrap bundle: an admin_log_snapshot. Tn.absorb
    // should reject (only bootstrap kinds are supported standalone).
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) seed[i] = (i + 1) & 0xff;
    const device = DeviceKey.fromSeed(seed);
    const manifest = newManifest({
      kind: "admin_log_snapshot",
      fromDid: device.did,
      ceremonyId: "any",
      scope: "admin",
    });
    signManifestWithBody(manifest, {}, device);
    const pkgPath = join(dir, "snap.tnpkg");
    writeTnpkg(pkgPath, manifest, {});

    await assert.rejects(
      () => Tn.absorb(pkgPath, { cwd: dir }),
      /not a bootstrap kind|only identity_seed and project_seed/i,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
