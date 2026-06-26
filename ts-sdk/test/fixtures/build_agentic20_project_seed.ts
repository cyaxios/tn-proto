// Mint a fresh ``Agentic20.project.tnpkg`` fixture for cross-language
// project_seed round-trip tests.
//
// The original fixture under HEAD was a real dashboard-minted bundle
// from `tn_proto_web/static/account/project_minter.js`, but the
// committed binary had been corrupted (UTF-8 replacement chars
// injected into the zip bytes during some past transit step). We
// mint a fresh equivalent here using only TS SDK primitives: stand up
// a real btn ceremony in a tempdir, harvest the resulting tn.yaml +
// keystore, then wrap into a signed project_seed manifest.
//
// Run with:
//
//     cd tn_proto/ts-sdk
//     node --import tsx test/fixtures/build_agentic20_project_seed.ts
//
// Re-running overwrites both the TS and Python copies (committed in
// `python/tests/fixtures/`) so the byte-compare tests stay in sync.

import { Buffer } from "node:buffer";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { DeviceKey, newManifest, signManifest, writeTnpkg } from "../../src/index.js";
import { Tn } from "../../src/tn.js";
import { BtnPublisher } from "../../src/raw.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const TS_FIXTURE = resolve(__dirname, "Agentic20.project.tnpkg");
const PY_FIXTURE = resolve(
  __dirname,
  "..",
  "..",
  "..",
  "python",
  "tests",
  "fixtures",
  "Agentic20.project.tnpkg",
);

function makeCeremony(): { yamlPath: string; tmpDir: string; deviceSeed: Uint8Array } {
  const dir = mkdtempSync(join(tmpdir(), "tn-agentic20-mint-"));
  const keys = join(dir, ".tn", "tn", "keys");
  const logs = join(dir, ".tn", "tn", "logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  // Deterministic device seed so consecutive runs produce identical
  // fixtures (good for committed diffs).
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 13 + 41) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");

  // Deterministic index-master.
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 11 + 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  // Mint two btn publishers — one for `default`, one for `tn.agents`.
  for (const [groupName, seedFactor] of [
    ["default", 3],
    ["tn.agents", 5],
  ] as const) {
    const btnSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * seedFactor + 19) & 0xff;
    const pub = new BtnPublisher(btnSeed);
    const kit = pub.mint();
    writeFileSync(
      join(keys, `${groupName}.btn.state`),
      Buffer.from(pub.toBytes()),
    );
    writeFileSync(join(keys, `${groupName}.btn.mykit`), Buffer.from(kit));
  }

  // Generate the project tn.yaml in the same shape the dashboard
  // emits. Both `device:` + `recipient_identity:` are the post-0.4.3a1
  // names; loader rejects the legacy `me:` + `did:` form.
  const yaml =
    `# tn.yaml minted for the Agentic20 cross-language project_seed fixture.\n` +
    `# Mirrors the shape ${"`"}tn init --cipher btn${"`"} produces.\n` +
    `\n` +
    `project_id: 01KQZR3MXTFEB0RG5XWNF5W260\n` +
    `label: "Agentic20"\n` +
    `\n` +
    `ceremony:\n` +
    `  id: local_agentic20\n` +
    `  mode: local\n` +
    `  cipher: btn\n` +
    `\n` +
    `logs:\n` +
    `  path: ./.tn/tn/logs/tn.ndjson\n` +
    `keystore:\n` +
    `  path: ./.tn/tn/keys\n` +
    `\n` +
    `device:\n` +
    `  device_identity: ${dk.did}\n` +
    `\n` +
    `default_policy: private\n` +
    `groups:\n` +
    `  default:\n` +
    `    policy: private\n` +
    `    cipher: btn\n` +
    `    recipients:\n` +
    `      - recipient_identity: ${dk.did}\n` +
    `  tn.agents:\n` +
    `    policy: private\n` +
    `    cipher: btn\n` +
    `    recipients:\n` +
    `      - recipient_identity: ${dk.did}\n` +
    `fields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return { yamlPath, tmpDir: dir, deviceSeed: seed };
}

async function main(): Promise<void> {
  const { yamlPath, tmpDir, deviceSeed } = makeCeremony();
  // Spin up the runtime once to confirm the yaml + keystore are
  // self-consistent — i.e. that the absorb-time loader will accept
  // them — then immediately close. We don't need to emit anything.
  const tn = await Tn.init(yamlPath);
  await tn.close();

  // Harvest the body bytes from the tempdir.
  const keysDir = join(tmpDir, ".tn", "tn", "keys");
  const body: Record<string, Uint8Array> = {
    "body/tn.yaml": new Uint8Array(readFileSync(yamlPath)),
    "body/keys/local.private": new Uint8Array(deviceSeed),
    "body/keys/local.public": new Uint8Array(
      readFileSync(join(keysDir, "local.public")),
    ),
    "body/keys/index_master.key": new Uint8Array(
      readFileSync(join(keysDir, "index_master.key")),
    ),
    "body/keys/default.btn.state": new Uint8Array(
      readFileSync(join(keysDir, "default.btn.state")),
    ),
    "body/keys/default.btn.mykit": new Uint8Array(
      readFileSync(join(keysDir, "default.btn.mykit")),
    ),
    "body/keys/tn.agents.btn.state": new Uint8Array(
      readFileSync(join(keysDir, "tn.agents.btn.state")),
    ),
    "body/keys/tn.agents.btn.mykit": new Uint8Array(
      readFileSync(join(keysDir, "tn.agents.btn.mykit")),
    ),
  };

  const device = DeviceKey.fromSeed(deviceSeed);
  const manifest = newManifest({
    kind: "project_seed",
    fromDid: device.did,
    ceremonyId: "local_agentic20",
    scope: "project",
    toDid: device.did,
  });
  manifest.state = {
    project: {
      schema: "tn-project-seed-v1",
      project_id: "01KQZR3MXTFEB0RG5XWNF5W260",
      ceremony_id: "local_agentic20",
      label: "Agentic20",
      minted_at: "2026-05-21T00:00:00.000+00:00",
    },
  };
  signManifest(manifest, device);

  writeTnpkg(TS_FIXTURE, manifest, body);
  // eslint-disable-next-line no-console
  console.log(`wrote ${TS_FIXTURE}`);

  copyFileSync(TS_FIXTURE, PY_FIXTURE);
  // eslint-disable-next-line no-console
  console.log(`mirrored to ${PY_FIXTURE}`);
}

void main();
