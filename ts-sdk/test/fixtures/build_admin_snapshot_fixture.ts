// Generate the TS-produced ``ts_admin_snapshot.tnpkg`` fixture for
// cross-language byte-compare tests.
//
// Canonical scenario (mirrored in the Python + Rust builders):
//
//   1. Fresh btn ceremony.
//   2. tn.recipient.added for did:key:zAlice  -> leaf A
//   3. tn.recipient.added for did:key:zBob    -> leaf B
//   4. tn.recipient.revoked for leaf A
//   5. tn.vault.linked     vault=did:web:vault.example  project_id=demo
//
// Run with:
//
//     cd tn-protocol/ts-sdk
//     node --import tsx test/fixtures/build_admin_snapshot_fixture.ts
//
// Re-running overwrites the fixture. Cross-consume tests verify that the
// signed manifest parses, signature verifies, AdminState matches the
// canonical scenario; byte-equivalence with other languages' fixtures is
// not asserted (per-ceremony randomness in DIDs / kit material). Wire-
// format byte-equivalence is asserted separately via the manifest-
// canonical-bytes test.

import { Buffer } from "node:buffer";
import { mkdirSync, mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { DeviceKey, TNClient } from "../../src/index.js";
import { BtnPublisher } from "../../src/raw.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function makeCeremony(): { yamlPath: string; tmpDir: string } {
  const dir = mkdtempSync(join(tmpdir(), "tn-tnpkg-fixture-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 17 + 31) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 23) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  const yaml = `ceremony:\n  id: ts_fixture\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${dk.did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\n- group\n- leaf_index\n- recipient_did\n- kit_sha256\n- cipher\n- ceremony_id\n- vault_did\n- project_id\n- linked_at\n- publisher_did\n- added_at\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - did: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return { yamlPath, tmpDir: dir };
}

function main(): void {
  const { yamlPath, tmpDir } = makeCeremony();
  const client = TNClient.init(yamlPath);
  const kitsDir = mkdtempSync(join(tmpdir(), "tn-tnpkg-kits-"));
  const leafA = client.adminAddRecipient(
    "default",
    join(kitsDir, "default.btn.mykit"),
    "did:key:zAlice",
  );
  client.adminAddRecipient(
    "default",
    join(kitsDir, "default_bob.btn.mykit"),
    "did:key:zBob",
  );
  client.adminRevokeRecipient("default", leafA, "did:key:zAlice");
  client.vaultLink("did:web:vault.example", "demo");

  const fixturePath = resolve(__dirname, "ts_admin_snapshot.tnpkg");
  client.export({ kind: "admin_log_snapshot" }, fixturePath);
  client.close();

  const bytes = statSync(fixturePath).size;
  // eslint-disable-next-line no-console
  console.log(`wrote ${fixturePath} (${bytes} bytes)`);
  // Cleanup is best-effort; ignore failures on Windows.
  void tmpDir;
}

main();
