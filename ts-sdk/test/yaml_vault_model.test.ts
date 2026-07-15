import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadConfig } from "../src/runtime/config.js";

function writeYaml(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "tn-yaml-vault-"));
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, body, "utf8");
  return yamlPath;
}

const BASE = `
ceremony:
  id: cer_vault
  cipher: btn
keystore:
  path: ./keys
device:
  device_identity: did:key:zABC
groups:
  default:
    cipher: btn
`;

test("no vault block means vault off", () => {
  const cfg = loadConfig(writeYaml(BASE));

  assert.equal(cfg.vault.enabled, false);
  assert.equal(cfg.vault.url, undefined);
  assert.equal(cfg.vault.linkedProjectId, undefined);
  assert.equal(cfg.vault.autosync, false);
  assert.equal(cfg.vault.syncIntervalSeconds, 600);
});

test("vault block normalizes with 600 second default", () => {
  const cfg = loadConfig(
    writeYaml(
      BASE +
        `vault:
  enabled: true
  url: https://vault.example
  linked_project_id: ""
  autosync: true
`,
    ),
  );

  assert.equal(cfg.vault.enabled, true);
  assert.equal(cfg.vault.url, "https://vault.example");
  assert.equal(cfg.vault.linkedProjectId, undefined);
  assert.equal(cfg.vault.autosync, true);
  assert.equal(cfg.vault.syncIntervalSeconds, 600);
});

test("vault.jwks pin normalizes as local operating trust config", () => {
  const cfg = loadConfig(
    writeYaml(
      BASE +
        `vault:
  enabled: true
  url: https://vault.example
  jwks:
    issuer: did:key:zVaultExample
    url: https://vault.example/.well-known/tn/jwks.json
    fingerprint: sha256:${"a".repeat(64)}
    pinned_at: 2026-07-14T00:00:00Z
`,
    ),
  );

  assert.deepEqual(cfg.vault.jwks, {
    issuer: "did:key:zVaultExample",
    url: "https://vault.example/.well-known/tn/jwks.json",
    fingerprint: "sha256:" + "a".repeat(64),
    pinnedAt: "2026-07-14T00:00:00Z",
  });
});

test("vault.jwks pin validates fingerprint and timestamp", () => {
  assert.throws(
    () =>
      loadConfig(
        writeYaml(
          BASE +
            `vault:
  enabled: true
  url: https://vault.example
  jwks:
    issuer: did:key:zVaultExample
    url: https://vault.example/.well-known/tn/jwks.json
    fingerprint: nope
`,
        ),
      ),
    /vault\.jwks\.fingerprint must be sha256/,
  );

  assert.throws(
    () =>
      loadConfig(
        writeYaml(
          BASE +
            `vault:
  enabled: true
  url: https://vault.example
  jwks:
    issuer: did:key:zVaultExample
    url: https://vault.example/.well-known/tn/jwks.json
    fingerprint: sha256:${"a".repeat(64)}
    pinned_at: not-a-date
`,
        ),
      ),
    /vault\.jwks\.pinned_at must be an ISO timestamp/,
  );
});

test("legacy ceremony link fields still populate vault view", () => {
  const cfg = loadConfig(
    writeYaml(`
ceremony:
  id: cer_vault
  mode: linked
  cipher: btn
  linked_vault: https://legacy-vault.example
  linked_project_id: proj_legacy
keystore:
  path: ./keys
device:
  device_identity: did:key:zABC
groups:
  default:
    cipher: btn
`),
  );

  assert.equal(cfg.vault.enabled, true);
  assert.equal(cfg.vault.url, "https://legacy-vault.example");
  assert.equal(cfg.vault.linkedProjectId, "proj_legacy");
  assert.equal(cfg.vault.autosync, true);
  assert.equal(cfg.vault.syncIntervalSeconds, 600);
});

test("disabled vault block suppresses legacy ceremony link fields", () => {
  const cfg = loadConfig(
    writeYaml(`
ceremony:
  id: cer_vault
  mode: local
  cipher: btn
  linked_vault: https://legacy-vault.example
  linked_project_id: proj_legacy
keystore:
  path: ./keys
device:
  device_identity: did:key:zABC
groups:
  default:
    cipher: btn
vault:
  enabled: false
  url: ""
  linked_project_id: ""
  autosync: false
  sync_interval_seconds: 600
`),
  );

  assert.equal(cfg.vault.enabled, false);
  assert.equal(cfg.vault.url, undefined);
  assert.equal(cfg.vault.linkedProjectId, undefined);
  assert.equal(cfg.vault.autosync, false);
  assert.equal(cfg.vault.syncIntervalSeconds, 600);
});
