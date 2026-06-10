import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";

import { createFreshCeremony } from "../src/runtime/node_runtime.js";
import { loadConfig } from "../src/runtime/config.js";
import { DEFAULT_VAULT_URL } from "../src/vault/url.js";

test("createFreshCeremony writes project-level vault block by default", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-create-vault-"));
  const yamlPath = join(dir, "tn.yaml");

  createFreshCeremony(yamlPath);

  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as {
    vault: Record<string, unknown>;
  };
  assert.equal(doc["vault"]["enabled"], true);
  assert.equal(doc["vault"]["url"], DEFAULT_VAULT_URL);
  assert.equal(doc["vault"]["linked_project_id"], "");
  assert.equal(doc["vault"]["autosync"], true);
  assert.equal(doc["vault"]["sync_interval_seconds"], 600);

  const cfg = loadConfig(yamlPath);
  assert.equal(cfg.vault.enabled, true);
  assert.equal(cfg.vault.url, DEFAULT_VAULT_URL);
  assert.equal(cfg.vault.linkedProjectId, undefined);
  assert.equal(cfg.vault.autosync, true);
  assert.equal(cfg.vault.syncIntervalSeconds, 600);
});
