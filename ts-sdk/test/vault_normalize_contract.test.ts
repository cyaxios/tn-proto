// Cross-language vault-block normalization contract (TS side).
//
// The server-independent half of the vault.sync contract. Consumes the
// shared golden ../../tests/fixtures/vault/normalize_cases.json (generated
// by python/tools/generate_vault_normalize_fixture.py) and proves the TS
// normalizer matches the Python reference on defaults, the legacy
// ceremony.linked_* bridge, enabled:false suppression, the 600s interval
// default, and the error conditions. Python asserts the same cases in
// python/tests/test_vault_normalize_contract.py.

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { normalizeVaultConfig } from "../src/runtime/config.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(HERE, "..", "..", "tests", "fixtures", "vault", "normalize_cases.json");

interface Expected {
  error?: boolean;
  enabled?: boolean;
  url?: string | null;
  linked_project_id?: string | null;
  autosync?: boolean;
  sync_interval_seconds?: number;
}
interface Case {
  name: string;
  vault: Record<string, unknown> | null;
  ceremony: Record<string, unknown>;
  expected: Expected;
}

const cases = (JSON.parse(readFileSync(FIXTURE, "utf-8")) as { cases: Case[] }).cases;

for (const c of cases) {
  test(`vault normalize: ${c.name}`, () => {
    if (c.expected.error) {
      assert.throws(() => normalizeVaultConfig("tn.yaml", c.vault, c.ceremony));
      return;
    }
    const v = normalizeVaultConfig("tn.yaml", c.vault, c.ceremony);
    assert.equal(v.enabled, c.expected.enabled);
    assert.equal(v.url ?? null, c.expected.url);
    assert.equal((v.linkedProjectId ?? null), c.expected.linked_project_id);
    assert.equal(v.autosync, c.expected.autosync);
    assert.equal(v.syncIntervalSeconds, c.expected.sync_interval_seconds);
  });
}
