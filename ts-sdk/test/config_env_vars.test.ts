// Env-var substitution in the TS yaml loader.
//
// Mirrors `python/tests/test_config_env_vars.py` and the Rust test in
// `crypto/tn-core/tests/config_env_vars.rs` for cross-language parity.

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { substituteEnvVars } from "../src/runtime/config.js";

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T): T {
  const prev: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) {
    prev[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k];
    else process.env[k] = vars[k];
  }
  try {
    return fn();
  } finally {
    for (const k of Object.keys(prev)) {
      const v = prev[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const SOURCE = "/tmp/tn.yaml";

test("required var present is substituted", () => {
  withEnv({ TN_TEST_HOST: "atlas.cluster.example" }, () => {
    const out = substituteEnvVars("uri: ${TN_TEST_HOST}\n", SOURCE);
    assert.equal(out, "uri: atlas.cluster.example\n");
  });
});

test("required var absent throws with var name and path", () => {
  withEnv({ TN_TEST_MISSING: undefined }, () => {
    assert.throws(
      () => substituteEnvVars("uri: ${TN_TEST_MISSING}\n", SOURCE),
      (err: Error) =>
        err.message.includes("TN_TEST_MISSING") &&
        err.message.includes(SOURCE) &&
        err.message.includes(":1:"),
    );
  });
});

test("default used when var absent", () => {
  withEnv({ TN_TEST_ABSENT: undefined }, () => {
    const out = substituteEnvVars("id: ${TN_TEST_ABSENT:-fallback_id}\n", SOURCE);
    assert.equal(out, "id: fallback_id\n");
  });
});

test("default ignored when var present", () => {
  withEnv({ TN_TEST_PRESENT: "real_value" }, () => {
    const out = substituteEnvVars("id: ${TN_TEST_PRESENT:-fallback}\n", SOURCE);
    assert.equal(out, "id: real_value\n");
  });
});

test("empty default substitutes empty string", () => {
  withEnv({ TN_TEST_EMPTY: undefined }, () => {
    const out = substituteEnvVars('id: "${TN_TEST_EMPTY:-}"\n', SOURCE);
    assert.equal(out, 'id: ""\n');
  });
});

test("escape $${LITERAL} passes through", () => {
  const out = substituteEnvVars("note: $${LITERAL}\n", SOURCE);
  assert.equal(out, "note: ${LITERAL}\n");
});

test("mixed substitutions in a yaml fragment", () => {
  withEnv({ TN_TEST_DID: "did:key:zABC", TN_TEST_LOG_DIR: undefined }, () => {
    const text =
      "ceremony:\n" +
      "  id: ${TN_TEST_DID}\n" +
      "  literal: $${LITERAL_TEMPLATE}\n" +
      "logs:\n" +
      "  path: ${TN_TEST_LOG_DIR:-./.tn/logs/tn.ndjson}\n";
    const out = substituteEnvVars(text, SOURCE);
    assert.match(out, /id: did:key:zABC/);
    assert.match(out, /literal: \$\{LITERAL_TEMPLATE\}/);
    assert.match(out, /path: \.\/\.tn\/logs\/tn\.ndjson/);
  });
});

test("malformed var name throws", () => {
  assert.throws(
    () => substituteEnvVars("id: ${1FOO}\n", SOURCE),
    (err: Error) =>
      err.message.includes("${1FOO}") &&
      err.message.includes("malformed") &&
      err.message.includes(SOURCE),
  );
});

test("no recursive expansion", () => {
  // ${X} resolves to a string that itself contains "${Y}"; we do NOT
  // re-scan the substituted text.
  withEnv(
    { TN_TEST_RECURSE: "${TN_TEST_NESTED}", TN_TEST_NESTED: "should_not_expand" },
    () => {
      const out = substituteEnvVars("v: ${TN_TEST_RECURSE}\n", SOURCE);
      assert.equal(out, "v: ${TN_TEST_NESTED}\n");
    },
  );
});

test("loadConfig propagates env-var substitution end-to-end", async () => {
  const { loadConfig } = await import("../src/runtime/config.js");
  const dir = mkdtempSync(join(tmpdir(), "tn-cfg-env-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    const yaml =
      "ceremony:\n" +
      "  id: ${TN_TEST_FIXTURE_ID:-default_id}\n" +
      "  mode: local\n" +
      "  cipher: btn\n" +
      "logs:\n" +
      "  path: ./.tn/logs/tn.ndjson\n" +
      "keystore:\n" +
      "  path: ./.tn/keys\n" +
      "me:\n" +
      "  did: did:key:zABC\n" +
      "groups:\n" +
      "  default:\n" +
      "    policy: private\n" +
      "    cipher: btn\n";
    writeFileSync(yamlPath, yaml, "utf8");

    withEnv({ TN_TEST_FIXTURE_ID: undefined }, () => {
      const cfg = loadConfig(yamlPath);
      assert.equal(cfg.ceremonyId, "default_id");
    });
    withEnv({ TN_TEST_FIXTURE_ID: "real_ceremony" }, () => {
      const cfg = loadConfig(yamlPath);
      assert.equal(cfg.ceremonyId, "real_ceremony");
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
