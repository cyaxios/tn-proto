import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import YAML from "yaml";

import { ensureProjectLayoutOnDisk, ensureProjectStreamOnDisk } from "../src/multi.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { Tn } from "../src/tn.js";

type ProjectYamlDoc = {
  ceremony: Record<string, unknown>;
  logs: Record<string, unknown>;
  keystore: Record<string, unknown>;
  extends?: unknown;
  groups?: unknown;
};

function makeProject(): string {
  return mkdtempSync(join(tmpdir(), "tn-project-layout-"));
}

test("ensureProjectLayoutOnDisk creates root yaml and default overlay", () => {
  const projectDir = makeProject();
  try {
    const yamlPath = ensureProjectLayoutOnDisk("payroll", { projectDir });

    assert.equal(yamlPath, join(projectDir, ".tn", "payroll", "tn.yaml"));
    assert.ok(existsSync(yamlPath));
    assert.ok(existsSync(join(projectDir, ".tn", "payroll", "keys", "local.private")));
    assert.ok(existsSync(join(projectDir, ".tn", "payroll", "streams", "default.yaml")));
    assert.ok(existsSync(join(projectDir, ".tn", "payroll", "logs")));
    assert.ok(existsSync(join(projectDir, ".tn", "payroll", "admin")));
    assert.ok(existsSync(join(projectDir, ".tn", "payroll", "vault")));

    const doc = YAML.parse(readFileSync(yamlPath, "utf8")) as ProjectYamlDoc;
    assert.equal(doc.ceremony.project_name, "payroll");
    assert.equal(doc.logs.path, "./logs/default.ndjson");
    assert.equal(doc.ceremony.admin_log_location, "./admin/default.ndjson");
    assert.equal(doc.keystore.path, "./keys");

    const rt = NodeRuntime.init(yamlPath);
    assert.equal(rt.config.logPath, join(projectDir, ".tn", "payroll", "logs", "default.ndjson"));
    rt.close();
  } finally {
    rmSync(projectDir, { recursive: true, force: true });
  }
});

test("ensureProjectStreamOnDisk creates stream overlay with project paths", () => {
  const projectDir = makeProject();
  try {
    const streamYaml = ensureProjectStreamOnDisk("api", {
      project: "payroll",
      projectDir,
    });

    assert.equal(streamYaml, join(projectDir, ".tn", "payroll", "streams", "api.yaml"));
    assert.ok(existsSync(streamYaml));
    assert.equal(existsSync(join(projectDir, ".tn", "payroll", "streams", "keys")), false);

    const doc = YAML.parse(readFileSync(streamYaml, "utf8")) as ProjectYamlDoc;
    assert.equal(doc.extends, "../tn.yaml");
    assert.equal(doc.logs.path, "../logs/api.ndjson");
    assert.equal(doc.ceremony.admin_log_location, "../admin/api.ndjson");
    assert.match(doc.ceremony.id, /^stream_api_/);
    assert.equal("groups" in doc, false);
    assert.equal("keystore" in doc, false);

    const rt = NodeRuntime.init(streamYaml);
    assert.equal(rt.config.logPath, join(projectDir, ".tn", "payroll", "logs", "api.ndjson"));
    assert.equal(rt.config.keystorePath, join(projectDir, ".tn", "payroll", "keys"));
    rt.close();
  } finally {
    rmSync(projectDir, { recursive: true, force: true });
  }
});

test("Tn.use project option opens stream inside named project layout", async () => {
  const projectDir = makeProject();
  try {
    const api1 = await Tn.use("api", { project: "payroll", projectDir });
    const api2 = await Tn.use("api", { project: "payroll", projectDir });
    const audit = await Tn.use("api", { project: "audit", projectDir });
    try {
      assert.equal(api1, api2);
      assert.notEqual(api1, audit);
      assert.equal(api1.logPath, join(projectDir, ".tn", "payroll", "logs", "api.ndjson"));
      assert.equal(audit.logPath, join(projectDir, ".tn", "audit", "logs", "api.ndjson"));
      assert.ok(existsSync(join(projectDir, ".tn", "payroll", "streams", "api.yaml")));
      assert.ok(existsSync(join(projectDir, ".tn", "audit", "streams", "api.yaml")));
    } finally {
      await api1.close();
      await audit.close();
    }
  } finally {
    rmSync(projectDir, { recursive: true, force: true });
  }
});

test("Tn.use infers workspace project when no legacy default exists", async () => {
  const projectDir = makeProject();
  try {
    const projectName = projectDir.split(/[\\/]/).pop() ?? "";
    const api = await Tn.use("api", { projectDir });
    try {
      assert.equal(api.logPath, join(projectDir, ".tn", projectName, "logs", "api.ndjson"));
      assert.ok(existsSync(join(projectDir, ".tn", projectName, "streams", "api.yaml")));
      assert.ok(existsSync(join(projectDir, ".tn", projectName, "tn.yaml")));
      assert.equal(existsSync(join(projectDir, ".tn", "api", "tn.yaml")), false);
    } finally {
      await api.close();
    }
  } finally {
    rmSync(projectDir, { recursive: true, force: true });
  }
});
