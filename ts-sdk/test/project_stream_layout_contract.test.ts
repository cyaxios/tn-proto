import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import {
  TNInvalidName,
  defaultProjectName,
  isValidCeremonyName,
  projectLayout,
  streamLayout,
} from "../src/multi.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = resolve(__filename, "..");
const REPO = resolve(__dirname, "..", "..");
const FIXTURE = resolve(REPO, "tests", "fixtures", "layout", "project_stream_paths.json");

interface LayoutCase {
  id: string;
  workspace: string;
  project: string | null;
  expected_project?: string;
  stream: string;
  project_dir: string;
  project_yaml: string;
  keys_dir: string;
  streams_dir: string;
  logs_dir: string;
  admin_dir: string;
  vault_dir: string;
  stream_yaml: string;
  log_path: string;
  admin_log_path: string;
  stream_extends: string;
}

interface LayoutContract {
  valid_names: string[];
  invalid_names: string[];
  cases: LayoutCase[];
}

function loadContract(): LayoutContract {
  return JSON.parse(readFileSync(FIXTURE, "utf8")) as LayoutContract;
}

function rel(path: string, root: string): string {
  return relative(root, path).replaceAll("\\", "/");
}

function makeRoot(): string {
  return mkdtempSync(join(tmpdir(), "tn-layout-contract-"));
}

test("project and stream name validation matches contract", () => {
  const contract = loadContract();
  for (const name of contract.valid_names) {
    assert.equal(isValidCeremonyName(name), true, name);
  }
  for (const name of contract.invalid_names) {
    assert.equal(isValidCeremonyName(name), false, name);
  }
});

for (const caseId of [
  "init_named_payroll_default_stream",
  "use_api_in_payroll",
  "cwd_name_as_project",
  "default_project_is_valid",
]) {
  test(`project and stream paths match contract: ${caseId}`, () => {
    const contract = loadContract();
    const c = contract.cases.find((item) => item.id === caseId);
    assert.ok(c);
    const root = makeRoot();
    try {
      const workspace = join(root, c.workspace);
      mkdirSync(workspace);
      const project = c.project ?? undefined;
      const pl = projectLayout(project, workspace);
      const sl = streamLayout(c.stream, { project, projectDir: workspace });

      assert.equal(pl.project, c.expected_project ?? c.project);
      assert.equal(defaultProjectName(workspace), c.workspace);
      assert.equal(rel(pl.projectDir, workspace), c.project_dir);
      assert.equal(rel(pl.projectYaml, workspace), c.project_yaml);
      assert.equal(rel(pl.keysDir, workspace), c.keys_dir);
      assert.equal(rel(pl.streamsDir, workspace), c.streams_dir);
      assert.equal(rel(pl.logsDir, workspace), c.logs_dir);
      assert.equal(rel(pl.adminDir, workspace), c.admin_dir);
      assert.equal(rel(pl.vaultDir, workspace), c.vault_dir);

      assert.equal(sl.project.project, pl.project);
      assert.equal(sl.stream, c.stream);
      assert.equal(rel(sl.streamYaml, workspace), c.stream_yaml);
      assert.equal(rel(sl.logPath, workspace), c.log_path);
      assert.equal(rel(sl.adminLogPath, workspace), c.admin_log_path);
      assert.equal(sl.extendsRelpath, c.stream_extends);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test("project and stream layout reject invalid names", () => {
  const root = makeRoot();
  try {
    for (const name of loadContract().invalid_names) {
      assert.throws(() => projectLayout(name, root), TNInvalidName);
      assert.throws(
        () => streamLayout(name, { project: "payroll", projectDir: root }),
        TNInvalidName,
      );
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
