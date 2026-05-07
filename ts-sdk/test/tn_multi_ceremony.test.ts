/**
 * Tests for TS-side multi-ceremony entry points.
 *
 * Coverage:
 *   - listCeremonies enumerates `.tn/<name>/` subdirs with a tn.yaml.
 *   - openCeremony rejects invalid names.
 *   - openCeremony rejects names not present on disk.
 *   - The discovery chain in Tn.init picks up `./.tn/default/tn.yaml`.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { Tn } from "../src/tn.js";

function makeProject(): string {
  return mkdtempSync(join(tmpdir(), "tn-multi-"));
}

function seedYaml(path: string): void {
  const minimal = [
    "ceremony:",
    "  id: test_ceremony",
    "  cipher: jwe",
    "me:",
    "  did: did:key:z6MkTest",
    "keystore:",
    "  path: ./keys",
    "groups:",
    "  default:",
    "    policy: private",
    "    cipher: jwe",
    "    recipients:",
    "      - did: did:key:z6MkTest",
    "default_policy: private",
    "",
  ].join("\n");
  writeFileSync(path, minimal, "utf8");
}

test("Tn.listCeremonies returns empty when no .tn/ exists", () => {
  const project = makeProject();
  try {
    assert.deepEqual(Tn.listCeremonies(project), []);
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("Tn.listCeremonies enumerates .tn/<name>/ subdirs with tn.yaml", () => {
  const project = makeProject();
  try {
    const root = join(project, ".tn");
    mkdirSync(join(root, "default"), { recursive: true });
    seedYaml(join(root, "default", "tn.yaml"));
    mkdirSync(join(root, "payments"), { recursive: true });
    seedYaml(join(root, "payments", "tn.yaml"));
    // Subdir without yaml is ignored.
    mkdirSync(join(root, "incomplete"), { recursive: true });

    const out = Tn.listCeremonies(project);
    assert.deepEqual(out, ["default", "payments"]);
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("Tn.openCeremony rejects invalid ceremony names", async () => {
  const project = makeProject();
  try {
    await assert.rejects(
      Tn.openCeremony("bad/name", { projectDir: project }),
      /invalid ceremony name/,
    );
    await assert.rejects(
      Tn.openCeremony("", { projectDir: project }),
      /invalid ceremony name/,
    );
    await assert.rejects(
      Tn.openCeremony("tn", { projectDir: project }),
      /invalid ceremony name/,
    );
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("Tn.openCeremony auto-creates the default ceremony if absent", async () => {
  const project = makeProject();
  try {
    // Open default — should auto-create the full ceremony (yaml + keys).
    const tn = await Tn.openCeremony("default", { projectDir: project });
    try {
      // Yaml exists on disk after open.
      assert.ok(
        existsSync(join(project, ".tn", "default", "tn.yaml")),
        "default tn.yaml should be created on first openCeremony",
      );
      // Keystore exists.
      assert.ok(
        existsSync(join(project, ".tn", "default", "keys", "local.private")),
        "default keystore should be created",
      );
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("Tn.openCeremony auto-creates a named stream that extends default", async () => {
  const project = makeProject();
  try {
    const tn = await Tn.openCeremony("payments", { projectDir: project });
    try {
      // Stream yaml exists.
      const streamYaml = join(project, ".tn", "payments", "tn.yaml");
      assert.ok(existsSync(streamYaml));
      // It contains extends: pointing at default.
      const text = readFileSync(streamYaml, "utf8");
      assert.match(text, /extends:.*default\/tn\.yaml/);
      // Default also got created (parent of the stream).
      assert.ok(existsSync(join(project, ".tn", "default", "tn.yaml")));
      assert.ok(existsSync(join(project, ".tn", "default", "keys", "local.private")));
      // Stream itself has no keys/ dir (shared identity).
      assert.ok(!existsSync(join(project, ".tn", "payments", "keys")));
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("Tn.openCeremony stamps profile into stream yaml", async () => {
  const project = makeProject();
  try {
    const tn = await Tn.openCeremony("traces", {
      projectDir: project,
      profile: "telemetry",
    });
    try {
      const text = readFileSync(
        join(project, ".tn", "traces", "tn.yaml"),
        "utf8",
      );
      assert.match(text, /profile:\s*telemetry/);
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});
