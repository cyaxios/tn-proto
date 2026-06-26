// End-to-end coverage for `tn-js admin rotate` — the deploy-shaped CLI
// verb. Mirrors the Python `tests/test_cli_rotate.py` shape so cross-
// language behavior stays in lockstep.
//
// Each test uses subprocess so we exercise the actual argv parsing +
// adminCmd dispatch, not just the AdminNamespace.rotate library API.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve } from "node:path";
import { Tn } from "../src/tn.js";

const CLI = pathResolve(process.cwd(), "bin/tn-js.mjs");

interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

async function runCli(args: string[], cwd: string): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn("node", [CLI, ...args], { cwd });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

async function setupCeremonyWithRecipients(): Promise<{ dir: string; yamlPath: string }> {
  const dir = mkdtempSync(join(tmpdir(), "ts-cli-rot-"));
  const yamlPath = join(dir, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  // Mint two recipient kits via the library (CLI add-recipient is
  // covered by other tests; we just need a populated ceremony here).
  const cfg = tn.config() as { keystorePath: string };
  // Use a side dir per kit so the publisher's own self-kit isn't
  // overwritten. (The CLI rotate's per-recipient kit re-mint uses
  // its own temp staging dir; this is just for setup.)
  const aDir = join(dir, "_alice");
  const bDir = join(dir, "_bob");
  for (const d of [aDir, bDir]) {
    rmSync(d, { recursive: true, force: true });
  }
  await tn.admin.addRecipient("default", {
    recipientDid: "did:key:zAlice",
    outKitPath: join(aDir, "default.btn.mykit"),
  });
  await tn.admin.addRecipient("default", {
    recipientDid: "did:key:zBob",
    outKitPath: join(bDir, "default.btn.mykit"),
  });
  void cfg;
  await tn.close();
  return { dir, yamlPath };
}

test("tn-js admin rotate emits per-recipient .tnpkg artifacts", async () => {
  const { dir, yamlPath } = await setupCeremonyWithRecipients();
  try {
    const result = await runCli(
      ["admin", "rotate", "--yaml", yamlPath],
      dir,
    );
    assert.equal(result.code, 0, `stderr=${result.stderr} stdout=${result.stdout}`);

    const out = JSON.parse(result.stdout.trim());
    assert.equal(out.ok, true);
    assert.equal(out.rotated.length, 1);
    assert.equal(out.rotated[0].group, "default");
    assert.ok(out.rotated[0].generation >= 1);
    assert.equal(out.artifacts.length, 2, "expected 2 .tnpkg artifacts (Alice + Bob)");
    for (const art of out.artifacts) {
      assert.ok(existsSync(art), `artifact ${art} should exist on disk`);
      assert.ok(statSync(art).size > 0, `artifact ${art} should be non-empty`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tn-js admin rotate --out <dir> writes into the chosen directory", async () => {
  const { dir, yamlPath } = await setupCeremonyWithRecipients();
  const outDir = join(dir, "custom_out");
  try {
    const result = await runCli(
      ["admin", "rotate", "--yaml", yamlPath, "--out", outDir],
      dir,
    );
    assert.equal(result.code, 0, `stderr=${result.stderr} stdout=${result.stdout}`);
    const out = JSON.parse(result.stdout.trim());
    assert.equal(out.out_dir, outDir);
    const files = readdirSync(outDir).filter((f) => f.endsWith(".tnpkg"));
    assert.equal(files.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tn-js admin rotate --out <single>.tnpkg rejects multi-recipient", async () => {
  const { dir, yamlPath } = await setupCeremonyWithRecipients();
  try {
    const single = join(dir, "single.tnpkg");
    const result = await runCli(
      ["admin", "rotate", "--yaml", yamlPath, "--out", single],
      dir,
    );
    assert.notEqual(result.code, 0, "should exit non-zero");
    assert.match(result.stderr, /single \.tnpkg path/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tn-js admin rotate without recipients records the rotation but emits no artifacts", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-cli-rot-empty-"));
  const yamlPath = join(dir, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  await tn.close();
  try {
    const result = await runCli(
      ["admin", "rotate", "--yaml", yamlPath],
      dir,
    );
    assert.equal(result.code, 0, `stderr=${result.stderr}`);
    const out = JSON.parse(result.stdout.trim());
    assert.equal(out.ok, true);
    assert.equal(out.artifacts.length, 0);
    assert.match(out.note, /no surviving recipients/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tn-js admin rotate --groups <subset> rotates only those groups", async () => {
  const { dir, yamlPath } = await setupCeremonyWithRecipients();
  try {
    const result = await runCli(
      ["admin", "rotate", "--yaml", yamlPath, "--groups", "default"],
      dir,
    );
    assert.equal(result.code, 0, `stderr=${result.stderr}`);
    const out = JSON.parse(result.stdout.trim());
    assert.equal(out.rotated.length, 1);
    assert.equal(out.rotated[0].group, "default");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tn-js admin rotate unknown group dies fast", async () => {
  const { dir, yamlPath } = await setupCeremonyWithRecipients();
  try {
    const result = await runCli(
      ["admin", "rotate", "--yaml", yamlPath, "--group", "nonexistent"],
      dir,
    );
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /unknown group/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tn-js admin rotate bumps groups.<g>.index_epoch in the yaml", async () => {
  const { dir, yamlPath } = await setupCeremonyWithRecipients();
  try {
    // Verify pre-rotation: epoch is 0 (or unset).
    const preYaml = readFileSync(yamlPath, "utf8");
    const preEpochMatch = preYaml.match(/index_epoch:\s*(\d+)/);
    const preEpoch = preEpochMatch ? Number.parseInt(preEpochMatch[1] ?? "0", 10) : 0;

    const result = await runCli(
      ["admin", "rotate", "--yaml", yamlPath],
      dir,
    );
    assert.equal(result.code, 0, `stderr=${result.stderr}`);

    const postYaml = readFileSync(yamlPath, "utf8");
    const postEpochMatch = postYaml.match(/index_epoch:\s*(\d+)/);
    assert.ok(postEpochMatch, "post-rotation yaml must have an index_epoch");
    const postEpoch = Number.parseInt(postEpochMatch[1] ?? "0", 10);
    assert.equal(postEpoch, preEpoch + 1, `epoch should bump by 1 (pre=${preEpoch})`);

    // Sidecar `.revoked.<ts>` files should also exist for the rotated group.
    const cfg = (await Tn.init(yamlPath)).config() as { keystorePath: string };
    const ks = readdirSync(cfg.keystorePath);
    assert.ok(
      ks.some((f) => f.startsWith("default.btn.state.revoked.")),
      `expected default.btn.state.revoked.<ts>; got ${ks.join(", ")}`,
    );
    assert.ok(
      ks.some((f) => f.startsWith("default.btn.mykit.revoked.")),
      `expected default.btn.mykit.revoked.<ts>; got ${ks.join(", ")}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rotated .tnpkg artifact is a valid kit_bundle", async () => {
  const { dir, yamlPath } = await setupCeremonyWithRecipients();
  try {
    const result = await runCli(["admin", "rotate", "--yaml", yamlPath], dir);
    assert.equal(result.code, 0, `stderr=${result.stderr}`);
    const out = JSON.parse(result.stdout.trim());
    assert.ok(out.artifacts.length > 0);

    // Each artifact is a zip with manifest.json declaring kind=kit_bundle.
    // We don't ship a zip dependency in the test surface; just verify
    // that the file looks like a zip (PK header) + size > 200 bytes.
    for (const art of out.artifacts) {
      const bytes = readFileSync(art);
      assert.ok(
        bytes.length >= 200,
        `artifact ${art} too small to be a kit_bundle (${bytes.length} bytes)`,
      );
      assert.equal(bytes[0], 0x50, "first byte should be 'P' (zip)");
      assert.equal(bytes[1], 0x4b, "second byte should be 'K' (zip)");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
