import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Tn } from "../src/tn.js";

// `tn read` parity with Python: --yaml is optional (discovered from cwd), the
// positional <log> resolves a stream/ceremony NAME from .tn/<name>/, and a
// missing ceremony exits 1.

interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
}

const TN_JS = join(process.cwd(), "bin", "tn-js.mjs");

function runRead(args: string[], cwd: string, idDir: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    // The CLI's discovery is cwd-relative, so run from the project dir; the
    // script itself is referenced by absolute path.
    const proc = spawn("node", [TN_JS, "read", ...args], {
      cwd,
      env: { ...process.env, TN_IDENTITY_DIR: idDir, TN_RUN_ID: "" },
    });
    let out = "";
    let err = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));
    proc.on("close", (code) => resolve({ stdout: out, stderr: err, code: code ?? -1 }));
    proc.on("error", reject);
  });
}

/** Create a ceremony at `yamlPath`, emit one event, disable init rotation. */
async function seed(yamlPath: string): Promise<void> {
  mkdirSync(dirname(yamlPath), { recursive: true });
  const tn = await Tn.init(yamlPath);
  tn.info("order.created", { amount: 100 });
  await tn.close();
  const yamlText = readFileSync(yamlPath, "utf8");
  writeFileSync(yamlPath, yamlText.replace(/rotate_on_init: true/, "rotate_on_init: false"));
}

test("tn-js read discovers ./tn.yaml without --yaml and drops run_id", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-read-"));
  const idDir = join(tmp, ".id");
  try {
    await seed(join(tmp, "tn.yaml"));
    const r = await runRead([], tmp, idDir);
    assert.equal(r.code, 0, `expected exit 0; stderr=${r.stderr}`);
    assert.match(r.stdout, /order\.created/);
    assert.match(r.stdout, /amount=100/);
    assert.doesNotMatch(r.stdout, /run_id=/, "run_id is plumbing, omitted from the one-line view");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js read <name> resolves a stream from .tn/<name>/", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-read-"));
  const idDir = join(tmp, ".id");
  try {
    await seed(join(tmp, ".tn", "mystream", "tn.yaml"));
    const r = await runRead(["mystream"], tmp, idDir);
    assert.equal(r.code, 0, `expected exit 0; stderr=${r.stderr}`);
    assert.match(r.stdout, /order\.created/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn-js read exits 1 with a helpful message when no ceremony is found", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "tn-cli-read-"));
  const idDir = join(tmp, ".id");
  try {
    const r = await runRead([], tmp, idDir);
    assert.equal(r.code, 1, `expected exit 1; stdout=${r.stdout}`);
    assert.match(r.stderr, /no ceremony found here/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
