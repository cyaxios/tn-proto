// `tn.init()` (module export) auto-link parity with Python `_auto_link_after_init`:
// in a serverless context (Vercel/Lambda/...) a coded `tn.init()` surfaces a
// vault claim URL BY DEFAULT — for both an unnamed ceremony and a generated-name
// one — and exposes it on the returned instance (`tn.claimUrl`). `link:false`
// and a non-serverless default must NOT auto-link.
//
// Run as child processes so each gets a fresh module-level latch + its own
// env (VERCEL/TN_VAULT_URL), against a local mock pending-claims server.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve } from "node:path";
import { pathToFileURL } from "node:url";

const DIST_INDEX = pathToFileURL(pathResolve(process.cwd(), "dist", "index.js")).href;

/** Start a mock vault that accepts the pending-claim POST and returns ids. */
function startMockVault(): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      if (req.method === "POST" && req.url === "/api/v1/pending-claims") {
        // Drain the body, then answer with the minimal id/expiry shape.
        req.on("data", () => {});
        req.on("end", () => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ vault_id: "v_test_abc123", expires_at: "2099-01-01T00:00:00Z" }));
        });
        return;
      }
      res.writeHead(404);
      res.end();
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

interface ChildEnv {
  proj?: string; // ceremony name; omit for the no-name path
  vercel?: boolean; // set VERCEL=1
  link?: "true" | "false"; // explicit opts.link
  vaultBase: string;
}

/** Run `tn.init()` in a child process and capture `tn.claimUrl`. */
function runInitChild(cwd: string, env: ChildEnv): Promise<{ claim: string; code: number }> {
  const script =
    `import { init } from ${JSON.stringify(DIST_INDEX)};\n` +
    `const opts = {};\n` +
    `if (process.env.LINK === "true") opts.link = true;\n` +
    `if (process.env.LINK === "false") opts.link = false;\n` +
    `const tn = await init(process.env.PROJ || undefined, opts);\n` +
    `console.log("CLAIMURL=" + (tn.claimUrl ?? "null"));\n` +
    `await (await import(${JSON.stringify(DIST_INDEX)})).close();\n`;
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    TN_IDENTITY_DIR: join(cwd, ".id"),
    TN_HOME: join(cwd, ".home"),
    TN_VAULT_URL: env.vaultBase,
    // Strip any ambient serverless markers so only what we set counts.
    VERCEL: undefined,
    VERCEL_ENV: undefined,
    AWS_LAMBDA_FUNCTION_NAME: undefined,
  };
  if (env.proj) childEnv.PROJ = env.proj;
  if (env.vercel) childEnv.VERCEL = "1";
  if (env.link) childEnv.LINK = env.link;

  mkdirSync(cwd, { recursive: true });
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, ["--input-type=module", "-e", script], { cwd, env: childEnv });
    let out = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => process.stderr.write(d));
    proc.on("close", (code) => {
      const m = out.match(/CLAIMURL=(.*)/);
      resolve({ claim: m ? m[1].trim() : "<none>", code: code ?? -1 });
    });
    proc.on("error", reject);
  });
}

test("tn.init() auto-links by default in serverless — no name AND generated name", async () => {
  const { server, base } = await startMockVault();
  const tmp = mkdtempSync(join(tmpdir(), "tn-autolink-"));
  try {
    // No project name, VERCEL=1 → claim URL surfaced by default.
    const noName = await runInitChild(join(tmp, "a"), { vercel: true, vaultBase: base });
    assert.equal(noName.code, 0);
    assert.match(noName.claim, new RegExp(`^${base}/claim/v_test_abc123#k=`), `got ${noName.claim}`);

    // Generated project name, VERCEL=1 → also surfaced.
    const named = await runInitChild(join(tmp, "b"), { proj: "genproj", vercel: true, vaultBase: base });
    assert.equal(named.code, 0);
    assert.match(named.claim, new RegExp(`^${base}/claim/v_test_abc123#k=`), `got ${named.claim}`);
  } finally {
    server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.init() does NOT auto-link off-serverless, or with link:false", async () => {
  const { server, base } = await startMockVault();
  const tmp = mkdtempSync(join(tmpdir(), "tn-autolink-"));
  try {
    // Not serverless, default link → no auto-link.
    const plain = await runInitChild(join(tmp, "a"), { vaultBase: base });
    assert.equal(plain.code, 0);
    assert.equal(plain.claim, "null", `expected no claim; got ${plain.claim}`);

    // Serverless but link:false → no auto-link.
    const optedOut = await runInitChild(join(tmp, "b"), { vercel: true, link: "false", vaultBase: base });
    assert.equal(optedOut.code, 0);
    assert.equal(optedOut.claim, "null", `expected no claim; got ${optedOut.claim}`);

    // Explicit link:true off-serverless → DOES auto-link.
    const forced = await runInitChild(join(tmp, "c"), { link: "true", vaultBase: base });
    assert.equal(forced.code, 0);
    assert.match(forced.claim, new RegExp(`^${base}/claim/`), `got ${forced.claim}`);
  } finally {
    server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
