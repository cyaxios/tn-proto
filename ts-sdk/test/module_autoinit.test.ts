// Module-level auto-init parity with Python (option b).
//
// The bare module verbs no longer throw "called before tn.init()". They
// behave like Python's auto-init:
//
//   * EMIT verbs (log/debug/info/warning/error) discover-or-MINT a
//     ceremony on first call (Python `_autoinit.maybe_autoinit`).
//   * READ-ONLY verbs (read/watch) discover an EXISTING ceremony but
//     never mint — throwing a friendly "no ceremony found" error when
//     none is on disk (Python `_autoinit.maybe_autoinit_load_only`).
//
// SAFETY: every test here is fully sandboxed. We point TN_HOME and
// TN_IDENTITY_DIR at fresh temp dirs AND chdir into a fresh temp cwd so
// no auto-mint can ever touch the real machine identity (%APPDATA%/tn)
// or the repo working tree. The original cwd + env are restored in a
// finally. `_defaultTn` is process-global, so we run from this file's
// own process (node:test gives each file a fresh process) and reset the
// default singleton between cases via `tn.close()`.

import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import * as tn from "../src/index.js";

/** Run `body` with cwd + TN_HOME + TN_IDENTITY_DIR isolated to fresh
 *  temp dirs, restoring everything (cwd, env, default singleton) after. */
async function isolated(
  body: (dirs: { cwd: string; home: string; identity: string }) => Promise<void> | void,
): Promise<void> {
  const cwd = mkdtempSync(join(tmpdir(), "tn-autoinit-cwd-"));
  const home = mkdtempSync(join(tmpdir(), "tn-autoinit-home-"));
  const identity = mkdtempSync(join(tmpdir(), "tn-autoinit-id-"));
  const prevCwd = process.cwd();
  const prevHome = process.env["TN_HOME"];
  const prevId = process.env["TN_IDENTITY_DIR"];
  process.env["TN_HOME"] = home;
  process.env["TN_IDENTITY_DIR"] = identity;
  process.env["TN_AUTOINIT_QUIET"] = "1";
  process.chdir(cwd);
  try {
    await body({ cwd, home, identity });
  } finally {
    // Release the default singleton minted/loaded during the test so the
    // next case starts from a clean `_defaultTn === null`.
    try {
      await tn.close();
    } catch {
      /* best-effort */
    }
    process.chdir(prevCwd);
    if (prevHome === undefined) delete process.env["TN_HOME"];
    else process.env["TN_HOME"] = prevHome;
    if (prevId === undefined) delete process.env["TN_IDENTITY_DIR"];
    else process.env["TN_IDENTITY_DIR"] = prevId;
    rmSync(cwd, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
    rmSync(identity, { recursive: true, force: true });
  }
}

test("module-level read() BEFORE init() throws a friendly no-ceremony error and does NOT mint", async () => {
  await isolated(({ cwd }) => {
    // No ceremony anywhere in the discovery chain. read() must refuse to
    // mint and surface the friendly hint.
    assert.throws(
      () => [...tn.read()],
      /no ceremony found/i,
      "read() before init must throw the friendly no-ceremony error",
    );
    // Critically: nothing was minted. No identity, no .tn directory.
    assert.equal(
      existsSync(join(cwd, ".tn")),
      false,
      "read() must not create a .tn/ ceremony directory",
    );
    assert.equal(
      existsSync(join(cwd, "tn.yaml")),
      false,
      "read() must not create a tn.yaml",
    );
  });
});

test("module-level info() BEFORE init() auto-inits + emits (does not throw)", async () => {
  await isolated(({ cwd }) => {
    // First touch of the default singleton is an emit verb: it must
    // discover-or-MINT a ceremony and emit successfully.
    const receipt = tn.info("autoinit.smoke", { ok: 1 });
    assert.equal(typeof receipt.eventId, "string");
    assert.notEqual(receipt.eventId, "", "auto-init emit should return a real receipt");
    assert.equal(typeof receipt.rowHash, "string");

    // A ceremony was minted under the sandboxed cwd (project-root layout
    // `.tn/<cwd-name>/tn.yaml`).
    const tnRoot = join(cwd, ".tn");
    assert.ok(existsSync(tnRoot), "info() should auto-mint a .tn/ ceremony");
    const projects = readdirSync(tnRoot);
    assert.ok(projects.length >= 1, "expected at least one minted project ceremony");
  });
});

test("module-level read() AFTER an emit auto-init reads back the emitted entries", async () => {
  await isolated(() => {
    tn.info("autoinit.evt.a", { x: 1 });
    tn.info("autoinit.evt.b", { x: 2 });
    // read() now finds the freshly-minted default and load-only auto-init
    // binds to it (no second mint).
    const entries = [...tn.read({ raw: true })] as Array<Record<string, unknown>>;
    const types = entries.map((e) => String(e["event_type"]));
    assert.ok(types.includes("autoinit.evt.a"), `missing evt.a in ${JSON.stringify(types)}`);
    assert.ok(types.includes("autoinit.evt.b"), `missing evt.b in ${JSON.stringify(types)}`);
  });
});
