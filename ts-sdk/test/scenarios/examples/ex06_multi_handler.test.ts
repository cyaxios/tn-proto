// Scenario ex06 — yaml-driven multi-handler fan-out with event_type filters.
//
// Python original: tn_proto/python/examples/ex06_multi_handler.py
//
// What this tests:
//   1. Registry recognises `kind: file.rotating` and wires it to FileHandler.
//   2. `Tn.init(yamlPath)` calls buildHandlers so yaml-declared handlers are
//      live fan-out targets (previously these were only informational).
//   3. filter.event_type.starts_with is translated to FilterSpec.eventTypePrefix
//      by the registry's parseFilter helper.
//   4. Three-way fan-out: "everything" (no filter), "auth_stream"
//      (auth.* prefix), "pages_only" (page.* prefix) each write to their
//      own files. Emitting 6 user events yields:
//        tn.ndjson     — 6 lines  (all user events)
//        auth.ndjson   — 2 lines  (auth.login, auth.failed)
//        pages.ndjson  — 2 lines  (page.view × 2)
//
// NOTE: uses `file.rotating` in place of Python's `file.timed_rotating`
// (timed rotation is not yet ported to TS). Fan-out behaviour is identical.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { Tn } from "../../../src/tn.js";

test("ex06/multi-handler-fan-out — yaml file.rotating handlers with event_type filters", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "tn-ex06-"));
  try {
    const yamlPath = join(tmpDir, "tn.yaml");

    // Step 1: mint a fresh ceremony. This creates tn.yaml + keystore.
    const tn0 = await Tn.init(yamlPath, { stdout: false });
    await tn0.close();

    // Step 2: replace the auto-generated `handlers:` block with three
    // fan-out handlers. The fresh yaml already contains a `handlers:` section;
    // we strip it (and everything that follows, since handlers is the last
    // top-level key) and replace it with our three entries.
    // Paths are relative to yamlDir; they differ from the main log path
    // (.tn/tn/logs/tn.ndjson) to avoid double-writes.
    const newHandlerBlock = `handlers:
  - name: everything
    kind: file.rotating
    path: ./.tn/logs/tn.ndjson
    max_bytes: 524288
    backup_count: 7
  - name: auth_stream
    kind: file.rotating
    path: ./.tn/logs/auth.ndjson
    max_bytes: 524288
    backup_count: 7
    filter:
      event_type:
        starts_with: "auth."
  - name: pages_only
    kind: file.rotating
    path: ./.tn/logs/pages.ndjson
    max_bytes: 524288
    backup_count: 7
    filter:
      event_type:
        starts_with: "page."
`;
    const originalYaml = readFileSync(yamlPath, "utf8");
    // Replace the handlers: block. The auto-generated yaml places `handlers:`
    // between `keystore:` and `me:`. We strip the entire handlers block
    // (from `^handlers:` up to but not including the next top-level key) and
    // replace it with the three fan-out entries.
    const withoutHandlers = originalYaml.replace(/^handlers:(?:\n(?![\w#])[^\n]*)*\n?/m, "");
    writeFileSync(yamlPath, withoutHandlers + newHandlerBlock, "utf8");

    // Step 3: re-init with the updated yaml so the new handlers are wired.
    const tn = await Tn.init(yamlPath, { stdout: false });

    // Step 4: emit 6 user events across three event types.
    tn.info("app.booted", {});
    tn.info("auth.login", {});
    tn.info("page.view", {});
    tn.info("auth.failed", {});
    tn.info("page.view", {});
    tn.info("app.metric", {});

    await tn.close();

    // Step 5: read each fan-out log file and count user events (exclude tn.*).
    function countUserLines(filePath: string): number {
      if (!existsSync(filePath)) return 0;
      const content = readFileSync(filePath, "utf8").trim();
      if (!content) return 0;
      return content
        .split("\n")
        .filter((line) => {
          const trimmed = line.trim();
          if (!trimmed) return false;
          try {
            const env = JSON.parse(trimmed) as Record<string, unknown>;
            return !String(env["event_type"] ?? "").startsWith("tn.");
          } catch {
            return false;
          }
        }).length;
    }

    const tnLog = join(tmpDir, ".tn/logs/tn.ndjson");
    const authLog = join(tmpDir, ".tn/logs/auth.ndjson");
    const pagesLog = join(tmpDir, ".tn/logs/pages.ndjson");

    const tnCount = countUserLines(tnLog);
    const authCount = countUserLines(authLog);
    const pagesCount = countUserLines(pagesLog);

    assert.equal(tnCount, 6, `expected 6 user events in tn.ndjson, got ${tnCount}`);
    assert.equal(authCount, 2, `expected 2 user events in auth.ndjson (auth.login + auth.failed), got ${authCount}`);
    assert.equal(pagesCount, 2, `expected 2 user events in pages.ndjson (page.view × 2), got ${pagesCount}`);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
