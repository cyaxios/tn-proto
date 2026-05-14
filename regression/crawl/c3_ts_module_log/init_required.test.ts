/**
 * SILO: C3 — TS module-level logging
 * TEST: bare verbs throw clearly when called before tn.init()
 * SEE: regression/crawl/c3_ts_module_log/README.md
 *
 * Asserts the developer-friendly failure mode: if a user reaches for
 * `tn.info(...)` without first calling `await tn.init(...)`, they get
 * a named error that points them at the fix. This is the kind of UX
 * gate that's easy to break silently and hard to notice — exactly the
 * shape the regression suite is for.
 *
 * Also asserts that calling `tn.init()` a second time closes the prior
 * default instance cleanly (re-init semantics, mirrors Python).
 *
 * Asserts (named):
 *   - "pre-init-info-throws": tn.info before init raises an error with
 *     a useful message
 *   - "pre-init-read-throws": same for tn.read
 *   - "post-close-info-throws": after tn.close, tn.info throws
 *   - "reinit-works": calling tn.init twice on the same module works
 */
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as tn from "../../../ts-sdk/src/index.ts";
import { NodeRuntime } from "../../../ts-sdk/src/index.ts";

import { assertNamed, setTestContext } from "../../_shared/assertions.js";

test("C3: tn.info before tn.init throws with a useful message", async () => {
  setTestContext({ silo: "c3", test: "c3_init_required::pre_init" });

  // The default singleton might be set from a previous test in this
  // file; explicitly close so we're in a known "no default" state.
  await tn.close();

  let captured: Error | null = null;
  try {
    tn.info("should.fail.before.init", {});
  } catch (e) {
    captured = e as Error;
  }

  assertNamed({
    name: "pre-init-info-throws",
    expected: "Error with init pointer",
    observed: captured === null ? "no-throw" : captured.message,
    onMiss:
      "tn.info() before tn.init() should throw a clear error pointing at init. " +
      "Check ts-sdk/src/index.ts:_requireDefault helper.",
    predicate: (_e, observed) =>
      typeof observed === "string" && /tn\.init/i.test(observed),
  });
});

test("C3: tn.read before tn.init throws too", async () => {
  setTestContext({ silo: "c3", test: "c3_init_required::pre_init_read" });
  await tn.close();

  let captured: Error | null = null;
  try {
    Array.from(tn.read());
  } catch (e) {
    captured = e as Error;
  }

  assertNamed({
    name: "pre-init-read-throws",
    expected: "Error with init pointer",
    observed: captured === null ? "no-throw" : captured.message,
    onMiss:
      "tn.read() before tn.init() should throw — the regression suite catches the silent-empty-iterator failure mode.",
    predicate: (_e, observed) =>
      typeof observed === "string" && /tn\.init/i.test(observed),
  });
});

test("C3: tn.close + tn.info throws; tn.init can be called again", async () => {
  setTestContext({ silo: "c3", test: "c3_init_required::reinit" });

  const td = mkdtempSync(join(tmpdir(), "c3-reinit-"));
  const yamlPath = join(td, "tn.yaml");
  NodeRuntime.init(yamlPath).close();

  await tn.init(yamlPath);
  tn.info("c3.reinit.first", {});
  await tn.close();

  // After close, info should throw.
  let captured: Error | null = null;
  try {
    tn.info("should.fail.after.close", {});
  } catch (e) {
    captured = e as Error;
  }
  assertNamed({
    name: "post-close-info-throws",
    expected: "Error with init pointer",
    observed: captured === null ? "no-throw" : captured.message,
    onMiss:
      "After tn.close(), tn.info() should throw the same not-initialized error as before tn.init(). " +
      "Check ts-sdk/src/index.ts:close resets the default to null.",
    predicate: (_e, observed) =>
      typeof observed === "string" && /tn\.init/i.test(observed),
  });

  // Reinit on a fresh ceremony.
  const td2 = mkdtempSync(join(tmpdir(), "c3-reinit-2-"));
  const yamlPath2 = join(td2, "tn.yaml");
  NodeRuntime.init(yamlPath2).close();

  let reinitErr: Error | null = null;
  try {
    await tn.init(yamlPath2);
    tn.info("c3.reinit.second", {});
  } catch (e) {
    reinitErr = e as Error;
  }
  assertNamed({
    name: "reinit-works",
    expected: null,
    observed: reinitErr,
    onMiss:
      "tn.init() should be callable a second time after tn.close(). " +
      "Check ts-sdk/src/index.ts:init handles _defaultTn already-null case.",
  });

  await tn.close();
});
