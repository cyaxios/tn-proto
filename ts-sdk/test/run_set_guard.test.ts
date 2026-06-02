import { test } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Guard against the "orphaned test file" problem: a *.test.ts can be added
// to test/ but forgotten in the package.json "test" script, so it never runs
// in CI and silently provides zero coverage (this is how 10 files drifted
// out of the run set). This test fails if any test file on disk is missing
// from the run set — unless it's explicitly allowlisted below with a reason.

const _here = dirname(fileURLToPath(import.meta.url));
const _pkgPath = join(_here, "..", "package.json");

// Files intentionally NOT in the run set. Each MUST have a reason.
const ALLOWLIST: Record<string, string> = {
  "test/wasm_runtime_smoke.test.ts":
    "smoke test for the wasm runtime, which is on the deprecation path " +
    "(see plans/2026-05-13-wasm-widen-and-fallback-deprecate.md); not worth " +
    "reviving its drifted read-shape assertions.",
};

function runSet(): Set<string> {
  const pkg = JSON.parse(readFileSync(_pkgPath, "utf8")) as { scripts: { test: string } };
  const matches = pkg.scripts.test.match(/test\/[\w/]+\.test\.ts/g) ?? [];
  return new Set(matches);
}

function testFilesOnDisk(): string[] {
  const root = join(_here);
  const out: string[] = [];
  const walk = (dir: string, rel: string) => {
    for (const name of readdirSync(dir, { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${name.name}` : name.name;
      if (name.isDirectory()) walk(join(dir, name.name), childRel);
      else if (name.name.endsWith(".test.ts")) out.push(`test/${childRel}`);
    }
  };
  walk(root, "");
  return out;
}

test("every test file on disk is in the package.json run set (or allowlisted)", () => {
  const run = runSet();
  const disk = testFilesOnDisk();
  const missing = disk.filter((f) => !run.has(f) && !(f in ALLOWLIST));
  assert.deepEqual(
    missing,
    [],
    `these test files exist on disk but are NOT in the package.json "test" script ` +
      `(so they never run in CI). Add them to the run set, or allowlist them with a ` +
      `reason in run_set_guard.test.ts:\n  ${missing.join("\n  ")}`,
  );
});

test("allowlisted files actually exist (no stale allowlist entries)", () => {
  const disk = new Set(testFilesOnDisk());
  const stale = Object.keys(ALLOWLIST).filter((f) => !disk.has(f));
  assert.deepEqual(stale, [], `allowlist references files that no longer exist: ${stale.join(", ")}`);
});
