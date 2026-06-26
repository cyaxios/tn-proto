import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";

import { createFreshCeremony } from "../src/runtime/node_runtime.js";
import { loadConfig } from "../src/runtime/config.js";

// Regression coverage for the Windows cross-drive yaml-path bug. On Windows,
// `path.relative(yamlDir, target)` does NOT throw when target is on a
// different drive; it returns the absolute target. createFreshCeremony must
// never serialize a drive-letter / UNC / POSIX-absolute path into the yaml
// (it is machine-local and leaks the author's filesystem layout), so it
// throws instead. Same-drive absolute paths still relativize to `./<rel>`.

// Matches a path that BEGINS with a drive-letter-absolute prefix, with an
// optional leading "./" or "/" that the serializer might have prepended.
const STARTS_WITH_DRIVE = /^\.?\/?[A-Za-z]:[\\/]/;

/** Pull the four serialized path fields out of a parsed ceremony yaml. */
function pathFields(doc: unknown): {
  logsPath: unknown;
  keystorePath: unknown;
  adminLogLocation: unknown;
  rotatingHandlerPath: unknown;
} {
  const d = doc as {
    logs: { path: unknown };
    keystore: { path: unknown };
    ceremony: { admin_log_location: unknown };
    handlers: ReadonlyArray<{ kind?: unknown; path?: unknown }>;
  };
  const rotating = d.handlers.find((h) => h.kind === "file.rotating");
  assert.ok(rotating, "expected a file.rotating handler in the generated yaml");
  return {
    logsPath: d.logs.path,
    keystorePath: d.keystore.path,
    adminLogLocation: d.ceremony.admin_log_location,
    rotatingHandlerPath: rotating.path,
  };
}

test("createFreshCeremony rejects cross-drive yaml paths (Windows guarantee)", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-yaml-portability-a-"));
  try {
    const yamlPath = join(dir, "tn.yaml");

    if (process.platform === "win32") {
      // On Windows these are genuine cross-drive (the temp dir is on the
      // runner's drive, almost never D:), so createFreshCeremony must
      // REJECT rather than serialize a drive-letter path. The rejection
      // surfaces either as the portable-path guard or, when the other drive
      // is absent, as a filesystem error from the early keystore mkdir;
      // both satisfy the guarantee that no drive-letter path is written.
      assert.throws(() =>
        createFreshCeremony(yamlPath, {
          keystoreDir: "D:\\b\\keys",
          logPath: "D:\\b\\logs\\tn.ndjson",
          adminLogPath: "D:\\b\\admin\\admin.ndjson",
        }),
      );
    } else {
      // On POSIX there is no second drive, so the cross-drive rejection
      // cannot be exercised — it is a Windows-specific guarantee. Passing
      // raw "D:\\b\\keys" strings here would be actively harmful: they are
      // not drive-absolute on POSIX, so createFreshCeremony's early
      // `mkdirSync` (which runs BEFORE relativization) would create a stray
      // directory literally named `D:\b\keys` under the CWD (ts-sdk/), which
      // the tmpdir `finally` does not clean up — leaking the keystore into
      // the repo and tripping the clobber guard on the next run. Instead we
      // root the overrides INSIDE the tmpdir (absolute, same-volume) and
      // assert the invariant that holds everywhere: an absolute path never
      // serializes as drive-absolute; it is relativized against the yaml dir.
      createFreshCeremony(yamlPath, {
        keystoreDir: join(dir, "keys"),
        logPath: join(dir, "logs", "tn.ndjson"),
        adminLogPath: join(dir, "admin", "admin.ndjson"),
      });
      const doc = parseYaml(readFileSync(yamlPath, "utf8"));
      const f = pathFields(doc);
      for (const v of [
        f.logsPath,
        f.keystorePath,
        f.adminLogLocation,
        f.rotatingHandlerPath,
      ]) {
        assert.equal(typeof v, "string");
        assert.doesNotMatch(v as string, STARTS_WITH_DRIVE);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("createFreshCeremony relativizes same-drive absolute yaml paths", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-yaml-portability-b-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    // All on the same drive/volume as the ceremony yaml -> must relativize.
    createFreshCeremony(yamlPath, {
      keystoreDir: join(dir, "keys"),
      logPath: join(dir, "logs", "tn.ndjson"),
      adminLogPath: join(dir, "admin", "admin.ndjson"),
    });

    const doc = parseYaml(readFileSync(yamlPath, "utf8"));
    const f = pathFields(doc);
    const fields = [
      f.logsPath,
      f.keystorePath,
      f.adminLogLocation,
      f.rotatingHandlerPath,
    ];

    for (const v of fields) {
      assert.equal(typeof v, "string");
      const s = v as string;
      // Relative, separator-normalized.
      assert.ok(s.startsWith("./"), `expected ${JSON.stringify(s)} to start with "./"`);
      // Shared assertion: no drive-letter absolute, no raw drive token.
      assert.doesNotMatch(s, STARTS_WITH_DRIVE);
      assert.ok(!s.includes(":/"), `expected no ":/" drive token in ${JSON.stringify(s)}`);
      assert.ok(!s.includes(":\\"), `expected no ":\\\\" drive token in ${JSON.stringify(s)}`);
    }

    // The yaml must still load.
    const cfg = loadConfig(yamlPath);
    assert.ok(cfg);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
