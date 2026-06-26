/**
 * Unit tests for `tn inbox list-local` (ts-sdk/src/cli/inbox_list_local.ts).
 *
 * Mirrors Python's `tn.inbox` `list-local` subcommand (python/tn/inbox.py:
 * `list_local` + `_cmd_list_local`). Drives the exported `inboxListLocalCmd`
 * with an injected stdout sink and asserts the same lines / exit code Python
 * prints, exercising every line of the command module:
 *   - a dir with matching zips (sorted, non-matching files filtered out)
 *   - an empty dir (the "No ... found in <dir>" branch with a custom --dir)
 *   - a missing dir (listLocal's `!existsSync` early-return → empty)
 *   - the default-`~/Downloads` branch + `~` expansion of `--dir`
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

import {
  inboxListLocalCmd,
  listLocal,
} from "../src/cli/inbox_list_local.js";

/** Run the verb, capturing everything written to the injected stdout sink. */
async function run(
  opts: Parameters<typeof inboxListLocalCmd>[0],
): Promise<{ code: number; out: string }> {
  let out = "";
  const code = await inboxListLocalCmd({
    ...opts,
    stdout: (s: string) => {
      out += s;
    },
  });
  return { code, out };
}

/** Make a throwaway directory; caller cleans it up. */
function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "tn-inbox-list-"));
}

test("list-local: lists matching zips, sorted, filtering non-matches", async () => {
  const dir = tmpDir();
  try {
    // Two matching invitation zips, written out of order...
    writeFileSync(join(dir, "tn-invite-02ZZ.zip"), "z");
    writeFileSync(join(dir, "tn-invite-01AA.zip"), "a");
    // ...plus files that must NOT match (wrong prefix, wrong suffix).
    writeFileSync(join(dir, "other-file.zip"), "x");
    writeFileSync(join(dir, "tn-invite-03.txt"), "x");

    const { code, out } = await run({ dir });
    assert.equal(code, 0);

    const lines = out.split("\n");
    // Header: "Found 2 invitation zip(s):"
    assert.equal(lines[0], "Found 2 invitation zip(s):");
    // Sorted ascending: 01AA before 02ZZ; each indented two spaces.
    assert.equal(lines[1], `  ${join(dir, "tn-invite-01AA.zip")}`);
    assert.equal(lines[2], `  ${join(dir, "tn-invite-02ZZ.zip")}`);
    // No non-matching file leaked into the output.
    assert.ok(!out.includes("other-file.zip"));
    assert.ok(!out.includes("tn-invite-03.txt"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("list-local: empty dir prints the not-found line naming that dir", async () => {
  const dir = tmpDir();
  try {
    const { code, out } = await run({ dir });
    assert.equal(code, 0);
    // Python: f"No tn-invite-*.zip files found in {d}" where d == resolved --dir.
    assert.equal(out, `No tn-invite-*.zip files found in ${dir}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("list-local: missing dir → not-found line (listLocal early-returns [])", async () => {
  const missing = join(tmpDir(), "does", "not", "exist");
  // listLocal itself returns [] for a non-existent directory.
  assert.deepEqual(listLocal(missing), []);

  const { code, out } = await run({ dir: missing });
  assert.equal(code, 0);
  assert.equal(out, `No tn-invite-*.zip files found in ${missing}\n`);
});

test("list-local: no --dir defaults to ~/Downloads in the not-found message", async () => {
  // When --dir is omitted, the displayed dir is ~/Downloads regardless of
  // whether that directory exists or what it contains. To get a deterministic
  // "not found" message we assert only the prefix/suffix shape (the real
  // Downloads dir may or may not hold zips on the runner).
  let out = "";
  const code = await inboxListLocalCmd({
    stdout: (s: string) => {
      out += s;
    },
  });
  assert.equal(code, 0);
  const downloads = join(homedir(), "Downloads");
  if (out.startsWith("No ")) {
    assert.equal(out, `No tn-invite-*.zip files found in ${downloads}\n`);
  } else {
    // If the runner happens to have invitation zips in ~/Downloads, the
    // header must still be the "Found N" form. Either way the default dir
    // resolved to ~/Downloads.
    assert.match(out, /^Found \d+ invitation zip\(s\):\n/);
  }
});

test("list-local: --dir with leading ~ expands to the home directory", async () => {
  // Create a sentinel dir under HOME, then reference it via "~/<name>".
  const name = `tn-inbox-tilde-${process.pid}-${Date.now()}`;
  const abs = join(homedir(), name);
  mkdirSync(abs, { recursive: true });
  try {
    writeFileSync(join(abs, "tn-invite-AAAA.zip"), "a");
    const { code, out } = await run({ dir: `~/${name}` });
    assert.equal(code, 0);
    assert.equal(out.split("\n")[0], "Found 1 invitation zip(s):");
    // The path printed is the home-resolved absolute path.
    assert.ok(out.includes(join(abs, "tn-invite-AAAA.zip")));
  } finally {
    rmSync(abs, { recursive: true, force: true });
  }
});

test("list-local: no injected stdout sink falls back to process.stdout", async () => {
  // Exercises the `opts.stdout ?? (...process.stdout.write)` default branch.
  const missing = join(tmpDir(), "absent");
  const orig = process.stdout.write.bind(process.stdout);
  let out = "";
  // @ts-expect-error — narrow write override for the duration of the call.
  process.stdout.write = (chunk: string | Uint8Array): boolean => {
    out += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  };
  let code: number;
  try {
    code = await inboxListLocalCmd({ dir: missing });
  } finally {
    process.stdout.write = orig;
  }
  assert.equal(code, 0);
  assert.equal(out, `No tn-invite-*.zip files found in ${missing}\n`);
});

test("list-local: --dir with a backslash ~\\ form also expands to HOME", async () => {
  // Covers the `p.startsWith("~\\")` arm of expanduser (Windows-style).
  const name = `tn-inbox-bs-${process.pid}-${Date.now()}`;
  const abs = join(homedir(), name);
  mkdirSync(abs, { recursive: true });
  try {
    writeFileSync(join(abs, "tn-invite-BBBB.zip"), "b");
    const { code, out } = await run({ dir: `~\\${name}` });
    assert.equal(code, 0);
    assert.equal(out.split("\n")[0], "Found 1 invitation zip(s):");
    assert.ok(out.includes(join(abs, "tn-invite-BBBB.zip")));
  } finally {
    rmSync(abs, { recursive: true, force: true });
  }
});

test("list-local: --dir of bare '~' expands to the home directory itself", async () => {
  // Covers the `if (p === "~") return homedir()` arm of expanduser. We don't
  // assert directory contents (HOME may hold anything); only that the bare
  // "~" resolves to HOME and the verb completes cleanly.
  const { code, out } = await run({ dir: "~" });
  assert.equal(code, 0);
  if (out.startsWith("No ")) {
    assert.equal(out, `No tn-invite-*.zip files found in ${homedir()}\n`);
  } else {
    assert.match(out, /^Found \d+ invitation zip\(s\):\n/);
  }
});

test("listLocal: default (no arg) scans ~/Downloads without throwing", () => {
  // Exercises the `downloadsDir ?? join(homedir(), "Downloads")` default
  // branch directly; result is an array (possibly empty) of absolute paths.
  const result = listLocal();
  assert.ok(Array.isArray(result));
  for (const p of result) {
    assert.ok(p.endsWith(".zip"));
  }
});
