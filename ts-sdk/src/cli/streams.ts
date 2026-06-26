// `tn streams` — list ceremonies under `.tn/` for the project. TypeScript
// port of the inline `streamsCmd` from `bin/tn-js.mjs`, which mirrors
// Python's `tn streams` subcommand (python/tn/cli.py:cmd_streams).
//
// The inline version did `await import("node:fs")` / `await import("node:path")`
// at call time; those are hoisted here to static top-of-file imports.
//
// stdout is byte-for-byte identical to the inline version (the spawn tests in
// test/cli_streams_validate.test.ts assert exact output and exit codes). The
// dispatcher parses argv into {@link StreamsOptions}; this module owns no argv.

import { existsSync, readFileSync } from "node:fs";
import { join, resolve as pathResolve } from "node:path";
import { parse as parseYaml } from "yaml";

import { ceremonyYamlPath, listCeremoniesOnDisk } from "../multi.js";

/** Options for {@link streamsCmd}, one-to-one with the CLI flags
 *  (`--project-dir`, `--format`). */
export interface StreamsOptions {
  /** Project directory to scan (`--project-dir`); default = cwd. */
  projectDir?: string | null;
  /** Output format (`--format`): "human" (default) or "json". */
  format?: string;
}

interface StreamRow {
  name: string;
  profile: string;
  yaml_path: string;
}

/**
 * Execute `tn streams`. Returns the process exit code (always 0), mirroring
 * the inline `streamsCmd`.
 */
export async function streamsCmd(opts: StreamsOptions): Promise<number> {
  const projectDir = opts.projectDir ? pathResolve(opts.projectDir) : process.cwd();
  const format = opts.format ?? "human";
  const root = join(projectDir, ".tn");

  const rows: StreamRow[] = [];
  if (existsSync(root)) {
    // Use the shared on-disk lister (mirrors python _layout.list_ceremonies_on_disk)
    // and parse each yaml for `ceremony.profile` — the prior regex matched any
    // indented `profile:` anywhere in the file, which could surface the wrong key.
    for (const name of listCeremoniesOnDisk(projectDir)) {
      const yp = ceremonyYamlPath(name, projectDir);
      let profile = "(unspecified)";
      try {
        const doc = (parseYaml(readFileSync(yp, "utf8")) as Record<string, unknown> | null) ?? {};
        const ceremony = doc["ceremony"];
        const p =
          ceremony && typeof ceremony === "object"
            ? (ceremony as Record<string, unknown>)["profile"]
            : undefined;
        if (typeof p === "string" && p) profile = p;
      } catch {
        // parse/read failure — leave as "(unspecified)" (mirrors Python's except).
      }
      rows.push({ name, profile, yaml_path: yp });
    }
  }

  if (format === "json") {
    process.stdout.write(JSON.stringify(rows, null, 2) + "\n");
    return 0;
  }
  if (rows.length === 0) {
    process.stdout.write(`(no ceremonies found under ${root})\n`);
    return 0;
  }
  const nameW = Math.max(4, ...rows.map((r) => r.name.length));
  const profW = Math.max(7, ...rows.map((r) => r.profile.length));
  process.stdout.write(
    `${"NAME".padEnd(nameW)}  ${"PROFILE".padEnd(profW)}  YAML\n`,
  );
  process.stdout.write(
    `${"-".repeat(nameW)}  ${"-".repeat(profW)}  ----\n`,
  );
  for (const r of rows) {
    process.stdout.write(
      `${r.name.padEnd(nameW)}  ${r.profile.padEnd(profW)}  ${r.yaml_path}\n`,
    );
  }
  return 0;
}
