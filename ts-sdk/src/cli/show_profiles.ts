// Print the profile catalog as a table or JSON.

import {
  allProfileNames,
  getProfile,
  DEFAULT_PROFILE,
  type Profile,
} from "../profiles.js";

/** Options for {@link showProfilesCmd}, one-to-one with the CLI flags. */
export interface ShowProfilesOptions {
  /**
   * Output format (`--format`): `human` (default) for the pretty table +
   * descriptions, `json` for programmatic use. Mirrors Python's choices.
   */
  format?: "human" | "json";
}

/** One column of the human table: header label and fixed width. */
interface Column {
  readonly label: string;
  readonly width: number;
}

// Column widths — byte-for-byte the same as Python's `cols`.
const COLS: ReadonlyArray<Column> = [
  { label: "NAME", width: 12 },
  { label: "ENCRYPTS", width: 8 },
  { label: "SIGNS", width: 5 },
  { label: "CHAINS", width: 6 },
  { label: "SINK", width: 14 },
];

/** Left-justify `s` to width `w` with spaces (Python's `f"{s:<{w}}"`). */
function ljust(s: string, w: number): string {
  return s.length >= w ? s : s + " ".repeat(w - s.length);
}

/**
 * Execute `tn show profiles`. Returns the process exit code (0 on
 * success), mirroring Python's `cmd_show_profiles`.
 */
export async function showProfilesCmd(opts: ShowProfilesOptions): Promise<number> {
  // Python: fmt = getattr(args, "format", "human") or "human"
  const fmt = opts.format ?? "human";

  const names = allProfileNames();
  const profiles: Profile[] = names.map((n) => getProfile(n));

  if (fmt === "json") {
    // Python: json.dumps({"profiles": payload}, indent=2) + "\n"
    const payload = profiles.map((p) => ({
      name: p.name,
      encrypts: p.encrypts,
      signs: p.signs,
      chains: p.chains,
      default_sink: p.default_sink,
      intended_use: p.intended_use,
      default: p.name === DEFAULT_PROFILE,
    }));
    process.stdout.write(JSON.stringify({ profiles: payload }, null, 2) + "\n");
    return 0;
  }

  // human table — header + separator rule.
  const header = COLS.map((c) => ljust(c.label, c.width)).join("  ");
  process.stdout.write(header + "\n");
  process.stdout.write(COLS.map((c) => "-".repeat(c.width)).join("  ") + "\n");

  for (const p of profiles) {
    // Python: marker = "*" if default else " "; the marker is appended to
    // the name BEFORE the 12-wide left-justify.
    const marker = p.name === DEFAULT_PROFILE ? "*" : " ";
    process.stdout.write(
      `${ljust(p.name + marker, 12)}  ` +
        `${ljust(p.encrypts ? "yes" : "no", 8)}  ` +
        `${ljust(p.signs ? "yes" : "no", 5)}  ` +
        `${ljust(p.chains ? "yes" : "no", 6)}  ` +
        `${ljust(p.default_sink, 14)}\n`,
    );
  }

  process.stdout.write(
    "\n* = catalog default (used when tn.init() is called with no profile=).\n\n",
  );

  // Intended-use details below the table.
  for (const p of profiles) {
    process.stdout.write(`${p.name}: ${p.intended_use}\n\n`);
  }
  return 0;
}
