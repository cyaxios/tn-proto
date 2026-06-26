// `tn show env|profiles` — read-only config inspection.
//
//     tn show env [--yaml <path>] [--format human|json] [--json]
//     tn show profiles [--format human|json]
//
// `show env` prints a snapshot of the resolved ceremony configuration
// (me.did, ceremony.id/cipher/mode, keystore.path, logs.path, handler +
// public-field counts). Human-readable by DEFAULT (mirroring Python
// `cli_show.cmd_show_env`'s --format human default); `--json` (or
// `--format json`) selects the structured snapshot. `show profiles` delegates
// to the already-extracted `showProfilesCmd` (cli/show_profiles.ts), unchanged.
//
// NOTE: Python's `show env` renders the full canonical TN_* environment-schema
// inventory (and supports `--format env` for a paste-able block). The TS verb
// reflects a different data source — the live ceremony config snapshot — so it
// mirrors Python's human/json default behaviour but not the env-schema table
// or the `env` format (no schema inventory exists on the TS side).
//
// Sub-dispatch is over `argv[3]`, reading flags from `argv.slice(4)`,
// matching the .mjs indexing verbatim.

import { Tn } from "../tn.js";
import { showProfilesCmd } from "./show_profiles.js";

/** Print `tn-js: <msg>` to stderr and return exit code 2 — the
 *  value-returning analogue of the .mjs `die` so the caller owns
 *  process exit. */
function die(msg: string): number {
  process.stderr.write(`tn-js: ${msg}\n`);
  return 2;
}

/**
 * Execute `tn show env|profiles`. Takes the FULL process argv (`argv[3]` is
 * the subcommand, `argv.slice(4)` the flags), mirroring the .mjs indexing
 * verbatim. Returns the process exit code.
 */
export async function showCmd(argv: string[]): Promise<number> {
  const sub = argv[3];
  const rest = argv.slice(4);

  // show profiles: print the curated profile catalog. Wraps
  // cli/show_profiles.js. --format human (default) | json.
  if (sub === "profiles") {
    let format: "human" | "json" = "human";
    for (let i = 0; i < rest.length; i += 1) {
      if (rest[i] === "--format") format = rest[++i] as "human" | "json";
    }
    return showProfilesCmd({ format });
  }

  let yamlPath: string | null = null;
  // --format human|json (human default, mirroring Python); --json is a
  // convenience alias for --format json.
  let format: "human" | "json" = "human";
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--yaml") yamlPath = rest[++i] ?? null;
    else if (rest[i] === "--json") format = "json";
    else if (rest[i] === "--format") {
      const f = rest[++i];
      if (f === "json" || f === "human") format = f;
      else return die(`show env: unknown --format ${f}. use human | json.`);
    }
  }
  if (sub !== "env") {
    return die(
      `show: unknown subcommand ${sub}. try: show env [--yaml <path>] [--format human|json] [--json] | show profiles [--format human|json]`,
    );
  }
  const tn = await Tn.init(yamlPath ?? undefined);
  try {
    const cfg = tn.config();
    // Pick only the safe summary fields. TS NodeRuntime exposes config with
    // its own field shape (camelCase, flatter than the yaml). Mirror the
    // documented `show env` contract: a stable snapshot, not a raw dump.
    const c = (cfg ?? {}) as Record<string, unknown>;
    const device = c["device"] as Record<string, unknown> | undefined;
    const handlers = c["handlers"] as unknown[] | undefined;
    const publicFields = c["publicFields"];
    const publicFieldsCount = Array.isArray(publicFields)
      ? publicFields.length
      : publicFields && typeof publicFields === "object"
        ? Object.keys(publicFields).length
        : 0;
    const did =
      device && typeof device === "object" && typeof device["device_identity"] === "string"
        ? device["device_identity"]
        : null;
    const ceremonyId = typeof c["ceremonyId"] === "string" ? c["ceremonyId"] : null;
    const cipher = typeof c["cipher"] === "string" ? c["cipher"] : null;
    const mode = typeof c["mode"] === "string" ? c["mode"] : null;
    const keystorePath = typeof c["keystorePath"] === "string" ? c["keystorePath"] : null;
    const logPath = typeof c["logPath"] === "string" ? c["logPath"] : null;
    const handlersCount = Array.isArray(handlers) ? handlers.length : 0;

    if (format === "json") {
      process.stdout.write(
        JSON.stringify(
          {
            ok: true,
            me: { did },
            ceremony: { id: ceremonyId, cipher, mode },
            keystore: { path: keystorePath },
            logs: { path: logPath },
            handlers_count: handlersCount,
            public_fields_count: publicFieldsCount,
          },
          null,
          2,
        ) + "\n",
      );
    } else {
      // Human snapshot — labeled lines, ordered like the JSON snapshot.
      process.stdout.write("# tn show env — resolved ceremony config\n");
      process.stdout.write(`device:             ${did ?? "(none)"}\n`);
      process.stdout.write(`ceremony.id:        ${ceremonyId ?? "(none)"}\n`);
      process.stdout.write(`ceremony.cipher:    ${cipher ?? "(none)"}\n`);
      process.stdout.write(`ceremony.mode:      ${mode ?? "(none)"}\n`);
      process.stdout.write(`keystore.path:      ${keystorePath ?? "(none)"}\n`);
      process.stdout.write(`logs.path:          ${logPath ?? "(none)"}\n`);
      process.stdout.write(`handlers:           ${handlersCount}\n`);
      process.stdout.write(`public_fields:      ${publicFieldsCount}\n`);
    }
  } finally {
    await tn.close();
  }
  return 0;
}
