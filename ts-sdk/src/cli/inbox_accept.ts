// `tn inbox accept <zip> [--yaml]` — accept an invitation zip locally and
// install the kit it carries. TypeScript parity port of Python's
// `tn.inbox accept` subcommand (python/tn/inbox.py): the `accept(...)`
// function, the `_cmd_accept` wrapper, and the `main()` dispatch's accept
// branch (the InboxError → stderr → exit 1 envelope). Behaviour, flags,
// stdout, and exit codes match the Python verb line-for-line.
//
// Frank runs this on his laptop after downloading a `tn-invite-<id>.zip`
// from the vault. No vault contact during acceptance — entirely local.
// The outer invitation zip carries `manifest.json` (group_name, leaf_index,
// from_email, from_account_did, kit_sha256) plus the inner `kit.tnpkg`. We
// verify the kit's sha256 against the manifest, install it as
// `<group_name>.btn.mykit` under the ceremony's keystore dir (backing up any
// prior kit to `.previous.<UTC_TS>`), then emit a `tn.enrolment.absorbed`
// attestation to the local log (non-fatal — the kit is installed regardless).
//
// The verb is a standalone, dependency-injectable function so it can be
// unit-tested in-process (no subprocess). It owns no argv parsing; the
// caller resolves flags into the explicit `InboxAcceptCmdOptions` shape.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve as pathResolve } from "node:path";

import { parseTnpkg } from "../core/tnpkg_archive.js";
import { Tn } from "../tn.js";

/** Raised when an inbox operation fails for a user-visible reason. The
 *  command wrapper catches this and maps it to `Error: <msg>` on stderr +
 *  exit 1. Mirrors `python/tn/inbox.py::InboxError`. */
export class InboxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InboxError";
  }
}

/** Result of a successful {@link accept}. Mirrors the dict Python's
 *  `accept(...)` returns: group_name, leaf_index, from_email, kit_path,
 *  absorbed_at. */
export interface AcceptResult {
  groupName: string;
  leafIndex: unknown;
  fromEmail: string;
  kitPath: string;
  absorbedAt: string;
}

/** Options for {@link inboxAcceptCmd}. Mirrors the Python `p_accept`
 *  parser: positional `zip`; flag `--yaml`. */
export interface InboxAcceptCmdOptions {
  /** Path to the `tn-invite-*.zip` (the positional `zip` argument). */
  zipPath: string;
  /** Path to Frank's `tn.yaml`. Defaults to `./tn.yaml` in cwd. */
  yaml?: string;
  /** Sink for normal output. Defaults to `process.stdout.write`. Injected
   *  so tests can capture without poking global streams. */
  stdout?: (line: string) => void;
  /** Sink for error output. Defaults to `process.stderr.write`. */
  stderr?: (line: string) => void;
}

function nowIso(): string {
  return new Date().toISOString();
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** A UTC `YYYYMMDDTHHMMSSZ` timestamp for the `.previous.<ts>` backup name.
 *  Matches Python's `strftime("%Y%m%dT%H%M%SZ")`. */
function backupStamp(): string {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

/** Verify `kitBytes` matches the sha256 recorded in the manifest. No-op when
 *  the manifest carries no `kit_sha256`. Mirrors `_verify_kit_hash`. */
function verifyKitHash(kitBytes: Uint8Array, manifest: Record<string, unknown>): void {
  const expected = String(manifest["kit_sha256"] ?? "");
  if (!expected) return; // no hash in manifest; skip verification
  const expectedHex = expected.startsWith("sha256:")
    ? expected.slice("sha256:".length)
    : expected;
  const actual = sha256Hex(kitBytes);
  if (actual !== expectedHex) {
    throw new InboxError(
      `Kit hash mismatch.\n` +
        `  Expected: ${expectedHex}\n` +
        `  Got:      ${actual}\n` +
        "The zip may be corrupted. Re-download from the vault.",
    );
  }
}

/**
 * Unzip an invitation, verify the kit, install it, and emit an attested
 * event. Mirrors `python/tn/inbox.py::accept`.
 *
 * @param zipPath Absolute path to the `tn-invite-<id>.zip`.
 * @param yamlPath Absolute path to Frank's `tn.yaml`, or `null` to default
 *   to `./tn.yaml` in cwd.
 * @param out Sink for the (non-fatal) backup / warning lines `accept` prints
 *   directly, matching Python's bare `print(...)` calls inside the function.
 * @returns An {@link AcceptResult}.
 * @throws {InboxError} on any user-visible failure (missing zip/yaml, bad
 *   zip, missing manifest/kit, hash mismatch).
 */
export async function accept(
  zipPath: string,
  yamlPath: string | null,
  out: (line: string) => void,
): Promise<AcceptResult> {
  if (!existsSync(zipPath)) {
    throw new InboxError(`Zip not found: ${zipPath}`);
  }

  const resolvedYaml = yamlPath ?? pathResolve("tn.yaml");
  if (!existsSync(resolvedYaml)) {
    throw new InboxError(
      `tn.yaml not found at ${resolvedYaml}. ` +
        "Run from a directory with a ceremony, or pass --yaml <path>.",
    );
  }

  // 1. Read + unzip the outer invitation zip (in-memory; parseTnpkg accepts
  //    the same STORED/DEFLATE subset Python's zipfile produces).
  let entries: ReturnType<typeof parseTnpkg>;
  try {
    entries = parseTnpkg(new Uint8Array(readFileSync(zipPath)));
  } catch (exc) {
    const msg = exc instanceof Error ? exc.message : String(exc);
    throw new InboxError(`Invalid zip file: ${msg}`);
  }
  const byName = new Map(entries.map((e) => [e.name, e.data]));

  // 2. Read manifest.
  const manifestBytes = byName.get("manifest.json");
  if (manifestBytes === undefined) {
    throw new InboxError("Invalid invitation zip: missing manifest.json");
  }
  const manifest = JSON.parse(new TextDecoder("utf-8").decode(manifestBytes)) as Record<
    string,
    unknown
  >;

  const groupName = String(manifest["group_name"] ?? "default");
  const leafIndex = manifest["leaf_index"];
  const fromEmail = String(manifest["from_email"] ?? "unknown");
  const fromDid = String(manifest["from_account_did"] ?? "");
  const kitSha256 = String(manifest["kit_sha256"] ?? "");

  // 3. Read and verify kit bytes.
  const kitBytes = byName.get("kit.tnpkg");
  if (kitBytes === undefined) {
    throw new InboxError("Invalid invitation zip: missing kit.tnpkg");
  }
  verifyKitHash(kitBytes, manifest);

  // 4. Load Frank's ceremony. config().keystorePath resolves the yaml's
  //    `keystore.path` (default ./.tn/keys), and logPath resolves
  //    `logs.path` — the same fields Python honors (FINDINGS #2).
  let tn: Tn;
  try {
    tn = await Tn.init(resolvedYaml);
  } catch (exc) {
    const msg = exc instanceof Error ? exc.message : String(exc);
    throw new InboxError(`Could not read tn.yaml: ${msg}`);
  }

  let absorbedAt: string;
  let kitDest: string;
  try {
    const cfg = tn.config() as { keystorePath: string };
    const keystoreDir = cfg.keystorePath;
    mkdirSync(keystoreDir, { recursive: true });

    // 5. Install kit: rename existing to .previous.<timestamp>, then write.
    kitDest = join(keystoreDir, `${groupName}.btn.mykit`);
    if (existsSync(kitDest)) {
      const ts = backupStamp();
      const previous = `${kitDest}.previous.${ts}`;
      renameSync(kitDest, previous);
      out(`  (Backed up existing kit to ${groupName}.btn.mykit.previous.${ts})\n`);
    }
    writeFileSync(kitDest, kitBytes);

    // 6. Emit tn.enrolment.absorbed to Frank's local log.
    absorbedAt = nowIso();
    try {
      tn.info("tn.enrolment.absorbed", {
        group: groupName,
        from_did: fromDid,
        package_sha256: kitSha256,
        absorbed_at: absorbedAt,
      });
    } catch (exc) {
      // Non-fatal: kit is already installed. Warn and continue.
      const msg = exc instanceof Error ? exc.message : String(exc);
      out(
        `  Warning: could not emit tn.enrolment.absorbed: ${msg}\n` +
          "  The kit is installed. You may emit the attestation manually.\n",
      );
    }
  } finally {
    await tn.close();
  }

  return {
    groupName,
    leafIndex,
    fromEmail,
    kitPath: kitDest,
    absorbedAt,
  };
}

/**
 * `tn inbox accept` verb. Returns the process exit code (0 on success, 1 on
 * an `InboxError`). Mirrors `_cmd_accept` (the stdout) wrapped in `main()`'s
 * accept branch (the InboxError → `Error: <msg>` on stderr → exit 1).
 *
 * @param opts See {@link InboxAcceptCmdOptions}.
 */
export async function inboxAcceptCmd(opts: InboxAcceptCmdOptions): Promise<number> {
  const out = opts.stdout ?? ((s: string) => void process.stdout.write(s));
  const err = opts.stderr ?? ((s: string) => void process.stderr.write(s));

  const zipPath = pathResolve(opts.zipPath);
  const yamlPath = opts.yaml ? pathResolve(opts.yaml) : null;

  const zipName = zipPath.replace(/^.*[/\\]/, "");
  out(`Accepting invitation from ${zipName} ...\n`);

  let result: AcceptResult;
  try {
    result = await accept(zipPath, yamlPath, out);
  } catch (exc) {
    if (exc instanceof InboxError) {
      err(`Error: ${exc.message}\n`);
      return 1;
    }
    throw exc;
  }

  out(
    `\nInstalled kit for group '${result.groupName}' ` +
      `(leaf ${result.leafIndex}) from ${result.fromEmail}.\n`,
  );
  out(`Kit written to: ${result.kitPath}\n`);
  out(`Absorbed at:    ${result.absorbedAt}\n`);
  out("\nReady to read. Try:\n");
  out(
    "  node -e \"import('@tnproto/sdk').then(async (m) => { const tn = await m.Tn.init('./tn.yaml'); for (const e of tn.read('../alice/.tn/logs/tn.ndjson')) console.log(String(e)); })\"\n",
  );
  return 0;
}
