// `tn validate` — static check of the project's `.tn/` tree. TypeScript
// port of Python's `tn validate` subcommand (python/tn/cli_introspect.py:
// cmd_validate and its `_validate_*` helpers).
//
// Five per-ceremony checks run, accumulating into `errors`/`warnings`:
//   1. required top-level sections (+ legacy `me:` block rejection)
//   2. required sub-keys (ceremony.id always; logs.path / keystore.path /
//      device.device_identity for non-stream yamls)
//   3. ceremony.profile must be in the SDK catalog when present
//   4. each declared btn group must have a non-empty publisher self-kit
//      `<group>.btn.mykit` on disk
//   5. yaml device.device_identity must match the keystore's
//      keys/local.public did:key
//
// A yaml carrying `extends:` is a *stream*: its required sections/sub-keys
// narrow to just `ceremony` (identity/logs/keystore/groups are inherited
// from the parent it extends).
//
// All module imports are static (no inline `await import`). Profiles come
// from the SOURCE `../profiles.js`; layout helpers from `../multi.js`; yaml
// from "yaml"; fs/path from node builtins.
//
// stderr lines are `WARNING: ...` / `ERROR: ...`; on success stdout gets the
// `OK: N ceremon...` line. Exit code is 0 when clean (or nothing to
// validate), 1 when any errors accumulate. Where Python `print(..., file=
// sys.stderr)` + `return 1`, this returns the exit code — the dispatcher
// owns the process exit.

import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve as pathResolve } from "node:path";
import { parse as parseYaml } from "yaml";

import { isKnownProfile, allProfileNames } from "../profiles.js";
import { listCeremoniesOnDisk, ceremonyYamlPath, tnRoot } from "../multi.js";

/** Options for {@link validateCmd}, one-to-one with the CLI flags
 *  (`--project-dir`). */
export interface ValidateOptions {
  /** Project directory to validate (`--project-dir`); default = cwd. */
  projectDir?: string | null;
}

type YamlDoc = Record<string, unknown>;

function asRecord(v: unknown): YamlDoc | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as YamlDoc) : null;
}

/**
 * Required top-level sections (narrower for `extends:` streams) + the legacy
 * `me:` block rejection. Mirrors `_validate_required_sections`.
 */
function validateRequiredSections(doc: YamlDoc, yamlPath: string, isStream: boolean): string[] {
  const errors: string[] = [];
  const requiredTop: string[] = ["ceremony"];
  if (!isStream) {
    requiredTop.push("logs", "keystore", "device", "groups");
    if ("me" in doc && !("device" in doc)) {
      errors.push(
        `${yamlPath}: legacy \`me:\` top-level block is no longer ` +
          `supported (0.4.3a1 renamed it to \`device:\`). Replace ` +
          `\`device: {device_identity: ...}\` with \`device: {device_identity: ...}\`.`,
      );
    }
  }
  for (const key of requiredTop) {
    if (!(key in doc)) {
      errors.push(
        `${yamlPath}: missing required top-level key ` +
          `'${key}'. A yaml that parses but lacks ` +
          `required sections will fail at init time with ` +
          `a confusing error; declare '${key}' or add an ` +
          `\`extends:\` pointing at a yaml that does.`,
      );
    }
  }
  return errors;
}

/**
 * Runtime-depended sub-keys: ceremony.id always; logs.path / keystore.path /
 * device.device_identity for non-stream yamls. Mirrors `_validate_subkeys`.
 */
function validateSubkeys(doc: YamlDoc, yamlPath: string, isStream: boolean): string[] {
  const errors: string[] = [];
  const ceremony = asRecord(doc.ceremony);
  if (ceremony && !("id" in ceremony)) {
    errors.push(`${yamlPath}: ceremony.id is required`);
  }
  if (!isStream) {
    const logs = asRecord(doc.logs);
    if (logs && !("path" in logs)) {
      errors.push(`${yamlPath}: logs.path is required`);
    }
    const keystore = asRecord(doc.keystore);
    if (keystore && !("path" in keystore)) {
      errors.push(`${yamlPath}: keystore.path is required`);
    }
    const device = asRecord(doc.device);
    if (device && !("device_identity" in device)) {
      errors.push(`${yamlPath}: device.device_identity is required`);
    }
  }
  return errors;
}

/** ceremony.profile must be in the SDK catalog when present. Mirrors
 *  `_validate_profile`. */
function validateProfile(doc: YamlDoc, yamlPath: string): string[] {
  const ceremony = asRecord(doc.ceremony) ?? {};
  const profile = ceremony.profile;
  if (profile !== undefined && profile !== null && !isKnownProfile(profile as string)) {
    return [
      `${yamlPath}: unknown profile ${JSON.stringify(profile)}; ` +
        `catalog: ${JSON.stringify(allProfileNames())}`,
    ];
  }
  return [];
}

/**
 * Each declared btn group must have a non-empty publisher self-kit on disk,
 * else the publisher silently fails to decrypt its own emits. Mirrors
 * `_validate_group_kits`.
 */
function validateGroupKits(doc: YamlDoc, yamlPath: string): string[] {
  const errors: string[] = [];
  const groupsDict = asRecord(doc.groups);
  const keystoreBlock = asRecord(doc.keystore);
  if (!groupsDict || !keystoreBlock || !("path" in keystoreBlock)) {
    return errors;
  }
  const rawPath = keystoreBlock.path;
  if (typeof rawPath !== "string" || !rawPath) {
    return errors;
  }
  const yamlDir = join(yamlPath, "..");
  const ksPath = isAbsolute(rawPath) ? rawPath : pathResolve(yamlDir, rawPath);
  const ceremony = asRecord(doc.ceremony) ?? {};
  for (const [gname, gspecRaw] of Object.entries(groupsDict)) {
    const gspec = asRecord(gspecRaw);
    if (!gspec) continue;
    const cipher = (gspec.cipher ?? ceremony.cipher ?? "btn") as string;
    if (cipher !== "btn") continue;
    const kitFile = join(ksPath, `${gname}.btn.mykit`);
    if (!existsSync(kitFile) || !statSync(kitFile).isFile()) {
      errors.push(
        `${yamlPath}: group '${gname}' kit missing: ` +
          `${kitFile}. Without the publisher self-kit ` +
          `the runtime will silently fail to decrypt ` +
          `its own emits. Re-init the ceremony or ` +
          `absorb a fresh kit bundle.`,
      );
    } else if (statSync(kitFile).size === 0) {
      errors.push(
        `${yamlPath}: group '${gname}' kit is empty: ` +
          `${kitFile}. Same effect as missing — ` +
          `emits will be unreadable by the publisher.`,
      );
    }
  }
  return errors;
}

/**
 * Resolve the path to `local.public` for the ceremony at `yamlPath`, mirroring
 * `_validate_resolve_keystore_pub`: keystore.path (relative to the yaml dir)
 * if present, else `<yaml_dir>/keys`, then `/local.public`.
 */
function resolveKeystorePub(doc: YamlDoc, yamlPath: string): string {
  const yamlDir = join(yamlPath, "..");
  const keystoreSection = asRecord(doc.keystore);
  const rawPath = keystoreSection ? keystoreSection.path : undefined;
  let keystoreDir: string;
  if (typeof rawPath === "string" && rawPath) {
    keystoreDir = pathResolve(yamlDir, rawPath);
  } else {
    keystoreDir = join(yamlDir, "keys");
  }
  return join(keystoreDir, "local.public");
}

/**
 * yaml device.device_identity must match the keystore's local.public did:key.
 * Mirrors `_validate_did_consistency`.
 */
function validateDidConsistency(doc: YamlDoc, yamlPath: string): string[] {
  const keystorePub = resolveKeystorePub(doc, yamlPath);
  if (!existsSync(keystorePub) || !statSync(keystorePub).isFile()) {
    return [];
  }
  let derivedDid: string;
  try {
    derivedDid = readFileSync(keystorePub, "ascii").trim();
  } catch (e) {
    return [`${yamlPath}: could not read keystore ${keystorePub}: ${(e as Error).message}`];
  }
  const device = asRecord(doc.device) ?? {};
  const yamlDid = device.device_identity;
  if (typeof yamlDid === "string" && yamlDid && derivedDid && yamlDid !== derivedDid) {
    return [
      `${yamlPath}: yaml device.device_identity does not match keystore. ` +
        `yaml device.device_identity = ${yamlDid}; ` +
        `keys/local.public = ${derivedDid}. ` +
        "Reseat one to match the other before any further " +
        "writes — the runtime will refuse to load this " +
        "ceremony otherwise.",
    ];
  }
  return [];
}

/**
 * Run every per-ceremony check for `name`; return its accumulated errors
 * (empty when valid). A read/parse failure or non-mapping top level
 * short-circuits the remaining checks. Mirrors `_validate_one_ceremony`.
 */
function validateOneCeremony(name: string, projectDir: string): string[] {
  const yamlPath = ceremonyYamlPath(name, projectDir);
  let parsed: unknown;
  try {
    parsed = parseYaml(readFileSync(yamlPath, "utf8"));
  } catch (e) {
    return [`${yamlPath}: read/parse failed: ${(e as Error).message}`];
  }
  const doc = asRecord(parsed);
  if (!doc) {
    return [`${yamlPath}: top-level must be a mapping`];
  }

  const isStream = "extends" in doc;
  const errors: string[] = [];
  errors.push(...validateRequiredSections(doc, yamlPath, isStream));
  errors.push(...validateSubkeys(doc, yamlPath, isStream));
  errors.push(...validateProfile(doc, yamlPath));
  errors.push(...validateGroupKits(doc, yamlPath));
  errors.push(...validateDidConsistency(doc, yamlPath));
  return errors;
}

/**
 * Execute `tn validate`. Returns the process exit code (0 on success or
 * nothing-to-validate; 1 when any ceremony fails validation), mirroring
 * Python's `cmd_validate`.
 */
export async function validateCmd(opts: ValidateOptions): Promise<number> {
  const projectDir = opts.projectDir ? pathResolve(opts.projectDir) : process.cwd();
  const root = tnRoot(projectDir);

  const errors: string[] = [];
  const warnings: string[] = [];

  if (!existsSync(root) || !statSync(root).isDirectory()) {
    process.stdout.write(`(no .tn/ directory at ${projectDir} — nothing to validate)\n`);
    return 0;
  }

  const names = listCeremoniesOnDisk(projectDir);
  if (names.length === 0) {
    process.stdout.write(`(no ceremonies under ${root} — nothing to validate)\n`);
    return 0;
  }

  if (!names.includes("default")) {
    warnings.push(
      "no 'default' ceremony at .tn/default/. The project's " +
        "identity should live there; named streams normally " +
        "extend from it.",
    );
  }

  for (const name of names) {
    errors.push(...validateOneCeremony(name, projectDir));
  }

  for (const w of warnings) process.stderr.write(`WARNING: ${w}\n`);
  if (errors.length > 0) {
    for (const e of errors) process.stderr.write(`ERROR: ${e}\n`);
    return 1;
  }

  process.stdout.write(`OK: ${names.length} ceremon${names.length === 1 ? "y" : "ies"} valid.\n`);
  return 0;
}
