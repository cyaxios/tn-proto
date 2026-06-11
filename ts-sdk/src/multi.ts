/**
 * Multi-ceremony layer for the TS SDK — mirrors python/tn/_multi.py.
 *
 * Provides:
 *   - directory-layout helpers (.tn/<name>/ subdirs)
 *   - ceremony name validation (mirrors tn._layout.is_valid_ceremony_name)
 *   - on-disk creation: full default ceremony or lightweight
 *     extends-based stream yaml
 *   - listing helpers
 *
 * The user-facing entry points (``Tn.openCeremony``, ``Tn.init``,
 * ``Tn.listCeremonies``) live in ``tn.ts`` and delegate here.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

import { createFreshCeremony } from "./runtime/node_runtime.js";
import { DEFAULT_PROFILE, getProfile, isKnownProfile, type ProfileName } from "./profiles.js";

export const TN_ROOT_DIRNAME = ".tn";
export const DEFAULT_CEREMONY_NAME = "default";
export const LEGACY_DEFAULT_DIRNAME = "tn";

const _CEREMONY_NAME_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/;

export interface ProjectLayout {
  workspace: string;
  project: string;
  projectDir: string;
  projectYaml: string;
  keysDir: string;
  streamsDir: string;
  logsDir: string;
  adminDir: string;
  vaultDir: string;
}

export interface StreamLayout {
  project: ProjectLayout;
  stream: string;
  streamYaml: string;
  logPath: string;
  adminLogPath: string;
  extendsRelpath: string;
}

export class TNInvalidName extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TNInvalidName";
  }
}

export class TNCreateFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TNCreateFailed";
  }
}

/**
 * True iff ``name`` is safe to use as a ``.tn/`` subdirectory.
 *
 * Conservative: ascii letters/digits/underscore/dash, must not start
 * with a dash, must not be empty. Rejects path separators, leading
 * dots, and the reserved legacy name ``tn`` (which collides with the
 * legacy single-ceremony layout).
 *
 * Mirrors python/tn/_layout.py:is_valid_ceremony_name.
 */
export function isValidCeremonyName(name: string): boolean {
  if (typeof name !== "string" || !name) return false;
  if (name === LEGACY_DEFAULT_DIRNAME) return false;
  return _CEREMONY_NAME_RE.test(name);
}

/** Return the ``.tn/`` directory for ``projectDir`` (default: cwd). */
export function tnRoot(projectDir?: string): string {
  return resolve(projectDir ?? process.cwd(), TN_ROOT_DIRNAME);
}

export function defaultProjectName(projectDir?: string): string {
  const workspace = resolve(projectDir ?? process.cwd());
  const parts = workspace.split(/[\\/]+/);
  const name = parts[parts.length - 1] ?? "";
  if (!isValidCeremonyName(name)) {
    throw new TNInvalidName(
      `invalid ceremony name ${JSON.stringify(name)}: must match ` +
        "[a-zA-Z0-9_][a-zA-Z0-9_-]* and is not 'tn' (reserved).",
    );
  }
  return name;
}

export function projectLayout(project?: string, projectDir?: string): ProjectLayout {
  const name = project ?? defaultProjectName(projectDir);
  if (!isValidCeremonyName(name)) {
    throw new TNInvalidName(
      `invalid ceremony name ${JSON.stringify(name)}: must match ` +
        "[a-zA-Z0-9_][a-zA-Z0-9_-]* and is not 'tn' (reserved).",
    );
  }
  const workspace = resolve(projectDir ?? process.cwd());
  const pdir = join(workspace, TN_ROOT_DIRNAME, name);
  return {
    workspace,
    project: name,
    projectDir: pdir,
    projectYaml: join(pdir, "tn.yaml"),
    keysDir: join(pdir, "keys"),
    streamsDir: join(pdir, "streams"),
    logsDir: join(pdir, "logs"),
    adminDir: join(pdir, "admin"),
    vaultDir: join(pdir, "vault"),
  };
}

export function streamLayout(
  stream = DEFAULT_CEREMONY_NAME,
  opts: { project?: string; projectDir?: string } = {},
): StreamLayout {
  if (!isValidCeremonyName(stream)) {
    throw new TNInvalidName(
      `invalid ceremony name ${JSON.stringify(stream)}: must match ` +
        "[a-zA-Z0-9_][a-zA-Z0-9_-]* and is not 'tn' (reserved).",
    );
  }
  const pl = projectLayout(opts.project, opts.projectDir);
  return {
    project: pl,
    stream,
    streamYaml: join(pl.streamsDir, `${stream}.yaml`),
    logPath: join(pl.logsDir, `${stream}.ndjson`),
    adminLogPath: join(pl.adminDir, `${stream}.ndjson`),
    extendsRelpath: "../tn.yaml",
  };
}

/** Return the directory for ceremony ``name``. */
export function ceremonyDir(name: string, projectDir?: string): string {
  if (!isValidCeremonyName(name)) {
    throw new TNInvalidName(
      `invalid ceremony name ${JSON.stringify(name)}: must match ` +
        "[a-zA-Z0-9_][a-zA-Z0-9_-]* and is not 'tn' (reserved).",
    );
  }
  return join(tnRoot(projectDir), name);
}

/** Return the canonical ``tn.yaml`` path for ceremony ``name``. */
export function ceremonyYamlPath(name: string, projectDir?: string): string {
  return join(ceremonyDir(name, projectDir), "tn.yaml");
}

/**
 * List ceremony names under ``.tn/`` for ``projectDir``. Returns
 * sorted names of immediate subdirs that contain a ``tn.yaml``.
 *
 * Mirrors python/tn/_layout.py:list_ceremonies_on_disk.
 */
export function listCeremoniesOnDisk(projectDir?: string): string[] {
  const root = tnRoot(projectDir);
  if (!existsSync(root)) return [];
  const out: string[] = [];
  for (const child of readdirSync(root)) {
    if (!isValidCeremonyName(child) && child !== LEGACY_DEFAULT_DIRNAME) {
      continue;
    }
    if (existsSync(join(root, child, "tn.yaml"))) {
      out.push(child);
    }
  }
  out.sort();
  return out;
}

/**
 * Migrate the legacy single-ceremony layout in place.
 *
 * If ``.tn/tn/tn.yaml`` exists and ``.tn/default/`` does not, rename
 * ``.tn/tn/`` to ``.tn/default/``. Returns the new path if a
 * migration was performed, ``null`` otherwise.
 *
 * If both ``.tn/tn/`` and ``.tn/default/`` exist, throws —
 * ambiguous state must be resolved by hand.
 *
 * Mirrors python/tn/_layout.py:migrate_legacy_layout.
 */
export function migrateLegacyLayout(projectDir?: string): string | null {
  const root = tnRoot(projectDir);
  const legacy = join(root, LEGACY_DEFAULT_DIRNAME);
  const target = join(root, DEFAULT_CEREMONY_NAME);

  const legacyYaml = join(legacy, "tn.yaml");
  if (!existsSync(legacy) || !existsSync(legacyYaml)) return null;

  if (existsSync(target)) {
    throw new Error(
      `TN layout migration ambiguous: both ${legacy} and ${target} ` +
        "exist. Resolve by hand: pick one, delete the other, then re-run.",
    );
  }

  renameSync(legacy, target);
  return target;
}

/**
 * Legacy ceremony/stream creator for the sibling ``.tn/<name>/tn.yaml``
 * layout. New project-root code uses ``ensureProjectLayoutOnDisk`` and
 * ``ensureProjectStreamOnDisk``.
 *
 * Two-mode behavior — mirrors python/tn/_multi.py:_ensure_ceremony_on_disk:
 *
 *   - For the *default* ceremony: calls ``createFreshCeremony`` to
 *     mint identity + keystore + full yaml. Stamps ``ceremony.profile``.
 *   - For *named streams*: writes a lightweight yaml that references
 *     default's identity/groups via ``extends: ../default/tn.yaml``.
 *     If default does not exist, it is created first.
 *
 * Per-stream directories only contain ``logs/`` and ``admin/``;
 * keystore lives at default.
 */
export function ensureCeremonyOnDisk(
  name: string,
  opts: {
    projectDir?: string;
    profile?: string;
    asRoot?: boolean;
    /** Seed the ceremony's device key from this 32-byte Ed25519 seed
     *  instead of minting a random one. Used by `tn-js init` to bind every
     *  ceremony to the machine-global identity (so they share one DID).
     *  Only honoured on the default / as-root mint path. */
    devicePrivateBytes?: Uint8Array;
  } = {},
): string {
  const yamlPath = ceremonyYamlPath(name, opts.projectDir);
  if (existsSync(yamlPath)) return yamlPath;

  const profile = opts.profile ?? DEFAULT_PROFILE;
  if (!isKnownProfile(profile)) {
    throw new TNCreateFailed(
      `unknown profile ${JSON.stringify(profile)}; catalog: ` +
        '["transaction","audit","secure_log","telemetry"]',
    );
  }

  // `asRoot` lets a project-named ceremony (0.5.0a2 layout, `.tn/<project>/`)
  // mint its own keystore instead of being a stream that references
  // `../default/keys`. The literal "default" name keeps the same behaviour
  // for back-compat. Mirrors python/tn/_multi.py:_ensure_ceremony_on_disk.
  if (name === DEFAULT_CEREMONY_NAME || opts.asRoot) {
    // For an as-root *named* project, stamp ceremony.project_name = name
    // so the vault labels the bound project with the human name (mirrors
    // Python's `_stamp_project_labels`). The literal "default" ceremony
    // stays unstamped.
    const projectName = opts.asRoot && name !== DEFAULT_CEREMONY_NAME ? name : undefined;
    return _createDefaultCeremony(
      name,
      yamlPath,
      opts.projectDir,
      profile,
      projectName,
      opts.devicePrivateBytes,
    );
  }
  return _createStreamYaml(name, yamlPath, opts.projectDir, profile);
}

export function ensureProjectLayoutOnDisk(
  project?: string,
  opts: {
    projectDir?: string;
    profile?: string;
    devicePrivateBytes?: Uint8Array;
  } = {},
): string {
  const profile = opts.profile ?? DEFAULT_PROFILE;
  if (!isKnownProfile(profile)) {
    throw new TNCreateFailed(
      `unknown profile ${JSON.stringify(profile)}; catalog: ` +
        '["transaction","audit","secure_log","telemetry"]',
    );
  }
  const layout = projectLayout(project, opts.projectDir);
  if (existsSync(layout.projectYaml)) return layout.projectYaml;
  for (const d of [
    layout.projectDir,
    layout.keysDir,
    layout.streamsDir,
    layout.logsDir,
    layout.adminDir,
    layout.vaultDir,
  ]) {
    mkdirSync(d, { recursive: true });
  }
  const freshOpts: {
    keystoreDir: string;
    logPath: string;
    adminLogPath: string;
    profile: ProfileName;
    projectName: string;
    devicePrivateBytes?: Uint8Array;
  } = {
    keystoreDir: layout.keysDir,
    logPath: join(layout.logsDir, `${DEFAULT_CEREMONY_NAME}.ndjson`),
    adminLogPath: join(layout.adminDir, `${DEFAULT_CEREMONY_NAME}.ndjson`),
    profile,
    projectName: layout.project,
  };
  if (opts.devicePrivateBytes !== undefined) {
    freshOpts.devicePrivateBytes = opts.devicePrivateBytes;
  }
  createFreshCeremony(layout.projectYaml, freshOpts);
  const defaultOverlay = join(layout.streamsDir, `${DEFAULT_CEREMONY_NAME}.yaml`);
  if (!existsSync(defaultOverlay)) {
    writeFileSync(defaultOverlay, "extends: ../tn.yaml\n", "utf8");
  }
  return layout.projectYaml;
}

export function ensureProjectStreamOnDisk(
  stream = DEFAULT_CEREMONY_NAME,
  opts: { project?: string; projectDir?: string; profile?: string } = {},
): string {
  const profile = opts.profile ?? DEFAULT_PROFILE;
  if (!isKnownProfile(profile)) {
    throw new TNCreateFailed(
      `unknown profile ${JSON.stringify(profile)}; catalog: ` +
        '["transaction","audit","secure_log","telemetry"]',
    );
  }
  const projectOpts: { projectDir?: string; profile: ProfileName } = {
    profile: DEFAULT_PROFILE,
  };
  if (opts.projectDir !== undefined) projectOpts.projectDir = opts.projectDir;
  ensureProjectLayoutOnDisk(opts.project, projectOpts);
  const streamOpts: { project?: string; projectDir?: string } = {};
  if (opts.project !== undefined) streamOpts.project = opts.project;
  if (opts.projectDir !== undefined) streamOpts.projectDir = opts.projectDir;
  const layout = streamLayout(stream, streamOpts);
  if (existsSync(layout.streamYaml)) return layout.streamYaml;
  mkdirSync(layout.project.streamsDir, { recursive: true });
  mkdirSync(layout.project.logsDir, { recursive: true });
  mkdirSync(layout.project.adminDir, { recursive: true });

  if (stream === DEFAULT_CEREMONY_NAME) {
    writeFileSync(layout.streamYaml, "extends: ../tn.yaml\n", "utf8");
    return layout.streamYaml;
  }

  const p = getProfile(profile);
  const logPath = `../logs/${stream}.ndjson`;
  const adminPath = `../admin/${stream}.ndjson`;
  const handlers: string[] = [];
  if (p.default_sink === "file_rotating") {
    handlers.push(
      `- kind: file.rotating\n  name: main\n  path: ${logPath}\n  ` +
        `max_bytes: 5242880\n  backup_count: 5\n  rotate_on_init: false`,
    );
  }
  handlers.push("- kind: stdout\n  name: stdout");
  const yaml =
    `extends: ${layout.extendsRelpath}\n` +
    `ceremony:\n` +
    `  id: ${_mintStreamCeremonyId(stream)}\n` +
    `  sign: ${p.signs}\n` +
    `  chain: ${p.chains}\n` +
    `  profile: ${profile}\n` +
    `  admin_log_location: ${adminPath}\n` +
    `  log_level: debug\n` +
    `logs:\n` +
    `  path: ${logPath}\n` +
    `handlers:\n` +
    handlers.join("\n") +
    "\n";
  writeFileSync(layout.streamYaml, yaml, "utf8");
  return layout.streamYaml;
}

function _createDefaultCeremony(
  name: string,
  yamlPath: string,
  projectDir: string | undefined,
  profile: ProfileName,
  projectName?: string,
  devicePrivateBytes?: Uint8Array,
): string {
  const ydir = ceremonyDir(name, projectDir);
  mkdirSync(ydir, { recursive: true });
  for (const sub of ["keys", "logs", "admin", "vault"]) {
    mkdirSync(join(ydir, sub), { recursive: true });
  }
  try {
    const freshOpts: {
      keystoreDir: string;
      logPath: string;
      adminLogPath: string;
      profile: ProfileName;
      projectName?: string;
      devicePrivateBytes?: Uint8Array;
    } = {
      keystoreDir: join(ydir, "keys"),
      logPath: join(ydir, "logs", "tn.ndjson"),
      adminLogPath: join(ydir, "admin", `${DEFAULT_CEREMONY_NAME}.ndjson`),
      profile,
    };
    if (projectName !== undefined) freshOpts.projectName = projectName;
    if (devicePrivateBytes !== undefined) freshOpts.devicePrivateBytes = devicePrivateBytes;
    createFreshCeremony(yamlPath, freshOpts);
  } catch (e) {
    throw new TNCreateFailed(
      `could not create fresh ceremony at ${yamlPath}: ${(e as Error).message}`,
    );
  }
  return yamlPath;
}

function _mintStreamCeremonyId(name: string): string {
  // Each stream has its own ceremony_id (scopes its chain) even though
  // it shares device identity with default. Format mirrors Python's
  // python/tn/_multi.py:_mint_stream_ceremony_id.
  const hex = randomBytes(3).toString("hex");
  return `stream_${name}_${hex}`;
}

function _createStreamYaml(
  name: string,
  yamlPath: string,
  projectDir: string | undefined,
  profile: ProfileName,
): string {
  const defaultYaml = ceremonyYamlPath(DEFAULT_CEREMONY_NAME, projectDir);
  if (!existsSync(defaultYaml)) {
    const opts: { projectDir?: string; profile?: string } = {
      profile: DEFAULT_PROFILE,
    };
    if (projectDir !== undefined) opts.projectDir = projectDir;
    ensureCeremonyOnDisk(DEFAULT_CEREMONY_NAME, opts);
  }

  const ydir = ceremonyDir(name, projectDir);
  mkdirSync(ydir, { recursive: true });
  for (const sub of ["logs", "admin"]) {
    mkdirSync(join(ydir, sub), { recursive: true });
  }

  const logPath = `./logs/${name}.ndjson`;
  const adminPath = `./admin/${name}.ndjson`;
  const cid = _mintStreamCeremonyId(name);
  const p = getProfile(profile);

  const handlers: string[] = [];
  if (p.default_sink === "file_rotating") {
    handlers.push(
      `- kind: file.rotating\n  name: main\n  path: ${logPath}\n  ` +
        `max_bytes: 5242880\n  backup_count: 5\n  rotate_on_init: false`,
    );
  } else if (p.default_sink === "stdout") {
    handlers.push(`- kind: stdout\n  name: stdout`);
  }

  // Reference to default's yaml by relative path. The loader's
  // resolveExtends pass merges identity/groups/recipients in.
  const extendsRelpath = `../${DEFAULT_CEREMONY_NAME}/tn.yaml`;

  const yaml =
    `extends: ${extendsRelpath}\n` +
    `ceremony:\n` +
    `  id: ${cid}\n` +
    `  sign: ${p.signs}\n` +
    // Propagate the profile's chains flag so the Rust/wasm core honours it
    // (chains=false -> empty prev_hash, sequence still advances). Without
    // this the core defaults to chain: true and links every row regardless
    // of profile. Mirrors python/tn/_multi.py:_create_stream_yaml.
    `  chain: ${p.chains}\n` +
    `  profile: ${profile}\n` +
    `  admin_log_location: ${adminPath}\n` +
    `  log_level: debug\n` +
    `logs:\n` +
    `  path: ${logPath}\n` +
    `handlers:\n` +
    handlers.join("\n") +
    "\n";

  try {
    writeFileSync(yamlPath, yaml, "utf8");
  } catch (e) {
    throw new TNCreateFailed(`could not write stream yaml ${yamlPath}: ${(e as Error).message}`);
  }
  return yamlPath;
}

/**
 * Profile-conflict check + warning. Mirrors python/tn/_multi.py:_check_no_conflict.
 *
 * If the on-disk yaml exists and disagrees with a code-supplied
 * profile, log a warning (operator-wins). Unknown profile names
 * raise — that's misconfig at the call site, not a conflict.
 */
export function checkProfileConflict(yamlPath: string, profile: string | undefined): void {
  if (profile !== undefined && !isKnownProfile(profile)) {
    throw new TNCreateFailed(
      `unknown profile ${JSON.stringify(profile)}; catalog: ` +
        '["transaction","audit","secure_log","telemetry"]',
    );
  }
  if (!existsSync(yamlPath) || profile === undefined) return;
  let onDisk: string | undefined;
  try {
    const text = readFileSync(yamlPath, "utf8");
    const m = text.match(/^\s+profile:\s*(\S+)/m);
    if (m) onDisk = m[1];
  } catch {
    return;
  }
  if (!onDisk || onDisk === profile) return;
  console.warn(
    `profile conflict for ${yamlPath}: code requested ` +
      `${JSON.stringify(profile)}, on-disk yaml specifies ${JSON.stringify(onDisk)}. ` +
      "Operator authority — yaml wins. To use the code-requested " +
      "profile, edit the yaml or pick a different ceremony name.",
  );
}
