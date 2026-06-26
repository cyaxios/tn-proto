// Shared CLI yaml-discovery — TypeScript port of python/tn/_autoinit.py
// `_resolve_existing_yaml` + python/tn/cli_common.py `_resolve_yaml_or_discover`.
//
// CLI verbs are operator actions, not onboarding flows: discovery is LOAD-ONLY
// (it never mints a fresh ceremony — that would surprise the caller). Use this
// instead of fabricating a default path and handing it to NodeRuntime.init,
// which WOULD create a fresh ceremony for a missing path.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

import { ceremonyYamlPath, listCeremoniesOnDisk } from "../multi.js";

/**
 * Project-named ceremony under `<cwd>/.tn/` (0.5.0a2 layout): returns the sole
 * project ceremony's yaml when no `default` exists and exactly one is on disk,
 * else null (ambiguous / none). Mirrors `_resolve_project_ceremony_yaml`.
 */
function resolveProjectCeremonyYaml(): string | null {
  const names = listCeremoniesOnDisk(process.cwd()).filter((n) => n !== "default");
  const only = names[0];
  if (names.length === 1 && only !== undefined) {
    const p = resolve(ceremonyYamlPath(only, process.cwd()));
    return existsSync(p) ? p : null;
  }
  return null;
}

/**
 * Walk the discovery chain LOAD-ONLY: return a yaml path that already exists, or
 * null if no ceremony is found. Never creates a fresh ceremony. Byte-parity with
 * python `_autoinit._resolve_existing_yaml`: `$TN_YAML` -> `./tn.yaml` ->
 * `./.tn/default/tn.yaml` -> sole `.tn/<project>/tn.yaml`. `$TN_HOME/tn.yaml` is
 * intentionally NOT in the chain (a project's tn calls scope to that project).
 */
export function resolveExistingYaml(): string | null {
  const envYaml = (process.env["TN_YAML"] ?? "").trim();
  if (envYaml) {
    const p = isAbsolute(envYaml) ? resolve(envYaml) : resolve(process.cwd(), envYaml);
    if (existsSync(p)) return p;
  }
  const cwdYaml = resolve(process.cwd(), "tn.yaml");
  if (existsSync(cwdYaml)) return cwdYaml;
  const multiYaml = resolve(process.cwd(), ".tn", "default", "tn.yaml");
  if (existsSync(multiYaml)) return multiYaml;
  return resolveProjectCeremonyYaml();
}

/**
 * Resolve a yaml path: the explicit arg if given (error if it doesn't exist),
 * else the load-only discovery chain, else a final fallback to any single
 * `*.yaml` in the cwd that smells like a ceremony. Mirrors python
 * `cli_common._resolve_yaml_or_discover`. Calls `die(msg)` (which must not
 * return) on a not-found path, an ambiguous cwd, or nothing found.
 *
 * The cwd smell-test checks `ceremony:` AND a `device:`/`device_identity:` block
 * — the canonical-schema equivalent of Python's stale `me:` probe (the loader
 * rejects legacy `me:`).
 */
export function resolveYamlOrDiscover(arg: string | null | undefined, die: (msg: string) => never): string {
  if (arg) {
    const p = resolve(arg);
    if (!existsSync(p)) die(`yaml not found: ${p}`);
    return p;
  }

  const discovered = resolveExistingYaml();
  if (discovered !== null) return discovered;

  // Final fallback: any *.yaml in cwd that smells like a ceremony.
  const cwd = process.cwd();
  const candidates: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(cwd).sort();
  } catch {
    entries = [];
  }
  for (const name of entries) {
    if (!name.endsWith(".yaml") && !name.endsWith(".yml")) continue;
    const p = resolve(cwd, name);
    let head: string;
    try {
      head = readFileSync(p, "utf8");
    } catch {
      continue;
    }
    if (head.includes("ceremony:") && (head.includes("device:") || head.includes("device_identity:"))) {
      candidates.push(p);
    }
  }
  if (candidates.length === 1 && candidates[0] !== undefined) return candidates[0];
  if (candidates.length > 1) {
    const names = candidates.map((p) => p.split(/[\\/]/).pop()).join(", ");
    die(`multiple ceremony yamls in cwd (${names}). Pass --yaml to disambiguate.`);
  }
  die(
    "no ceremony found here. Looked at $TN_YAML, ./tn.yaml, ./.tn/default/tn.yaml, " +
      "a sole .tn/<project>/tn.yaml, and any *.yaml in the cwd with a ceremony: block.\n" +
      "  - Restoring a downloaded seed (.tnpkg)?  run: tn import <seed.tnpkg>\n" +
      "  - Starting a brand-new project?          run: tn init <name>\n" +
      "  - Ceremony lives elsewhere?              pass --yaml <path>, or cd into its directory.",
  );
}
