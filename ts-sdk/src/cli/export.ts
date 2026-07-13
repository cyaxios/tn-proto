// `tn export --kind project_seed --out <file>` — write a self-addressed
// `.tnpkg` backup of the device's identity/keystore + canonical tn.yaml.
// TypeScript port of the inline `exportCmd` from `bin/tn-js.mjs`. Behaviour,
// flags, stdout, and exit codes match the original verb byte-for-byte:
//
//   tn-js export --kind project_seed --out <file> [--yaml <path>] --include-secrets
//
// The verb owns no argv parsing; the caller (dispatcher) resolves flags into
// the explicit {@link ExportCmdOptions} shape and forwards the exit code.
//
// On any expected misuse the original called the dispatcher's `die`, which
// writes `tn-js: <msg>\n` to stderr and `process.exit(2)`. That exact
// behaviour is preserved via the local {@link die} helper below.

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve as pathResolve } from "node:path";

import { parse as parseYaml } from "yaml";

import { DeviceKey } from "../core/signing.js";
import { newManifest, signManifestWithBody, type BodyContents } from "../core/tnpkg.js";
import { writeTnpkg } from "../tnpkg_io.js";
import { resolveYamlOrDiscover } from "./_discover.js";

/** Options for {@link exportCmd}. Mirrors the inline `exportCmd` flag set:
 *  `--kind`, `--out`, `--yaml`, `--include-secrets`, `--json`. */
export interface ExportCmdOptions {
  /** Path to the ceremony's tn.yaml (`--yaml`). Required by the verb. */
  yaml?: string;
  /** Output `.tnpkg` path (`--out`). Required by the verb. */
  out?: string;
  /** Bundle kind (`--kind`). Only `project_seed` is supported. */
  kind?: string;
  /** Acknowledge that raw private keys are written into the bundle
   *  (`--include-secrets`). Required for `project_seed`. */
  includeSecrets?: boolean;
  /** Print the structured receipt instead of the human `[tn export]` lines
   *  (`--json`). */
  json?: boolean;
}

/** Replicates the dispatcher's `die`: write `tn-js: <msg>\n` to stderr and
 *  exit the process with code 2. Preserves the original verb's exact
 *  stderr bytes and exit code. */
function die(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  process.exit(2);
}

/** Discovery/runtime errors exit 1 with the `tn: error:` prefix (Python `_die`),
 *  distinct from the exit-2 misuse `die` above (argparse-style usage errors). */
function dieRuntime(msg: string): never {
  process.stderr.write(`tn: error: ${msg}\n`);
  process.exit(1);
}

/**
 * Execute `tn export`. Returns the process exit code (0 on success). On any
 * expected misuse it calls {@link die}, which exits the process with code 2
 * — matching the inline `exportCmd` it ports.
 *
 * @param opts See {@link ExportCmdOptions}.
 */
export async function exportCmd(opts: ExportCmdOptions): Promise<number> {
  // tn-js export --kind project_seed --out <file> [--yaml <path>] --include-secrets
  // --yaml is optional: discover via the standard chain (Python uses
  // _resolve_yaml_or_discover), exiting 1 if no ceremony is found.
  const yamlPath = resolveYamlOrDiscover(opts.yaml, dieRuntime);
  const outPath = opts.out ?? null;
  const kind = opts.kind ?? "project_seed";
  const includeSecrets = opts.includeSecrets ?? false;
  if (!outPath) die("export: --out <file> is required");
  if (kind !== "project_seed")
    die(`export: unsupported kind ${JSON.stringify(kind)} (only project_seed)`);
  if (!includeSecrets) {
    die(
      "export --kind project_seed writes the device's raw private keys into " +
        "the bundle. Pass --include-secrets to acknowledge.",
    );
  }

  // Resolve identity/keystore straight from disk (no runtime init needed):
  // the keystore's local.public is the authoritative DID, and absorb only
  // cares about the body files + manifest, not a live runtime.
  const yamlAbs = pathResolve(yamlPath);
  const doc = (parseYaml(readFileSync(yamlAbs, "utf8")) as Record<string, unknown> | null) || {};
  const ceremony = doc?.["ceremony"] as Record<string, unknown> | undefined;
  const ceremonyId = (ceremony?.["id"] as string | undefined) ?? "";
  const keystore = doc?.["keystore"] as Record<string, unknown> | undefined;
  const ksPath = (keystore?.["path"] as string | undefined) || "./.tn/keys";
  const yamlDir = dirname(yamlAbs);
  const keysDir = isAbsolute(ksPath) ? ksPath : pathResolve(yamlDir, ksPath);
  if (!existsSync(keysDir)) die(`export: keystore dir not found: ${keysDir}`);
  const did = readFileSync(join(keysDir, "local.public"), "utf8").trim();

  // Body: canonical tn.yaml + every key file nested under body/keys/.
  const body: BodyContents = {
    "body/tn.yaml": new Uint8Array(readFileSync(pathResolve(yamlPath))),
  };
  for (const name of readdirSync(keysDir)) {
    const p = join(keysDir, name);
    if (!statSync(p).isFile()) continue;
    body[`body/keys/${name}`] = new Uint8Array(readFileSync(p));
  }

  // Self-addressed manifest (fromDid === toDid === device DID), signed
  // by the device key loaded from the keystore.
  const manifest = newManifest({
    kind: "project_seed",
    fromDid: did,
    ceremonyId,
    scope: "project",
    toDid: did,
  });
  const device = DeviceKey.fromSeed(new Uint8Array(readFileSync(join(keysDir, "local.private"))));
  const signed = signManifestWithBody(manifest, body, device);
  mkdirSync(dirname(pathResolve(outPath)), { recursive: true });
  const outResolved = writeTnpkg(pathResolve(outPath), signed, body);
  const bytes = statSync(outResolved).size;
  if (opts.json === true) {
    process.stdout.write(
      JSON.stringify({
        ok: true,
        kind: "project_seed",
        out: outResolved,
        bytes,
        device_identity: did,
        restore: `tn-js import ${basename(outPath)}`,
      }) + "\n",
    );
    return 0;
  }
  // Human summary — mirrors Python cli_pkg.cmd_export `[tn export]` lines.
  process.stdout.write(`[tn export] wrote ${outResolved}\n`);
  process.stdout.write(`[tn export]   kind:    project_seed\n`);
  process.stdout.write(`[tn export]   device:  ${did}\n`);
  process.stdout.write(`[tn export]   restore: tn-js import ${basename(outPath)}\n`);
  return 0;
}
