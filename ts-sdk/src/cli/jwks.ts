// `tn-js jwks export` - export local public key material as a TN JWKS.
//
// This is intentionally separate from `tn-js export`, which writes secret
// project_seed backups. JWKS export is public-key discovery material only.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";

import {
  jwksDocumentFingerprint,
  localDeviceJwks,
  localJweEncryptionJwksKey,
  parseTnJwks,
  type TnJwksDocument,
} from "../core/jwks.js";
import { loadConfig } from "../runtime/config.js";
import { loadKeystore } from "../runtime/keystore.js";
import { resolveYamlOrDiscover } from "./_discover.js";

type WritableSink = Pick<typeof process.stdout, "write">;

export interface JwksExportOptions {
  yaml?: string;
  out?: string;
  issuer?: string;
  kid?: string;
  issuedAt?: string;
  expiresAt?: string;
  includeEncryption?: boolean;
  groups?: string[];
  json?: boolean;
}

export interface JwksCmdDeps {
  stdout?: WritableSink;
  stderr?: WritableSink;
  loadJwks?: ((yamlPath: string, opts: JwksExportOptions) => TnJwksDocument) | undefined;
  writeText?: ((path: string, text: string) => void) | undefined;
}

interface ResolvedJwksCmdDeps {
  stdout: WritableSink;
  stderr: WritableSink;
  loadJwks: (yamlPath: string, opts: JwksExportOptions) => TnJwksDocument;
  writeText: (path: string, text: string) => void;
}

class JwksCliError extends Error {
  readonly code: number;
  readonly prefix: "tn-js" | "tn";

  constructor(code: number, prefix: "tn-js" | "tn", message: string) {
    super(message);
    this.code = code;
    this.prefix = prefix;
  }
}

function defaultLoadJwks(yamlPath: string, opts: JwksExportOptions): TnJwksDocument {
  const cfg = loadConfig(yamlPath);
  const keystore = loadKeystore(cfg.keystorePath);
  const jwks = localDeviceJwks(keystore.device, {
    ...(opts.issuer === undefined ? {} : { issuer: opts.issuer }),
    ...(opts.kid === undefined ? {} : { kid: opts.kid }),
    ...(opts.issuedAt === undefined ? {} : { issuedAt: opts.issuedAt }),
    ...(opts.expiresAt === undefined ? {} : { expiresAt: opts.expiresAt }),
  });
  if (opts.includeEncryption !== true) return jwks;

  const requested = opts.groups ?? [];
  const groups =
    requested.length > 0
      ? requested
      : [...keystore.groups.entries()]
          .filter(([, group]) => (group.jweKeys?.length ?? 0) > 0)
          .map(([name]) => name)
          .sort();
  if (groups.length === 0) {
    throw new Error("jwks export: no local JWE encryption keys found; pass --group for a specific JWE group");
  }
  for (const groupName of groups) {
    const group = keystore.groups.get(groupName);
    const privateKey = group?.jweKeys?.[0];
    if (privateKey === undefined) {
      throw new Error(`jwks export: group ${JSON.stringify(groupName)} has no active JWE encryption key`);
    }
    jwks.keys.push(localJweEncryptionJwksKey(groupName, privateKey));
  }
  return parseTnJwks(jwks);
}

function defaultWriteText(path: string, text: string): void {
  const resolved = pathResolve(path);
  mkdirSync(dirname(resolved), { recursive: true });
  writeFileSync(resolved, text, "utf8");
}

function depsOrDefault(deps: JwksCmdDeps): ResolvedJwksCmdDeps {
  return {
    stdout: deps.stdout ?? process.stdout,
    stderr: deps.stderr ?? process.stderr,
    loadJwks: deps.loadJwks ?? defaultLoadJwks,
    writeText: deps.writeText ?? defaultWriteText,
  };
}

function usage(msg: string): never {
  throw new JwksCliError(2, "tn-js", msg);
}

function runtimeError(msg: string): never {
  throw new JwksCliError(1, "tn", msg);
}

function parseExportOptions(rest: string[]): JwksExportOptions {
  const opts: JwksExportOptions = {};
  const next = (i: number, flag: string): string => {
    const value = rest[i + 1];
    if (value === undefined) usage(`jwks export: ${flag} requires a value`);
    return value;
  };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === undefined) continue;
    if (a === "--yaml") opts.yaml = next(i++, a);
    else if (a === "--out") opts.out = next(i++, a);
    else if (a === "--issuer") opts.issuer = next(i++, a);
    else if (a === "--kid") opts.kid = next(i++, a);
    else if (a === "--issued-at") opts.issuedAt = next(i++, a);
    else if (a === "--expires-at") opts.expiresAt = next(i++, a);
    else if (a === "--include-encryption") opts.includeEncryption = true;
    else if (a === "--group") {
      const value = next(i++, a);
      const groups = value
        .split(",")
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
      opts.groups = [...(opts.groups ?? []), ...groups];
    }
    else if (a === "--json") opts.json = true;
    else usage(`jwks export: unknown argument ${a}`);
  }
  return opts;
}

function printError(err: JwksCliError, stderr: WritableSink): number {
  stderr.write(`${err.prefix}: ${err.prefix === "tn-js" ? "" : "error: "}${err.message}\n`);
  return err.code;
}

/**
 * Execute `tn-js jwks export`.
 *
 * Full argv shape mirrors `bin/tn-js.mjs`: `argv[2] === "jwks"` and
 * `argv[3] === "export"`.
 */
export async function jwksCmd(argv: string[], deps: JwksCmdDeps = {}): Promise<number> {
  const io = depsOrDefault(deps);
  try {
    const sub = argv[3];
    if (sub !== "export") {
      usage(`jwks: unknown subcommand ${sub}. try: jwks export [--yaml <path>] [--out <path>]`);
    }

    const opts = parseExportOptions(argv.slice(4));
    const yamlPath = resolveYamlOrDiscover(opts.yaml, runtimeError);
    const jwks = io.loadJwks(yamlPath, opts);
    const body = `${JSON.stringify(jwks, null, 2)}\n`;

    if (opts.out === undefined) {
      io.stdout.write(body);
      return 0;
    }

    const outPath = pathResolve(opts.out);
    io.writeText(outPath, body);
    const receipt = {
      ok: true,
      verb: "jwks.export",
      out: outPath,
      issuer: jwks.issuer,
      jwks_fingerprint: jwksDocumentFingerprint(jwks),
      keys: jwks.keys.map((key) => ({
        kid: key.kid,
        use: key.use,
        alg: key.alg,
        fingerprint: key.tn_fingerprint,
      })),
    };

    if (opts.json === true) {
      io.stdout.write(`${JSON.stringify(receipt)}\n`);
    } else {
      io.stdout.write(`[tn jwks] wrote ${outPath}\n`);
      io.stdout.write(`[tn jwks]   issuer:      ${receipt.issuer}\n`);
      io.stdout.write(`[tn jwks]   fingerprint: ${receipt.jwks_fingerprint}\n`);
    }
    return 0;
  } catch (err) {
    if (err instanceof JwksCliError) return printError(err, io.stderr);
    throw err;
  }
}
