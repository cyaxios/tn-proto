// `tn vault link|unlink|jwks` - record vault/JWKS trust events as
// attested audit events and mutate ceremony YAML cache where appropriate.

import type { VaultJwksConfig } from "../runtime/config.js";
import { inspectVaultJwks, trustedVaultJwksRecipient } from "../vault/jwks.js";

type WritableSink = Pick<typeof process.stdout, "write">;
interface OpenedTn {
  close(): Promise<void> | void;
  vault: {
    link(vaultDid: string, projectId: string): Promise<{ eventId: string; rowHash: string }> | { eventId: string; rowHash: string };
    unlink(
      vaultDid: string,
      projectId: string,
      reason?: string | undefined,
    ): Promise<{ eventId: string; rowHash: string }> | { eventId: string; rowHash: string };
    pinJwks(
      jwks: VaultJwksConfig,
      opts?: { signingKid?: string; signingKeyFingerprint?: string } | undefined,
    ):
      | Promise<{
          receipt: { eventId: string; rowHash: string };
          targetYamlPath: string;
          jwks: VaultJwksConfig;
        }>
      | {
          receipt: { eventId: string; rowHash: string };
          targetYamlPath: string;
          jwks: VaultJwksConfig;
        };
    rotateJwks(
      jwks: VaultJwksConfig,
      previousJwksFingerprint: string,
      opts?:
        | { signingKid?: string; signingKeyFingerprint?: string; rotatedAt?: string }
        | undefined,
    ):
      | Promise<{
          receipt: { eventId: string; rowHash: string };
          targetYamlPath: string;
          jwks: VaultJwksConfig;
        }>
      | {
          receipt: { eventId: string; rowHash: string };
          targetYamlPath: string;
          jwks: VaultJwksConfig;
        };
  };
}

async function defaultOpenTn(yamlPath?: string | undefined): Promise<OpenedTn> {
  const { Tn } = await import("../tn.js");
  return Tn.init(yamlPath);
}

export interface VaultCmdDeps {
  fetchImpl?: typeof fetch | undefined;
  stdout?: WritableSink | undefined;
  stderr?: WritableSink | undefined;
  openTn?: ((yamlPath?: string | undefined) => Promise<OpenedTn>) | undefined;
}

interface ResolvedVaultCmdDeps {
  fetchImpl: typeof fetch | undefined;
  stdout: WritableSink;
  stderr: WritableSink;
  openTn: (yamlPath?: string | undefined) => Promise<OpenedTn>;
}

function depsOrDefault(deps: VaultCmdDeps): ResolvedVaultCmdDeps {
  return {
    fetchImpl: deps.fetchImpl,
    stdout: deps.stdout ?? process.stdout,
    stderr: deps.stderr ?? process.stderr,
    openTn: deps.openTn ?? defaultOpenTn,
  };
}

/** Print `tn-js: <msg>` to stderr and return exit code 2. */
function die(msg: string, stderr: WritableSink = process.stderr): number {
  stderr.write(`tn-js: ${msg}\n`);
  return 2;
}

/**
 * Execute `tn vault link|unlink|jwks`. Takes the FULL process argv
 * (`argv[3]` is the subcommand), mirroring the .mjs indexing verbatim.
 * Returns the process exit code.
 */
export async function vaultCmd(argv: string[], deps: VaultCmdDeps = {}): Promise<number> {
  const io = depsOrDefault(deps);
  const sub = argv[3];
  if (sub === "jwks") return vaultJwksCmd(argv, deps);

  const rest = argv.slice(4);
  const opts: {
    yaml: string | null;
    vaultDid: string | null;
    projectId: string | null;
    reason: string | null;
  } = { yaml: null, vaultDid: null, projectId: null, reason: null };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === undefined) continue;
    if (a === "--yaml") opts.yaml = rest[++i] ?? null;
    else if (a === "--reason") opts.reason = rest[++i] ?? null;
    else if (!a.startsWith("-")) {
      if (opts.vaultDid === null) opts.vaultDid = a;
      else if (opts.projectId === null) opts.projectId = a;
    }
  }
  if (sub !== "link" && sub !== "unlink") {
    return die(
      `vault: unknown subcommand ${sub}. try: ` +
        `vault link <vault-did> <project-id> [--yaml <path>] | ` +
        `vault jwks pin|rotate ...`,
      io.stderr,
    );
  }
  if (!opts.vaultDid || !opts.projectId) {
    return die(`vault ${sub}: <vault-did> and <project-id> are required positionals`, io.stderr);
  }
  const tn = await io.openTn(opts.yaml ?? undefined);
  try {
    const receipt =
      sub === "link"
        ? await tn.vault.link(opts.vaultDid, opts.projectId)
        : await tn.vault.unlink(opts.vaultDid, opts.projectId, opts.reason ?? undefined);
    io.stdout.write(
      JSON.stringify({
        ok: true,
        verb: `vault.${sub}`,
        event_id: receipt.eventId,
        row_hash: receipt.rowHash,
        vault_did: opts.vaultDid,
        project_id: opts.projectId,
      }) + "\n",
    );
  } finally {
    await tn.close();
  }
  return 0;
}

async function vaultJwksCmd(argv: string[], deps: VaultCmdDeps): Promise<number> {
  const io = depsOrDefault(deps);
  const action = argv[4];
  const rest = argv.slice(5);
  const opts: {
    yaml: string | null;
    issuer: string | null;
    url: string | null;
    fingerprint: string | null;
    previous: string | null;
    pinnedAt: string | null;
    rotatedAt: string | null;
    signingKid: string | null;
    signingKeyFingerprint: string | null;
  } = {
    yaml: null,
    issuer: null,
    url: null,
    fingerprint: null,
    previous: null,
    pinnedAt: null,
    rotatedAt: null,
    signingKid: null,
    signingKeyFingerprint: null,
  };

  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === undefined) continue;
    if (a === "--yaml") opts.yaml = rest[++i] ?? null;
    else if (a === "--issuer") opts.issuer = rest[++i] ?? null;
    else if (a === "--url" || a === "--jwks-url") opts.url = rest[++i] ?? null;
    else if (a === "--fingerprint") opts.fingerprint = rest[++i] ?? null;
    else if (a === "--previous" || a === "--previous-fingerprint") opts.previous = rest[++i] ?? null;
    else if (a === "--pinned-at") opts.pinnedAt = rest[++i] ?? null;
    else if (a === "--rotated-at") opts.rotatedAt = rest[++i] ?? null;
    else if (a === "--signing-kid") opts.signingKid = rest[++i] ?? null;
    else if (a === "--signing-key-fingerprint") opts.signingKeyFingerprint = rest[++i] ?? null;
    else return die(`vault jwks ${action ?? ""}: unknown argument ${a}`, io.stderr);
  }

  if (action !== "pin" && action !== "rotate" && action !== "inspect") {
    return die(
      "vault jwks: unknown action. try: " +
        "vault jwks inspect --url <jwks-url> | " +
        "vault jwks pin --yaml <path> --issuer <did> --url <jwks-url> --fingerprint <sha256:...>",
      io.stderr,
    );
  }
  if (action === "inspect") {
    if (!opts.url) return die("vault jwks inspect: --url <jwks-url> is required", io.stderr);
    const inspectOpts = io.fetchImpl === undefined ? { url: opts.url } : { url: opts.url, fetchImpl: io.fetchImpl };
    const result = await inspectVaultJwks(inspectOpts);
    io.stdout.write(
      JSON.stringify({
        ok: true,
        verb: "vault.jwks.inspect",
        issuer: result.issuer,
        jwks_url: result.url,
        jwks_fingerprint: result.jwksFingerprint,
        active_encryption_kid: result.activeEncryptionKid,
        active_encryption_key_fingerprint: result.activeEncryptionKeyFingerprint,
      }) + "\n",
    );
    return 0;
  }
  if (!opts.yaml) return die(`vault jwks ${action}: --yaml <path> is required`, io.stderr);
  if (!opts.issuer) return die(`vault jwks ${action}: --issuer <did> is required`, io.stderr);
  if (!opts.url) return die(`vault jwks ${action}: --url <jwks-url> is required`, io.stderr);
  if (!opts.fingerprint) return die(`vault jwks ${action}: --fingerprint <sha256:...> is required`, io.stderr);
  if (action === "rotate" && !opts.previous) {
    return die("vault jwks rotate: --previous <sha256:...> is required", io.stderr);
  }

  const jwks: VaultJwksConfig = {
    issuer: opts.issuer,
    url: opts.url,
    fingerprint: opts.fingerprint,
    ...(opts.pinnedAt === null ? {} : { pinnedAt: opts.pinnedAt }),
  };
  const eventOpts: { signingKid?: string; signingKeyFingerprint?: string } = {};
  if (opts.signingKid !== null) eventOpts.signingKid = opts.signingKid;
  if (opts.signingKeyFingerprint !== null) {
    eventOpts.signingKeyFingerprint = opts.signingKeyFingerprint;
  }

  // Strong default: prove the remote key set currently matches the explicit
  // pin before mutating local YAML or writing the signed admin event.
  const trustOpts = io.fetchImpl === undefined ? { jwks } : { jwks, fetchImpl: io.fetchImpl };
  await trustedVaultJwksRecipient(trustOpts);

  const tn = await io.openTn(opts.yaml);
  try {
    const result =
      action === "pin"
        ? await tn.vault.pinJwks(jwks, eventOpts)
        : await tn.vault.rotateJwks(jwks, opts.previous!, {
            ...eventOpts,
            ...(opts.rotatedAt === null ? {} : { rotatedAt: opts.rotatedAt }),
          });
    io.stdout.write(
      JSON.stringify({
        ok: true,
        verb: `vault.jwks.${action}`,
        event_id: result.receipt.eventId,
        row_hash: result.receipt.rowHash,
        yaml: result.targetYamlPath,
        issuer: result.jwks.issuer,
        jwks_url: result.jwks.url,
        jwks_fingerprint: result.jwks.fingerprint,
      }) + "\n",
    );
  } finally {
    await tn.close();
  }
  return 0;
}
