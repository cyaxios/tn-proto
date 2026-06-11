// `tn bundle` CLI verb — TS port of Python `cli.py::cmd_bundle`.
//
// Mints a kit_bundle `.tnpkg` for one recipient DID. Mirrors the Python
// command's behaviour, flags, stdout, and exit code:
//
//   tn bundle [--yaml=...] [--groups=a,b] [--seal-for-recipient] <recipient> <out>
//
// Source of truth: python/tn/cli.py `cmd_bundle` + parser `p_bundle`.
// Crypto / sealing is NOT reimplemented here — this delegates to the
// existing `NodeRuntime.bundleForRecipient`, the same primitive the rest
// of the TS SDK uses.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve as pathResolve, join } from "node:path";

import { NodeRuntime } from "../runtime/node_runtime.js";
import {
  mintAndSealBundle,
  recipientKeyIsResolvable,
} from "../seal_bundle_producer.js";

/** Explicit, pre-parsed options for the `bundle` verb. The orchestrator
 * wires argv -> these fields before dispatch (mirrors argparse's
 * `args.recipient_identity` / `args.out` / `args.yaml` / `args.groups` /
 * `args.seal_for_recipient`). */
export interface BundleCmdOptions {
  /** DID of the recipient receiving the kit (positional `recipient_identity`). */
  recipientIdentity: string;
  /** Destination `.tnpkg` path (positional `out`). */
  out: string;
  /** `--yaml`: path to tn.yaml. When omitted, discovered. */
  yaml?: string | undefined;
  /** `--groups`: comma-separated group names. When omitted, all non-tn.agents. */
  groups?: string | undefined;
  /** `--seal-for-recipient`: wrap the body under a per-export key. */
  sealForRecipient?: boolean | undefined;
}

/** Normalize a thrown value to a printable message. Errors yield their
 * `.message`; anything else is stringified. */
function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Resolve the yaml path from an explicit `--yaml` arg, else discover via
 * `$TN_YAML`, `./tn.yaml`, then `~/.tn/tn.yaml`. Mirrors the explicit-arg
 * branch and basic discovery order of Python's
 * `_resolve_yaml_or_discover`. Throws on a not-found path so the caller
 * can surface a non-zero exit. */
function resolveYamlOrDiscover(arg?: string): string {
  if (arg) {
    const p = pathResolve(arg);
    if (!existsSync(p)) {
      throw new Error(`yaml not found: ${p}`);
    }
    return p;
  }
  const env = process.env.TN_YAML;
  if (env && existsSync(env)) return pathResolve(env);
  const cwdYaml = pathResolve("tn.yaml");
  if (existsSync(cwdYaml)) return cwdYaml;
  const homeYaml = join(homedir(), ".tn", "tn.yaml");
  if (existsSync(homeYaml)) return homeYaml;
  throw new Error(
    "no yaml found. Looked at $TN_YAML, ./tn.yaml, ~/.tn/tn.yaml. " +
      "Pass --yaml or `cd` into a project directory.",
  );
}

/**
 * Execute the `bundle` verb. Returns the process exit code (0 on success,
 * 1 on a handled error — matching Python's `_die`, which exits non-zero).
 *
 * Prints the same four-line summary Python's `cmd_bundle` prints:
 *   [tn bundle] wrote <out>
 *   [tn bundle]   recipient: <did>
 *   [tn bundle]   ceremony:  <id>  (cipher=<cipher>)
 *   [tn bundle]   groups:    <list>
 */
export async function bundleCmd(opts: BundleCmdOptions): Promise<number> {
  let yamlPath: string;
  try {
    yamlPath = resolveYamlOrDiscover(opts.yaml);
  } catch (e) {
    console.error(`[tn bundle] ${errMsg(e)}`);
    return 1;
  }

  // --seal-for-recipient now seals for real: a per-export BEK encrypts the
  // bundle body and is wrapped to the recipient DID. It can only wrap under
  // a recipient whose DID carries an embedded Ed25519 public key — refuse
  // (keeping the old gap behaviour) only when no key is resolvable.
  if (opts.sealForRecipient && !recipientKeyIsResolvable(opts.recipientIdentity)) {
    console.error(
      "[tn bundle] --seal-for-recipient requires a recipient did:key:z... with an " +
        "embedded Ed25519 public key to wrap the body key under; " +
        `${JSON.stringify(opts.recipientIdentity)} has none. Pass the recipient's real ` +
        "did:key, or drop --seal-for-recipient to ship an unsealed kit bundle.",
    );
    return 1;
  }

  let rt: NodeRuntime;
  try {
    rt = NodeRuntime.init(yamlPath);
  } catch (e) {
    console.error(`[tn bundle] ${errMsg(e)}`);
    return 1;
  }
  try {
    const groups = opts.groups ? opts.groups.split(",") : undefined;
    let out: string;
    if (opts.sealForRecipient) {
      // Mint an unsealed kit_bundle to a temp path, then seal it under a
      // fresh BEK wrapped to the recipient. Composes the existing seal
      // primitives (encryptBodyBlob + buildRecipientWraps); no plaintext
      // body ever reaches `opts.out`.
      const sealed = await mintAndSealBundle({
        recipientDid: opts.recipientIdentity,
        publisherKey: rt.keystore.device,
        outPath: opts.out,
        mintUnsealed: (tmpUnsealedPath: string) =>
          rt.bundleForRecipient(
            opts.recipientIdentity,
            tmpUnsealedPath,
            groups !== undefined ? { groups } : {},
          ),
      });
      out = sealed.outPath;
    } else {
      out = rt.bundleForRecipient(
        opts.recipientIdentity,
        opts.out,
        groups !== undefined ? { groups } : {},
      );
    }
    const cfg = rt.config;
    // The bundle was just minted — every requested group has a fresh
    // tn.recipient.added event in the log. Print a one-line summary the
    // user can hand off alongside the .tnpkg.
    const summaryGroups =
      groups ??
      [...cfg.groups.keys()].filter((g) => g !== "tn.agents").sort();
    console.log(`[tn bundle] wrote ${out}`);
    console.log(`[tn bundle]   recipient: ${opts.recipientIdentity}`);
    console.log(
      `[tn bundle]   ceremony:  ${cfg.ceremonyId}  (cipher=${cfg.cipher})`,
    );
    console.log(`[tn bundle]   groups:    ${JSON.stringify(summaryGroups)}`);
  } catch (e) {
    console.error(`[tn bundle] ${errMsg(e)}`);
    return 1;
  } finally {
    rt.close();
  }
  return 0;
}
