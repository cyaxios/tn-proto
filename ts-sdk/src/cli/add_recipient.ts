// Top-level `tn add_recipient` CLI verb — TS parity port of Python's
// `cmd_add_recipient` (python/tn/cli.py). One-shot mint + bundle: given a
// group and a recipient DID (or a friendly label), mint a reader kit and
// write a `.tnpkg` kit_bundle the recipient can absorb.
//
//   tn add_recipient <group> <did-or-label> [--out path] [--yaml path]
//                    [--seal-for-recipient]
//
// A bare label like `professor` is auto-prefixed with `did:key:zLabel-` so
// the attestation event still records something identifiable. The default
// output filename is `./<safe-label>.tnpkg` in the cwd, matching the
// student one-liner `tn add_recipient default professor`.
//
// Behaviour, flags, stdout, and exit codes mirror the Python verb:
//   - exit 0 on success (prints `wrote`, `group:`, `recipient:` lines)
//   - exit 2 when `--seal-for-recipient` is combined with a label / synthetic
//     DID that has no embedded base58 public key to wrap under.
//
// The mint + bundle itself is delegated to the existing SDK surface
// (`Tn.init(...).pkg.bundleForRecipient`) — no crypto is re-implemented here.

import { resolve as pathResolve } from "node:path";
import { Tn } from "../tn.js";

export interface AddRecipientOpts {
  /** Group name to mint a kit for (e.g. "default"). */
  group: string;
  /** Recipient DID, or a friendly label (auto-prefixed with did:key:zLabel-). */
  recipient: string;
  /** Output .tnpkg path. Default: ./<safe-label>.tnpkg in the cwd. */
  out?: string | undefined;
  /** Path to tn.yaml. Default: discovered via TN_YAML / ./tn.yaml / etc. */
  yaml?: string | undefined;
  /** Wrap the bundle body under a per-export key only the recipient can unwrap. */
  sealForRecipient?: boolean | undefined;
  /** Sink for normal output (defaults to process.stdout). */
  stdout?: { write(s: string): void } | undefined;
  /** Sink for error output (defaults to process.stderr). */
  stderr?: { write(s: string): void } | undefined;
}

/** Sanitize a label into a filesystem-safe stem (mirrors Python's regex). */
function safeStem(label: string): string {
  return label.replace(/[^A-Za-z0-9._-]/g, "_");
}

/**
 * Run the `tn add_recipient` verb. Returns the process exit code
 * (0 success, 2 on the seal/label conflict) so a CLI shell can
 * `process.exit(await addRecipientCmd(...))`.
 */
export async function addRecipientCmd(opts: AddRecipientOpts): Promise<number> {
  const out = opts.stdout ?? process.stdout;
  const err = opts.stderr ?? process.stderr;
  const label = opts.recipient;

  let recipientDid: string;
  let outDefaultStem: string;
  if (label.startsWith("did:")) {
    recipientDid = label;
    // Python: out_default_stem from label.split(":")[-1]. A `did:`-prefixed
    // string always splits into >= 2 parts, so the tail is always defined.
    const parts = label.split(":");
    outDefaultStem = safeStem(parts[parts.length - 1]!);
  } else {
    // Stable placeholder DID from the label — recorded on the attestation
    // event so the kit-recipient lookup works.
    recipientDid = `did:key:zLabel-${label}`;
    outDefaultStem = safeStem(label) || "recipient";
  }

  // --seal-for-recipient needs a real key-DID with an embedded base58 public
  // key. A friendly label synthesizes a `did:key:zLabel-*` placeholder that
  // has nothing to wrap under, so reject the combination with a clear message
  // (matches Python's exit code 2).
  if (
    opts.sealForRecipient &&
    (!label.startsWith("did:") || recipientDid.startsWith("did:key:zLabel-"))
  ) {
    err.write(
      "[tn add_recipient] error: --seal-for-recipient requires a real " +
        "key-DID for the recipient (one with an embedded base58 public " +
        "key). Friendly labels synthesize a placeholder DID that has no " +
        "public key, so the seal step has nothing to wrap under. Got " +
        `${JSON.stringify(label)}. Pass the recipient's real did:key:z... instead, or ` +
        "drop --seal-for-recipient to ship an unsealed kit bundle.\n",
    );
    return 2;
  }

  const outPath = opts.out
    ? pathResolve(opts.out)
    : pathResolve(process.cwd(), `${outDefaultStem}.tnpkg`);

  const tn = await Tn.init(opts.yaml);
  try {
    const result = await tn.pkg.bundleForRecipient({
      recipientDid,
      outPath,
      groups: [opts.group],
    });
    out.write(`[tn add_recipient] wrote ${result.bundlePath}\n`);
    out.write(`[tn add_recipient]   group:     ${opts.group}\n`);
    out.write(`[tn add_recipient]   recipient: ${recipientDid}\n`);
  } finally {
    await tn.close();
  }
  return 0;
}
