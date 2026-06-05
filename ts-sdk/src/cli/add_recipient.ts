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
// Behaviour, flags, stdout, and exit codes mirror the Python verb, EXCEPT
// for --seal-for-recipient: the TypeScript runtime has no producer path that
// seals a bundle body for a recipient (the seal primitives in
// core/recipient_seal.ts are wired into the consumer/absorb and browser
// project_seed paths only — `bundleForRecipient` always writes a plaintext
// body). So rather than silently shipping an UNSEALED bundle when the
// operator asked for sealing, this verb refuses --seal-for-recipient in ALL
// cases:
//   - exit 0 on success (prints `wrote`, `group:`, `recipient:` lines)
//   - exit 2 when --seal-for-recipient is combined with a label / synthetic
//     placeholder DID that has no embedded base58 public key to wrap under.
//   - exit 1 when --seal-for-recipient is requested for a real did:key (the
//     TS runtime gap — Python would seal here; TS cannot, and must not write
//     an unsealed bundle in its place). Matches `tn bundle`'s refusal.
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

  if (opts.sealForRecipient) {
    // Two refusal paths, both before any kit is written.
    //
    // 1) Label / synthetic placeholder DID: there is no embedded base58
    //    public key to wrap under. Reject with exit 2 (mirrors Python).
    if (!label.startsWith("did:") || recipientDid.startsWith("did:key:zLabel-")) {
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

    // 2) Real did:key: the seal primitives exist, but the TS runtime has no
    //    PRODUCER path that seals a bundle body for a recipient
    //    (bundleForRecipient always writes a plaintext body). Refuse rather
    //    than silently writing an UNSEALED bundle when the operator asked for
    //    sealing. Matches `tn bundle`'s refusal (exit 1).
    err.write(
      "[tn add_recipient] error: --seal-for-recipient is not supported by " +
        "the TypeScript runtime yet; bundleForRecipient writes an unsealed " +
        "body, so honoring the flag here would silently ship an UNSEALED " +
        "bundle. Run this ceremony from Python to seal the bundle body, or " +
        "drop --seal-for-recipient to knowingly ship an unsealed kit bundle.\n",
    );
    return 1;
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
