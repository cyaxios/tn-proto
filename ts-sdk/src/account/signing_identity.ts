// Signing-identity CASCADE for `account connect`.
//
// `account connect` signs sha256(code) and binds the SIGNER'S DID as an
// account principal (it lands in accounts.minted_dids[]). Python and
// TypeScript historically picked DIFFERENT signing keys for this, so the
// same operator bound a different DID depending on which binary ran. This
// resolver is the single, language-mirrored decision of which key signs
// the redeem. Its Python twin is
// `tn-proto/python/tn/sync_state.py::resolve_signing_identity`.
//
// Cascade — first available wins:
//   tier 2  SUPPLIED   — an explicit identity.json path passed by the
//                        caller (`--identity <path>`); the explicit override.
//   tier 1  MACHINE    — the machine-global identity.json under
//                        TN_IDENTITY_DIR / the platform default. This is the
//                        DEFAULT when a machine identity exists (matches
//                        Python's historical behaviour — the bug fix gives
//                        TS this machine preference it previously lacked).
//   tier 3  CEREMONY   — the per-ceremony keystore key
//                        (`<keystore>/local.private`). The FALLBACK for the
//                        headless / CI case where no machine identity has
//                        been minted (matches TS's historical behaviour).

import { existsSync } from "node:fs";

import { DeviceKey } from "../core/signing.js";
import { Identity, defaultIdentityPath } from "../identity.js";
import { loadKeystore } from "../runtime/keystore.js";

export type SigningTier = "supplied" | "machine" | "ceremony";

export interface ResolvedSigningIdentity {
  /** The did:key:z... that will be bound as the account principal. */
  did: string;
  /** The DeviceKey matching `did` (signs the redeem). */
  deviceKey: DeviceKey;
  /** Which cascade tier produced this key. */
  tier: SigningTier;
  /** The on-disk artefact the key was read from (diagnostic only). */
  sourcePath: string;
}

export class SigningIdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SigningIdentityError";
  }
}

export interface ResolveSigningIdentityOptions {
  /** Tier 2 override: explicit identity.json path (e.g. from `--identity`). */
  suppliedIdentityPath?: string | null;
  /** Tier 3 fallback: the ceremony's keystore directory. Resolved by the
   *  caller from the loaded config (`cfg.keystorePath`). */
  keystorePath?: string | null;
  /** Tier 1 path override (defaults to defaultIdentityPath()). Tests only. */
  machineIdentityPath?: string | null;
}

/**
 * Resolve which Ed25519 key signs an `account connect` redeem. See the
 * module-level cascade note. The Python twin is `resolve_signing_identity`
 * in `python/tn/sync_state.py`; keep the two in lockstep.
 *
 * @throws SigningIdentityError when the cascade exhausts with no usable key.
 */
export function resolveSigningIdentity(
  opts: ResolveSigningIdentityOptions = {},
): ResolvedSigningIdentity {
  // --- tier 2: SUPPLIED override -----------------------------------
  if (opts.suppliedIdentityPath) {
    let identity: Identity;
    try {
      identity = Identity.load(opts.suppliedIdentityPath);
    } catch (e) {
      throw new SigningIdentityError(
        `--identity ${opts.suppliedIdentityPath} could not be loaded: ${(e as Error).message}`,
      );
    }
    return {
      did: identity.did,
      deviceKey: identity.deviceKey(),
      tier: "supplied",
      sourcePath: opts.suppliedIdentityPath,
    };
  }

  // --- tier 1: MACHINE-GLOBAL identity (the default) ---------------
  const machinePath = opts.machineIdentityPath ?? defaultIdentityPath();
  if (existsSync(machinePath)) {
    let identity: Identity | null = null;
    try {
      identity = Identity.load(machinePath);
    } catch {
      // unreadable/corrupt machine identity: cascade past it to tier 3
    }
    if (identity) {
      return {
        did: identity.did,
        deviceKey: identity.deviceKey(),
        tier: "machine",
        sourcePath: machinePath,
      };
    }
  }

  // --- tier 3: PER-CEREMONY keystore key (the fallback) ------------
  if (opts.keystorePath && existsSync(opts.keystorePath)) {
    let device: DeviceKey | null = null;
    try {
      device = loadKeystore(opts.keystorePath).device;
    } catch {
      // unreadable keystore: fall through to the exhaustion error
    }
    if (device) {
      return {
        did: device.did,
        deviceKey: device,
        tier: "ceremony",
        sourcePath: opts.keystorePath,
      };
    }
  }

  throw new SigningIdentityError(
    "no signing identity for `account connect`: no machine identity at " +
      `${machinePath} and no usable ceremony keystore${opts.keystorePath ? ` at ${opts.keystorePath}` : ""}. ` +
      "Run `tn init <project>` to create one, or pass --identity <path>.",
  );
}
