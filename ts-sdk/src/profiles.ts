/** Named defaults for event signing, chaining, and output sinks. */

export type ProfileName = "transaction" | "audit" | "secure_log" | "telemetry";

/** Sink kind a profile declares as its baseline output target. */
export type SinkKind = "file_rotating" | "stdout";


export interface Profile {
  readonly name: ProfileName;
  readonly encrypts: boolean; // Always true. Floor.
  readonly signs: boolean;
  readonly chains: boolean;
  readonly default_sink: SinkKind;
  readonly intended_use: string;
}

const _CATALOG: Record<ProfileName, Profile> = {
  transaction: {
    name: "transaction",
    encrypts: true,
    signs: true,
    chains: true,
    default_sink: "file_rotating",
    intended_use:
      "Signed and chained events for grants, payments, and application actions.",
  },
  audit: {
    name: "audit",
    encrypts: true,
    signs: true,
    chains: true,
    default_sink: "file_rotating",
    intended_use:
      "Signed and chained business events with a rotating file sink.",
  },
  secure_log: {
    name: "secure_log",
    encrypts: true,
    signs: true,
    chains: false,
    default_sink: "file_rotating",
    intended_use:
      "Sensitive application logs with independently signed entries.",
  },
  telemetry: {
    name: "telemetry",
    encrypts: true,
    signs: false,
    chains: false,
    default_sink: "stdout",
    intended_use:
      "Encrypted traces, metrics, and debug events written to stdout with signing and chaining disabled.",
  },
};

/** Default profile for signed, chained events in a file. */
export const DEFAULT_PROFILE: ProfileName = "transaction";

/** Return all profile names in a stable order. */
export function allProfileNames(): ReadonlyArray<ProfileName> {
  return ["transaction", "audit", "secure_log", "telemetry"];
}

/**
 * Look up a profile by name. Throws with a friendly message listing
 * the catalog when the name is unknown.
 */
export function getProfile(name: string): Profile {
  if (!isKnownProfile(name)) {
    throw new Error(
      `unknown profile ${JSON.stringify(name)}; catalog: ` +
        JSON.stringify(allProfileNames()),
    );
  }
  return _CATALOG[name as ProfileName];
}

/** True iff ``name`` is a profile in the catalog. */
export function isKnownProfile(name: string): name is ProfileName {
  return name in _CATALOG;
}

/**
 * True iff a stream with this profile has a readable backlog.
 * ``stdout`` is forward-only; reading "all events ever" requires
 * a file or persistent sink. Read/watch on a stream with no
 * replay surface return empty rather than raising — a different
 * shape, not an error.
 */
export function hasReplaySurface(profile: ProfileName | Profile): boolean {
  const p = typeof profile === "string" ? getProfile(profile) : profile;
  return p.default_sink === "file_rotating";
}
