/**
 * TN evidence profiles — fixed, SDK-tuned types.
 *
 * Mirrors python/tn/_profiles.py exactly. Profiles are SDK-fixed —
 * users pick one per stream; they do not compose, extend, or invent
 * their own. The catalog below is the source of truth for both
 * Python and TypeScript SDKs; any change here MUST land in lockstep
 * with the Python catalog.
 *
 * Always-on floor: encryption is the unconditional guarantee across
 * the catalog. Signing, chaining, durability, and sink choice vary
 * per profile.
 */

export type ProfileName = "transaction" | "audit" | "secure_log" | "telemetry";

/** Sink kind a profile declares as its baseline output target. */
export type SinkKind = "file_rotating" | "stdout";

/**
 * Flush semantics:
 *   - ``fsync``    — write + fsync after every entry; max durability.
 *   - ``buffered`` — write to OS buffer, flush at batch boundary.
 *   - ``async``    — handler accepts entry, returns immediately;
 *                    background drains.
 */
export type FlushPolicy = "fsync" | "buffered" | "async";

export interface Profile {
  readonly name: ProfileName;
  readonly encrypts: boolean; // Always true. Floor.
  readonly signs: boolean;
  readonly chains: boolean;
  readonly flush: FlushPolicy;
  readonly default_sink: SinkKind;
  readonly intended_use: string;
}

const _CATALOG: Record<ProfileName, Profile> = {
  transaction: {
    name: "transaction",
    encrypts: true,
    signs: true,
    chains: true,
    flush: "fsync",
    default_sink: "file_rotating",
    intended_use:
      "Grants, revokes, payments, agent actions, security events. " +
      "Maximum evidence: signed, chained, durable. Use when " +
      "reconstruction and non-repudiation matter.",
  },
  audit: {
    name: "audit",
    encrypts: true,
    signs: true,
    chains: true,
    flush: "buffered",
    default_sink: "file_rotating",
    intended_use:
      "Normal business events where reconstruction matters but " +
      "you can afford a small flush window. Same evidence as " +
      "transaction; weaker durability.",
  },
  secure_log: {
    name: "secure_log",
    encrypts: true,
    signs: true,
    chains: false,
    flush: "buffered",
    default_sink: "file_rotating",
    intended_use:
      "Sensitive application logs where signing matters more than " +
      "sequence. No chain — each entry stands alone. Cheaper to " +
      "scale than audit/transaction.",
  },
  telemetry: {
    name: "telemetry",
    encrypts: true,
    signs: false,
    chains: false,
    flush: "async",
    default_sink: "stdout",
    intended_use:
      "Fast-as-stdlib-logger profile. Encryption still applies; " +
      "signing is dropped to approach zero overhead. Intended for " +
      "high-volume traces, metrics, debug noise where evidence is " +
      "overkill. Will be regression-tested for near-zero perf " +
      "impact vs Python's logging.Logger.",
  },
};

/**
 * The default profile picked when ``Tn.init(name)`` is called
 * without an explicit ``profile`` option. Conservative on every
 * axis: signed, chained, durable, file-sink. Onboarding-as-trust
 * means the bare default carries every guarantee.
 *
 * Users opt *down* explicitly. Never silently degrade evidence.
 */
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
