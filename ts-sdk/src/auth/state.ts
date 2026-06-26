/**
 * tn.auth shared contract layer - mirrors python tn/auth.py.
 *
 * The Verdict values and VERDICT_MESSAGE table MUST stay byte-identical to the
 * Python ones (asserted by a cross-impl parity test). Design:
 * docs/guide/auth-namespace-design.md
 *
 * State machine (resting state is "backed_up"), keyed on three layers:
 *   linked     - the local file claims an account
 *   enrolled   - the vault agrees this device belongs to that account
 *   keyCached  - the backup key (AWK) is cached on this machine
 */

export type Verdict =
  | "not_logged_in"
  | "one_sided_link"
  | "linked_no_key"
  | "backed_up";

/** Verdict -> one-line human message. Keep byte-identical to Python's
 *  VERDICT_MESSAGE in tn/auth.py (cross-impl parity test). */
export const VERDICT_MESSAGE: Record<Verdict, string> = {
  not_logged_in: "Not logged in - run `tn auth login`.",
  one_sided_link:
    "One-sided link: this device claims an account the vault has not " +
    "enrolled. Run `tn auth login` to repair.",
  linked_no_key:
    "Linked, but no backup key cached - backups will not run. Run " +
    "`tn auth login --account-passphrase`.",
  backed_up: "Backed up and ready.",
};

/** Map the three layers onto the state machine. Pure; the shared contract.
 *  `enrolled === null` means "not checked this call" and is treated as
 *  not-failing (mirrors Python's tri-state). */
export function computeVerdict(args: {
  linked: boolean;
  enrolled: boolean | null;
  keyCached: boolean;
}): Verdict {
  if (!args.linked) return "not_logged_in";
  if (args.enrolled === false) return "one_sided_link";
  if (!args.keyCached) return "linked_no_key";
  return "backed_up";
}

/** Immutable snapshot returned by every tn.auth verb. A class (not a bare
 *  interface) so `verdict`/`message` are getters, mirroring Python's
 *  @property. */
export class AuthState {
  constructor(
    readonly deviceDid: string | null,
    readonly accountId: string | null,
    readonly vaultUrl: string,
    readonly linked: boolean,
    readonly enrolled: boolean | null,
    readonly keyCached: boolean,
  ) {}

  get verdict(): Verdict {
    return computeVerdict({
      linked: this.linked,
      enrolled: this.enrolled,
      keyCached: this.keyCached,
    });
  }

  get message(): string {
    return VERDICT_MESSAGE[this.verdict];
  }
}

/** The ONLY error tn.auth verbs throw - the failure the caller explicitly
 *  asked about (a rejected connect code, or a headless login with no usable
 *  credential). Mirrors Python's tn.auth.AuthError. */
export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}
