// `tn wallet restore --passphrase` - passphrase-fallback restore.
//
// TypeScript port of the Python CLI's `_restore_via_passphrase`
// (python/tn/cli_wallet.py). When the user can't run a browser (headless
// server, no display) they pass a vault session token and the account
// passphrase; we derive the project BEK locally (AWK -> BEK chain in
// ts-sdk/src/wallet/restore.ts `restoreViaPassphrase`) and restore without a
// browser handoff.
//
// Python is the reference. The flow:
//   1. require a session token (else die exit 2);
//   2. if no --project-id, GET /api/v1/account/projects with the bearer and
//      prompt the operator to pick (or require --project-id in non-TTY);
//   3. prompt for the account passphrase (TTY only; non-TTY dies exit 2);
//   4. build a session-token VaultClient, derive + restore via the SDK.

import { createInterface } from "node:readline";
import { stdin, stdout } from "node:process";

import { VaultClient, type VaultIdentity } from "../vault/client.js";
import { restoreViaPassphrase, RestoreError } from "../wallet/restore.js";
import { USER_AGENT } from "../version.js";

/** Print `tn-js: <msg>` to stderr and exit 2 — identical to the wallet
 *  dispatcher's `die`. Mirrors Python `_die(..., code=2)`. */
function die(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  process.exit(2);
}

function isTty(): boolean {
  return Boolean(stdin.isTTY && stdout.isTTY);
}

/** Prompt for a secret on the TTY with echo suppressed (getpass analog). */
async function promptPassphrase(label: string): Promise<string> {
  return new Promise<string>((resolve) => {
    const rl = createInterface({ input: stdin, output: stdout, terminal: true });
    // Mute the echo: replace the muted output's write so typed chars are
    // not displayed (the readline "prompt" itself is still shown once).
    const outAny = rl as unknown as { output?: { write: (s: string) => void }; _writeToOutput?: (s: string) => void };
    let muted = false;
    outAny._writeToOutput = (s: string): void => {
      if (muted) {
        // Only echo the prompt label / control sequences, not the input.
        if (s.includes(label)) stdout.write(s);
        return;
      }
      stdout.write(s);
    };
    rl.question(label, (answer) => {
      muted = false;
      stdout.write("\n");
      rl.close();
      resolve(answer);
    });
    muted = true;
  });
}

/** Bearer GET returning [status, bodyText]. Mirrors Python
 *  `wallet_restore_passphrase._bearer_get`. */
async function bearerGet(url: string, bearer: string): Promise<[number, string]> {
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "application/json",
        Authorization: `Bearer ${bearer}`,
      },
    });
  } catch (e) {
    throw new RestoreError(`could not reach ${url}: ${(e as Error).message}`);
  }
  const text = await resp.text();
  return [resp.status, text];
}

/** Stub identity for the session-token client. The passphrase flow holds a
 *  vault session token, not a device key — no DID challenge is run. A 401
 *  reauth would call signNonce; surface that as a clear error instead. */
const SESSION_TOKEN_IDENTITY: VaultIdentity = {
  did: "did:key:session-token",
  signNonce(): Uint8Array {
    throw new RestoreError(
      "session token rejected by the vault (401); obtain a fresh --session-token",
    );
  },
};

export interface WalletRestorePassphraseOpts {
  vaultUrl: string;
  outDir: string;
  sessionToken: string | null;
  projectId?: string | null;
  credentialId?: string | null;
}

/**
 * Passphrase fallback restore. Mirror of Python `_restore_via_passphrase`:
 * require a session token, resolve the project (flag or interactive pick),
 * prompt for the passphrase, then derive the BEK + restore through the SDK.
 * Returns the process exit code; error paths exit 2 via `die`.
 */
export async function walletRestorePassphraseCmd(
  opts: WalletRestorePassphraseOpts,
): Promise<number> {
  const sessionToken = opts.sessionToken;
  if (!sessionToken) {
    die(
      "--session-token is required for passphrase-only restore. Obtain one by " +
        "running OAuth in a browser and copying the token from the response " +
        "(or use the loopback flow instead).",
    );
  }

  const vaultUrl = opts.vaultUrl.replace(/\/+$/, "");
  let projectId = opts.projectId ?? null;

  if (!projectId) {
    const listUrl = `${vaultUrl}/api/v1/account/projects`;
    let code: number;
    let body: string;
    try {
      [code, body] = await bearerGet(listUrl, sessionToken);
    } catch (e) {
      die((e as Error).message);
    }
    if (code !== 200) {
      die(`projects list returned HTTP ${code}: ${body.slice(0, 200)}`);
    }
    let rows: Array<Record<string, unknown>>;
    try {
      rows = JSON.parse(body) as Array<Record<string, unknown>>;
    } catch (e) {
      die(`projects list returned non-JSON: ${(e as Error).message}`);
    }
    if (!Array.isArray(rows) || rows.length === 0) {
      die("no restorable projects on this account");
    }
    for (let i = 0; i < rows.length; i += 1) {
      const r = rows[i] as Record<string, unknown>;
      const label = (r.label as string) || (r.project_id as string) || "";
      stdout.write(`  [${i}] ${String(r.project_id ?? "")}  ${label}\n`);
    }
    if (!isTty()) {
      die("--project-id is required in non-TTY contexts");
    }
    const pick = await new Promise<string>((resolve) => {
      const rl = createInterface({ input: stdin, output: stdout });
      rl.question("Pick a project index: ", (a) => {
        rl.close();
        resolve(a.trim());
      });
    });
    const idx = Number.parseInt(pick, 10);
    if (!Number.isInteger(idx) || idx < 0 || idx >= rows.length) {
      die("invalid project pick");
    }
    // project_id is the vault-side project identity — without it there is no
    // wrapped-key / blob to fetch. Enforce it rather than letting a null slip
    // into the BEK derivation. Mirrors Python's guard.
    const picked = (rows[idx] as Record<string, unknown>).project_id;
    if (!picked) {
      die("selected project has no project_id");
    }
    projectId = String(picked);
  }

  if (!isTty()) {
    die("passphrase prompt requires a TTY");
  }
  const passphrase = await promptPassphrase("Enter your account passphrase: ");
  if (!passphrase) {
    die("empty passphrase");
  }

  // Build a VaultClient that authenticates with the session token directly
  // (no DID challenge). `restoreViaPassphrase` only reads client.token /
  // client.baseUrl + the credential/wrapped-key GETs, all bearer-authed.
  const client = VaultClient.unauthed({
    baseUrl: vaultUrl,
    identity: SESSION_TOKEN_IDENTITY,
    token: sessionToken,
  });

  const restoreOpts: { projectId: string; passphrase: string; outDir: string; credentialId?: string } = {
    projectId,
    passphrase,
    outDir: opts.outDir,
  };
  if (opts.credentialId != null) restoreOpts.credentialId = opts.credentialId;

  try {
    const result = await restoreViaPassphrase(client, restoreOpts);
    stdout.write(`\n[tn wallet restore] Restored ${result.filesWritten.length} file(s) to ${result.outDir}\n`);
    stdout.write(
      JSON.stringify({
        ok: true,
        verb: "wallet.restore",
        project_id: result.projectId,
        out_dir: result.outDir,
        files_written: result.filesWritten,
        notes: result.notes,
      }) + "\n",
    );
  } catch (e) {
    die(`restore failed: ${(e as { message?: string })?.message ?? e}`);
  }
  return 0;
}
