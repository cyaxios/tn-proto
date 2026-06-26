// In-process tests for `tn wallet export-mnemonic` (ts-sdk port of Python's
// `cmd_wallet_export_mnemonic`). We drive `walletExportMnemonicCmd` directly
// — not via subprocess — so c8 can measure line coverage of the source
// module, and capture stdout/stderr by patching the streams' `write`.
//
// Every branch is exercised:
//   * --yes + stored mnemonic  → banner printed, exit 0
//   * stored mnemonic, no --yes → warning, exit 2 (phrase NOT shown)
//   * no mnemonic stored        → guidance to stderr, exit 2
//   * identity load failure     → hint to stderr, exit 1

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";

import { walletExportMnemonicCmd } from "../src/cli/wallet_export_mnemonic.js";

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/** A 32-byte all-zero device seed, b64url-encoded (what Identity.load wants). */
const SEED_B64URL = Buffer.alloc(32).toString("base64url");

/** Write a minimal valid identity.json; optionally with a stored mnemonic. */
function seedIdentity(dir: string, mnemonic?: string): string {
  const p = join(dir, "identity.json");
  const doc: Record<string, unknown> = {
    version: 1,
    did: "did:key:z6MkProbe",
    device_pub_b64: SEED_B64URL,
    device_priv_b64_enc: SEED_B64URL,
    device_priv_enc_method: "none",
    seed_b64: SEED_B64URL,
    linked_vault: null,
    linked_account_id: null,
  };
  if (mnemonic !== undefined) doc["mnemonic_stored"] = mnemonic;
  writeFileSync(p, JSON.stringify(doc, null, 2), "utf8");
  return p;
}

/** Capture stdout + stderr while running `fn`, restoring the streams after. */
async function capture(fn: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((c: string | Uint8Array) => {
    out += typeof c === "string" ? c : Buffer.from(c).toString();
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((c: string | Uint8Array) => {
    err += typeof c === "string" ? c : Buffer.from(c).toString();
    return true;
  }) as typeof process.stderr.write;
  try {
    const code = await fn();
    return { code, out, err };
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
  }
}

test("export-mnemonic --yes with stored phrase prints banner and exits 0", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-expmn-"));
  try {
    const identityPath = seedIdentity(dir, MNEMONIC);
    const { code, out, err } = await capture(() =>
      walletExportMnemonicCmd({ yes: true, identityPath }),
    );
    assert.equal(code, 0);
    assert.equal(err, "");
    assert.match(out, /WRITE THIS DOWN NOW\./);
    assert.match(out, /={76}/); // the 76-char bar
    assert.ok(out.includes(`  ${MNEMONIC}\n`), "phrase must be printed on its own indented line");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("export-mnemonic without --yes warns and exits 2, never showing the phrase", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-expmn-"));
  try {
    const identityPath = seedIdentity(dir, MNEMONIC);
    const { code, out, err } = await capture(() =>
      walletExportMnemonicCmd({ identityPath }),
    );
    assert.equal(code, 2);
    assert.equal(err, "");
    assert.match(out, /ABOUT TO DISPLAY YOUR RECOVERY PHRASE\./);
    assert.match(out, /Re-run with --yes to confirm/);
    assert.ok(!out.includes(MNEMONIC), "the phrase must NOT leak without --yes");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("export-mnemonic with no stored mnemonic exits 2 with guidance", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-expmn-"));
  try {
    // No mnemonic_stored key at all.
    const identityPath = seedIdentity(dir);
    const { code, out, err } = await capture(() =>
      walletExportMnemonicCmd({ yes: true, identityPath }),
    );
    assert.equal(code, 2);
    assert.equal(out, "");
    assert.match(err, /no mnemonic stored on this machine/);
    assert.match(err, /--keep-mnemonic/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("export-mnemonic treats an empty stored mnemonic as not-stored (exit 2)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-expmn-"));
  try {
    const identityPath = seedIdentity(dir, "");
    const { code, err } = await capture(() =>
      walletExportMnemonicCmd({ yes: true, identityPath }),
    );
    assert.equal(code, 2);
    assert.match(err, /no mnemonic stored/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("export-mnemonic falls back to the default identity path when none is passed", async () => {
  // Point the OS-default resolver (defaultIdentityPath → TN_IDENTITY_DIR) at
  // an empty temp dir, then call WITHOUT identityPath to cover the `??`
  // default branch. No file there → the load-failure path (exit 1).
  const dir = mkdtempSync(join(tmpdir(), "tn-expmn-"));
  const prev = process.env["TN_IDENTITY_DIR"];
  process.env["TN_IDENTITY_DIR"] = dir;
  try {
    const { code, err } = await capture(() => walletExportMnemonicCmd({ yes: true }));
    assert.equal(code, 1);
    assert.match(err, /tn init <project>/);
  } finally {
    if (prev === undefined) delete process.env["TN_IDENTITY_DIR"];
    else process.env["TN_IDENTITY_DIR"] = prev;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("export-mnemonic on a missing identity exits 1 with the init/restore hint", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-expmn-"));
  try {
    const identityPath = join(dir, "does-not-exist.json");
    const { code, out, err } = await capture(() =>
      walletExportMnemonicCmd({ yes: true, identityPath }),
    );
    assert.equal(code, 1);
    assert.equal(out, "");
    assert.match(err, /tn init <project>/);
    assert.match(err, /tn wallet restore --mnemonic/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
