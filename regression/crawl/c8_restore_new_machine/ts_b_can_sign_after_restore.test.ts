/**
 * SILO: C8 — Restore on new machine
 * TEST: TS machine B, after cross-language restore, can sign and verify
 *       new entries under the recovered keystore.
 * SEE: regression/crawl/c8_restore_new_machine/README.md
 *
 * Why this is its own test: the DID-match check in
 * `cross_language_restore.test.ts` is necessary but not sufficient —
 * it's satisfied by the public-key fields alone. The vault could
 * return a tnpkg with only public material and B would still see a
 * matching DID, then silently fail the first time B tries to sign.
 * This test exercises the signing path and gates verification via
 * `tn.read({ verify: true })`.
 *
 * Flow (same head as cross_language_restore.test.ts):
 *   1. Python A: tn.init(link=True), emit one entry, print did + claim_url.
 *   2. TS B: parse URL, dev-auth, fetch, decrypt, lay out, Tn.init.
 *   3. TS B: t.info("c8.b.entry", ...) — must succeed (signs under
 *      the recovered private key).
 *   4. TS B: Array.from(t.read({ verify: true })) — must not throw.
 *   5. Assert B's entry has did matching A's DID.
 *
 * Asserts (named):
 *   - "ts-b-did-matches-python-a"
 *   - "ts-b-emit-after-restore-succeeded"
 *   - "ts-b-read-verify-did-not-throw"
 *   - "ts-b-entry-signed-by-same-did"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";
import {
  deletePendingClaim,
  devAuthLogin,
  fetchPendingClaim,
  parseClaimUrl,
  restoreKeystoreTo,
} from "../../_shared/vault_test_helpers.ts";

const TN_VAULT_URL = process.env["TN_VAULT_URL"] ?? "http://127.0.0.1:8790";

function pythonMintAndUpload(tmpDir: string): {
  did: string;
  yaml_path: string;
  claim_url: string;
} {
  const py = String.raw`
import json, os, sys
os.environ['TN_IDENTITY_DIR'] = r'${tmpDir.replace(/\\/g, "\\\\")}_id'
os.environ.pop('TN_NO_LINK', None)
os.environ['TN_VAULT_URL'] = r'${TN_VAULT_URL}'
os.chdir(r'${tmpDir.replace(/\\/g, "\\\\")}')
import tn
tn.init(link=True)
cfg = tn.current_config()
yaml_path = str(cfg.yaml_path)
did = cfg.device.did
sync = os.path.join(os.path.dirname(yaml_path), '.tn', 'sync', 'claim_url.txt')
with open(sync, 'r', encoding='utf-8') as f:
    claim_url = f.read().strip()
tn.flush_and_close()
print(json.dumps({'did': did, 'yaml_path': yaml_path, 'claim_url': claim_url}))
`;
  const pythonBin =
    process.env["TN_REGRESSION_PYTHON"] ??
    "C:/codex/tn/tn_proto/.venv/Scripts/python.exe";
  const proc = spawnSync(pythonBin, ["-c", py], {
    encoding: "utf-8",
    timeout: 30000,
  });
  if (proc.status !== 0) {
    throw new Error(
      `pythonMintAndUpload: python exit ${proc.status}, stderr=${proc.stderr?.slice(0, 400)}`,
    );
  }
  const last = proc.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(last) as { did: string; yaml_path: string; claim_url: string };
}

test("C8 (cross-lang): TS B can sign new entries that verify after restore", async () => {
  setTestContext({
    silo: "c8",
    test: "c8_ts_b_can_sign_after_restore::sign_and_verify",
  });

  const aDir = mkdtempSync(join(tmpdir(), "c8-sign-py-a-"));
  const a = pythonMintAndUpload(aDir);

  const { vaultId, bek } = parseClaimUrl(a.claim_url);
  const login = await devAuthLogin(TN_VAULT_URL, "alice");
  const ciphertext = await fetchPendingClaim(TN_VAULT_URL, vaultId, login.token);

  const bDir = mkdtempSync(join(tmpdir(), "c8-sign-ts-b-"));
  const yamlB = restoreKeystoreTo(bDir, ciphertext, bek);

  let t: Tn | undefined;
  try {
    t = await Tn.init(yamlB);

    assertNamed({
      name: "ts-b-did-matches-python-a",
      expected: a.did,
      observed: t.did,
      onMiss:
        `Pre-condition for the signing test failed: TS B's DID (${t.did}) ` +
        `differs from Python A's (${a.did}). Signing test below is moot.`,
    });

    // Emit on B. If the private key didn't survive the round-trip,
    // this will throw (or produce an envelope the verifier rejects below).
    let emitErr: unknown = null;
    try {
      t.info("c8.b.entry", { note: "from-ts-b", linked_to_a_did: a.did });
    } catch (e) {
      emitErr = e;
    }
    assertNamed({
      name: "ts-b-emit-after-restore-succeeded",
      expected: null,
      observed: emitErr === null ? null : String(emitErr),
      onMiss:
        `t.info(...) on the restored B-side instance threw ` +
        `${String(emitErr)}. The keystore came over but the signing ` +
        `path can't use it — investigate the keystore: yaml field vs ` +
        `the laid-out keys/ dir, and ts-sdk/src/runtime/node_runtime.ts ` +
        `signing key load.`,
    });

    // Strict verify pass: tn.read({ verify: true }) raises on bad sig.
    let verifyErr: unknown = null;
    let bEntry: { event_type?: string; did?: string } | undefined;
    try {
      for (const e of t.read({ verify: true })) {
        // The user-emitted message hoists to `e` as both an Entry-like
        // typed object or the raw envelope (depending on `raw`). We
        // didn't pass raw, so e is an Entry — pull event_type + did.
        const obj = e as unknown as { event_type?: string; did?: string };
        if (obj.event_type === "c8.b.entry") bEntry = obj;
      }
    } catch (e) {
      verifyErr = e;
    }
    assertNamed({
      name: "ts-b-read-verify-did-not-throw",
      expected: null,
      observed: verifyErr === null ? null : String(verifyErr),
      onMiss:
        `t.read({ verify: true }) on B's log threw ${String(verifyErr)}. ` +
        `That means at least one envelope failed signature or chain ` +
        `verification — strongly suggests the recovered keystore has ` +
        `wrong/missing private material.`,
    });

    assertNamed({
      name: "ts-b-entry-signed-by-same-did",
      expected: a.did,
      observed: bEntry?.did,
      onMiss:
        `B's emitted envelope has did=${JSON.stringify(bEntry?.did)} but A's ` +
        `was ${JSON.stringify(a.did)}. Different identity signed B's entry — ` +
        `the recovered keystore is being shadowed by a freshly minted one.`,
    });
  } finally {
    if (t !== undefined) await t.close();
    await deletePendingClaim(TN_VAULT_URL, vaultId, login.token);
  }

  void assert;
});
