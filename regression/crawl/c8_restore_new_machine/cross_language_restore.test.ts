/**
 * SILO: C8 — Restore on new machine
 * TEST: cross-language. Python machine A uploads; TS machine B restores.
 *       Same ceremony DID, TS-side `Tn.init(yamlPath)` works.
 * SEE: regression/crawl/c8_restore_new_machine/README.md
 *
 * Why cross-language is the right shape here: the TS SDK has no
 * vault auto-backup today (see critic log, C7 TS section), so a
 * TS-only round-trip isn't possible. But the *restore* half is
 * symmetric — it's just decrypt + lay-out + `Tn.init`. Driving Python
 * A → TS B proves the wire format and zip layout are language-agnostic,
 * which is arguably a STRONGER test than TS-only.
 *
 * Flow:
 *   1. Spawn a Python child process that does:
 *        - hop into tmp dir, set TN_IDENTITY_DIR+TN_VAULT_URL+clear NO_LINK
 *        - tn.init(link=True)
 *        - print the ceremony DID + claim_url + yaml_path as JSON
 *      Read that JSON from stdout.
 *   2. TS: parseClaimUrl(claim_url) → (vault_id, bek)
 *   3. TS: devAuthLogin("alice"), fetchPendingClaim(vault_id, token)
 *   4. TS: restoreKeystoreTo(<tmpdir_B>, ciphertext, bek)
 *   5. TS: await Tn.init(yaml_b). Assert t.did equals Python A's DID.
 *   6. Cleanup: deletePendingClaim so the live vault stays clean.
 *
 * Asserts (named):
 *   - "python-a-printed-valid-payload"
 *   - "claim-url-parses-bek-32"
 *   - "vault-returned-non-empty-ciphertext"
 *   - "ts-b-yaml-on-disk"
 *   - "ts-b-did-matches-python-a"
 *
 * Failure modes the test catches:
 *   - Python and TS disagree about the body-blob format (AES-GCM
 *     nonce layout, zip structure, body/ prefix convention).
 *   - TS Tn.init doesn't load the keystore from the right path
 *     (yaml's keystore: field convention).
 *   - The vault's dev-auth flow doesn't authorize the GET for a
 *     pending-claim it didn't itself authenticate (cross-flow auth).
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

/** Spawn `python -c '...'` to do machine A's init+upload. Read JSON
 *  from stdout: `{ did, yaml_path, claim_url }`.
 */
function pythonMintAndUpload(tmpDir: string): {
  did: string;
  yaml_path: string;
  claim_url: string;
} {
  const py = String.raw`
import json, os, sys
# Redirect TN's user-home identity into the tmpdir so this Python
# process doesn't pollute the developer's real ~/AppData/Roaming/tn/.
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
  // Pick the regression venv python. If that ever changes, set
  // TN_REGRESSION_PYTHON env.
  const pythonBin =
    process.env["TN_REGRESSION_PYTHON"] ??
    "C:/codex/tn/tn_proto/.venv/Scripts/python.exe";
  const proc = spawnSync(pythonBin, ["-c", py], {
    encoding: "utf-8",
    timeout: 30000,
  });
  if (proc.status !== 0) {
    throw new Error(
      `pythonMintAndUpload: python exited ${proc.status}. ` +
        `stdout=${proc.stdout?.slice(0, 600)} ` +
        `stderr=${proc.stderr?.slice(0, 600)}`,
    );
  }
  const last = proc.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(last) as {
    did: string;
    yaml_path: string;
    claim_url: string;
  };
}

test("C8 (cross-lang): Python A uploads, TS B restores, same DID", async () => {
  setTestContext({
    silo: "c8",
    test: "c8_cross_language_restore::python_a_to_ts_b",
  });

  // Machine A on the Python side.
  const aDir = mkdtempSync(join(tmpdir(), "c8-py-a-"));
  const a = pythonMintAndUpload(aDir);

  assertNamed({
    name: "python-a-printed-valid-payload",
    expected: true,
    observed:
      typeof a.did === "string" &&
      a.did.startsWith("did:key:") &&
      typeof a.claim_url === "string" &&
      a.claim_url.includes("/claim/"),
    onMiss: `Python A's output looked malformed: ${JSON.stringify(a)}`,
  });

  // Parse the claim URL on the TS side.
  const { vaultId, bek } = parseClaimUrl(a.claim_url);

  assertNamed({
    name: "claim-url-parses-bek-32",
    expected: 32,
    observed: bek.length,
    onMiss:
      `parseClaimUrl returned BEK of length ${bek.length}, expected 32. ` +
      "If this fails, the URL spec or base64url decoding has drifted.",
  });

  // Auth + fetch as a TS user.
  const login = await devAuthLogin(TN_VAULT_URL, "alice");
  const ciphertext = await fetchPendingClaim(TN_VAULT_URL, vaultId, login.token);

  assertNamed({
    name: "vault-returned-non-empty-ciphertext",
    expected: true,
    observed: ciphertext.length > 0,
    onMiss: `GET /pending-claims/${vaultId} returned ${ciphertext.length} bytes.`,
  });

  // Machine B on the TS side — fresh tmpdir, decrypt + lay out.
  const bDir = mkdtempSync(join(tmpdir(), "c8-ts-b-"));
  const yamlB = restoreKeystoreTo(bDir, ciphertext, bek);

  assertNamed({
    name: "ts-b-yaml-on-disk",
    expected: true,
    observed: yamlB.endsWith("tn.yaml"),
    onMiss:
      `restoreKeystoreTo returned ${JSON.stringify(yamlB)}, ` +
      "expected a path ending in tn.yaml.",
  });

  // tn.init on B — same DID expected.
  let t: Tn | undefined;
  try {
    t = await Tn.init(yamlB);
    assertNamed({
      name: "ts-b-did-matches-python-a",
      expected: a.did,
      observed: t.did,
      onMiss:
        `TS machine B loaded DID=${t.did}, Python A's was ${a.did}. ` +
        "Either the keystore didn't round-trip through the encrypt/decrypt " +
        "pipeline, or TS Tn.init is minting a fresh identity instead of " +
        "loading the restored one. Check the keystore: path in " +
        yamlB +
        " and ts-sdk's keystore loader.",
    });
  } finally {
    if (t !== undefined) await t.close();
    // Best-effort cleanup so the live vault doesn't accumulate.
    await deletePendingClaim(TN_VAULT_URL, vaultId, login.token);
  }

  // Silence unused-import warning under strict mode.
  void assert;
});
