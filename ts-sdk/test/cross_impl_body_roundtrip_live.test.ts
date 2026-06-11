// CROSS-IMPL body round-trip through the LIVE vault: a TS PUSH of the REAL
// nested body layout (`body/keys/<name>`, `body/tn.yaml`) -> a PYTHON restore
// -> byte-match. Proves the whole-ceremony body crosses TS -> Python (the
// direction the owner asked to verify).
//
// This is the round-trip the older `wallet_sync_live.test.ts` could NOT do:
// it used FLAT member names to dodge the TS restore's old separator guard.
// Both push sides nest identically and the Python restore rebuilds subpaths;
// the TS restore now does too (restore.ts fix), so the body crosses BOTH ways
// — this pins the TS->Python leg end to end.
//
// CI-safe: skips when the dev vault is unreachable OR no Python+`tn` is found.
// Run (vault up): PLUMB_VAULT=http://127.0.0.1:38790 node --import tsx \
//   --import ./test/_setup_wasm.mjs --test test/cross_impl_body_roundtrip_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { encryptBodyBlob } from "../src/core/body_encryption.js";
import { bytesToB64, randomBytes } from "../src/core/encoding.js";
import { deriveAwkFromMaterial, wrapBekUnderAwk, type CredentialWrap } from "../src/vault/awk_bek.js";
import { VaultClient } from "../src/vault/client.js";

import { VAULT_BASE, devLogin, ulidish, uniqueHandle, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

const PYTHON_DIR = resolve(import.meta.dirname, "..", "..", "python");
const PY_CANDIDATES = [
  resolve(import.meta.dirname, "..", "..", ".venv", "Scripts", "python.exe"),
  resolve(import.meta.dirname, "..", "..", ".venv", "bin", "python"),
];
function findUsablePython(): string | null {
  for (const py of PY_CANDIDATES) {
    if (!existsSync(py)) continue;
    const probe = spawnSync(py, ["-c", "import tn"], {
      cwd: PYTHON_DIR,
      env: { ...process.env, PYTHONPATH: PYTHON_DIR },
      encoding: "utf8",
    });
    if (probe.status === 0) return py;
  }
  return null;
}
const PYTHON = reachable ? findUsablePython() : null;
const skip = !reachable ? "dev vault not reachable" : !PYTHON ? "no python+tn available" : false;

function devClient(token: string): VaultClient {
  return VaultClient.unauthed({
    baseUrl: VAULT_BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token,
  });
}

// Python restore: derive the BEK from the passphrase, restore the body blob
// to outDir via the real `_restore_with_token` (mirrors `tn wallet restore`).
const PY_RESTORE = `
import sys, json
from base64 import urlsafe_b64encode
from pathlib import Path
from tn.wallet_restore_passphrase import _derive_bek_via_passphrase
from tn import wallet_restore as wr
from tn import wallet_restore_loopback as wl
vault, project_id, passphrase, token, out = sys.argv[1:6]
bek = _derive_bek_via_passphrase(vault_url=vault, bearer=token, project_id=project_id, passphrase=passphrase)
tt = wl.TransferToken(
    vault_jwt=token, account_id="x", project_id=project_id,
    raw_bek_b64=urlsafe_b64encode(bek).decode().rstrip("="),
)
res = wr._restore_with_token(vault_url=vault, token=tt, out_dir=Path(out))
print(json.dumps([str(f) for f in res.files_written]))
`;

test(
  "cross-impl body round-trip: TS push (nested layout) -> Python restore -> MATCH",
  { skip },
  async () => {
    const dev = await devLogin(uniqueHandle("xbody"));
    const client = devClient(dev.token);

    // The REAL nested body layout BOTH push sides produce.
    const yamlBytes = new TextEncoder().encode(`ceremony:\n  id: live_${ulidish()}\n  mode: linked\n`);
    const keyPriv = randomBytes(32);
    const kit = new TextEncoder().encode("KIT:" + ulidish());
    const body = new Map<string, Uint8Array>([
      ["body/tn.yaml", yamlBytes],
      ["body/keys/local.private", keyPriv],
      ["body/keys/default.btn.mykit", kit],
    ]);

    // TS push: mint BEK -> wrap under AWK -> PUT wrapped-key -> PUT body frame.
    const projectId = ulidish();
    const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
    const awk = await deriveAwkFromMaterial(dev.passphrase, cred);
    const bek = randomBytes(32);
    const wrapped = await wrapBekUnderAwk(awk, bek);
    await client.putWrappedKey(projectId, { ...wrapped, label: "xbody" });
    const frame = await encryptBodyBlob(body, bek);
    await client.putEncryptedBlobAccount(
      projectId,
      {
        ciphertext_b64: bytesToB64(frame),
        nonce_b64: bytesToB64(frame.subarray(0, 12)),
        salt_b64: bytesToB64(randomBytes(16)),
        kdf: "pbkdf2-sha256",
        kdf_params: { iterations: 1 },
        cipher_suite: "aes-256-gcm",
        bundle_kind: "project-body-v1",
      },
      { ifMatch: "*" },
    );

    // Python restore (separate process, real Python `tn`).
    const out = mkdtempSync(join(tmpdir(), "xbody-restore-"));
    const r = spawnSync(
      PYTHON as string,
      ["-c", PY_RESTORE, VAULT_BASE, projectId, dev.passphrase, dev.token, out],
      { cwd: PYTHON_DIR, env: { ...process.env, PYTHONPATH: PYTHON_DIR }, encoding: "utf8" },
    );
    assert.equal(r.status, 0, `python restore failed: ${r.stderr}\n${r.stdout}`);

    // Byte-match the nested members Python wrote (the cross-impl bar).
    const read = (p: string) => new Uint8Array(readFileSync(join(out, ...p.split("/"))));
    assert.deepEqual(read("body/keys/local.private"), keyPriv, "local.private bytes match");
    assert.deepEqual(read("body/keys/default.btn.mykit"), new Uint8Array(kit), "kit bytes match");
    assert.deepEqual(read("body/tn.yaml"), new Uint8Array(yamlBytes), "tn.yaml bytes match");
  },
);
