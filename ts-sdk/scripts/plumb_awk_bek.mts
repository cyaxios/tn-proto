// Live plumbing test: full AWK/BEK round-trip against a real dev vault.
// Push side uses the VaultClient API + crypto wrap helpers + the no-AAD
// frame body encrypt (mirroring Python). Restore side uses the real
// verb `restoreViaPassphrase` (= Python _restore_via_passphrase). Proves
// the whole chain end to end.
//
// Run:  node --import tsx scripts/plumb_awk_bek.mts   (dev vault up)

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";

import { encryptBodyBlob } from "../src/core/body_encryption.js";
import { bytesToB64, randomBytes } from "../src/core/encoding.js";
import {
  deriveAwkFromMaterial,
  wrapBekUnderAwk,
  type CredentialWrap,
} from "../src/vault/awk_bek.js";
import { VaultClient } from "../src/vault/client.js";
import { restoreViaPassphrase } from "../src/wallet/restore.js";

const BASE = process.env.PLUMB_VAULT ?? "http://127.0.0.1:34987";

function ulidish(): string {
  const C = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const r = crypto.getRandomValues(new Uint8Array(26));
  let s = "";
  for (let i = 0; i < 26; i += 1) s += C[r[i]! % 32];
  return s;
}

async function main(): Promise<void> {
  const handle = "frank";
  const resp = await fetch(`${BASE}/api/v1/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle }),
  });
  if (!resp.ok) throw new Error(`dev login ${resp.status}: ${await resp.text()}`);
  const dev = (await resp.json()) as { account_id: string; token: string; passphrase?: string };
  const passphrase = dev.passphrase ?? `tn-dev-${handle}`;
  console.log(`dev login OK  account_id=${dev.account_id}  passphrase=${passphrase}`);

  const client = VaultClient.unauthed({
    baseUrl: BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token: dev.token,
  });
  const projectId = ulidish();

  // ── Push (setup via API + crypto wrap helpers; mirrors browser mint) ──
  const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
  const awk = await deriveAwkFromMaterial(passphrase, cred);
  const bek = randomBytes(32);
  const wrapped = await wrapBekUnderAwk(awk, bek);
  await client.putWrappedKey(projectId, { ...wrapped, label: "plumbtest" });
  console.log(`putWrappedKey OK  project=${projectId}`);

  const payload = new TextEncoder().encode("plumbing body " + ulidish());
  // No-AAD nonce||ct frame of a STORED zip — the Python-faithful body shape.
  const frame = await encryptBodyBlob(new Map([["plumbtest.txt", payload]]), bek);
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
  console.log("putEncryptedBlobAccount OK (no-AAD frame body)");

  // ── Restore via the real verb (Python _restore_via_passphrase) ──
  const outDir = mkdtempSync(join(tmpdir(), "plumb-restore-"));
  const result = await restoreViaPassphrase(client, { projectId, passphrase, outDir });
  const restored = readFileSync(join(outDir, "plumbtest.txt"));
  const match = Buffer.from(restored).equals(Buffer.from(payload));
  console.log(`restoreViaPassphrase -> files=${result.filesWritten.length}  MATCH=${match}`);
  if (!match) {
    console.error("PLUMBING FAIL: restored body != pushed body");
    process.exit(1);
  }
  console.log("PLUMBING PASS: AWK/BEK round-trip (Python-faithful no-AAD body) vs dev vault");
}

main().catch((e) => {
  console.error("PLUMBING ERROR:", e);
  process.exit(1);
});
