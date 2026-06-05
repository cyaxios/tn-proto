// Live plumbing test: full AWK/BEK round-trip through the TS VaultClient
// API methods + wallet verbs against a real dev vault (TN_DEV_AUTH_BYPASS).
// Proves the wiring (auth -> getCredentialWrap -> derive AWK -> mint BEK
// -> putWrappedKey -> encrypt body -> putEncryptedBlobAccount -> getWrappedKey
// -> derive BEK -> getEncryptedBlob -> decrypt) end to end.
//
// Run:  node --import tsx scripts/plumb_awk_bek.mts  (with the dev vault up)

import { VaultClient } from "../src/vault/client.js";
import { mintWrappedKey, pushProjectBody, restoreProjectBody } from "../src/wallet/awk_sync.js";

const BASE = process.env.PLUMB_VAULT ?? "http://127.0.0.1:34987";

function ulidish(): string {
  const C = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const r = crypto.getRandomValues(new Uint8Array(26));
  let s = "";
  for (let i = 0; i < 26; i += 1) s += C[r[i]! % 32];
  return s;
}

async function main(): Promise<void> {
  // 1. dev login -> account JWT + the seeded passphrase. The passphrase
  // is only echoed when the persona is first created; on re-login it's
  // null, but it's deterministic (`tn-dev-{handle}`) and the credential
  // persists, so fall back to computing it.
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

  // 2. client carrying the account token (no DID-challenge needed).
  const client = VaultClient.unauthed({
    baseUrl: BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token: dev.token,
  });

  // 3. mint a wrapped-key for a fresh project (establishes account ownership).
  const projectId = ulidish();
  const bek = await mintWrappedKey(client, projectId, passphrase, { label: "plumbtest" });
  console.log(`mintWrappedKey OK  project=${projectId}  bek=${bek.length}B`);

  // 4. push a body under the freshly-minted BEK.
  const body = new TextEncoder().encode("PK plumbing body " + ulidish());
  const put = (await pushProjectBody(client, projectId, passphrase, body, { bek })) as {
    generation?: number;
  };
  console.log(`pushProjectBody OK  generation=${put.generation}`);

  // 5. restore via the passphrase chain and assert byte-equality.
  const restored = await restoreProjectBody(client, projectId, passphrase);
  const match = Buffer.from(restored).equals(Buffer.from(body));
  console.log(`restoreProjectBody -> ${restored.length}B  MATCH=${match}`);
  if (!match) {
    console.error("PLUMBING FAIL: restored body != pushed body");
    process.exit(1);
  }
  console.log("PLUMBING PASS: full AWK/BEK round-trip against the dev vault");
}

main().catch((e) => {
  console.error("PLUMBING ERROR:", e);
  process.exit(1);
});
