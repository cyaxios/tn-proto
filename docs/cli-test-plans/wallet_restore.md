# `wallet restore` — same-language round-trip test contract

Status: **contract + audit only**. No new tests are written or run by this
document. The audit below reflects the tree as of 2026-06-05.

The `wallet restore` verb reconstructs a ceremony's keystore + `tn.yaml` on a
fresh machine from a backup that the vault is holding. A *same-language*
round-trip means the backup is produced and restored by the **same** SDK
(Python→Python or TS→TS); cross-language restore is a separate contract.

A real round-trip needs a **LIVE VAULT** — there is no way to fake the
fetch-the-blob half without one, because the ciphertext the SDK decrypts lives
server-side and is keyed off the project id + a bearer/JWT the vault issues.

---

## 1. Flow

A backup is produced by one of:

| Producer verb | What it pushes | Where the BEK lives |
|---|---|---|
| `tn init --link` (a.k.a. `tn.init(link=True)`) | encrypted `.tnpkg` (`body/encrypted.bin` + `manifest.json`) to a pending-claim row | URL fragment `#k=<bek_b64url>` in the claim URL |
| `tn init upload` / init-upload | encrypted blob bound to the account/project (`/encrypted-blob`) | wrapped server-side under AWK→BEK; never on the wire in cleartext |
| `wallet sync` push | refreshes the same account-bound encrypted blob | same as init upload |

Restore then pulls the blob back into an **empty identity dir** and lays out
`tn.yaml` + `keys/`.

### Python paths (`python/tn/cli.py::cmd_wallet_restore`)

`cmd_wallet_restore` branches on `_is_new_flow_restore(args)` (cli.py:948):

- **Mnemonic restore (legacy)** — selected by `--mnemonic` / `--mnemonic-file`.
  Rebuilds the device key from the BIP39 phrase (`Identity.from_mnemonic`),
  writes `identity.json`, then (if `--vault`) lists linked ceremonies and pulls
  each. Refuses to clobber an existing identity without `--force` (cli.py:1084).
  With no `--vault` it restores identity only.
- **Account-bound / loopback restore (default)** — `_cmd_wallet_restore_account_bound`
  (cli.py:1123). Starts a one-shot loopback receiver on `127.0.0.1`
  (`wallet_restore_loopback.LoopbackReceiver`), opens the browser to
  `<vault>/restore?return_to=<cb>&state=<nonce>`, waits for the browser to POST a
  `TransferToken` (`vault_jwt`, `account_id`, `project_id`, `raw_bek_b64`). The
  **browser** does the WebAuthn-PRF / passkey unwrap and hands the raw BEK over
  loopback. The CLI then calls `_restore_with_token` →
  `_fetch_encrypted_blob` (GET `/api/v1/projects/{id}/encrypted-blob`, legacy
  fallback `/encrypted-backup`) → `_decrypt_blob_with_bek` (AES-256-GCM,
  `nonce||ct+tag`, no AAD) → `_write_restored_bytes` (unzip the tn.export frame,
  or write a raw `<project>.tnpkg`).
- **Passphrase restore (headless fallback, D-22)** — `_restore_via_passphrase`
  (cli.py:1209), reached when `--passphrase` is set. Requires `--jwt`. Derives
  the credential key locally via **PBKDF2-SHA256** (`wallet_restore_passphrase`),
  unwraps AWK (AAD `tn-vault-awk-wrap-v1`) then BEK (AAD `tn-vault-bek-wrap-v1`),
  builds a synthetic `TransferToken`, and joins the same
  `_restore_with_token` blob-fetch+decrypt+write path. Argon2id credentials are
  rejected here — they require the browser path.

### TS paths (`ts-sdk/src/wallet/restore.ts`)

- **`restoreViaLoopback`** (restore.ts:370) — browser loopback dance, mirror of
  the Python default. Starts `LoopbackReceiver`, surfaces the `/restore` URL via
  `onRestoreUrl`, waits for the `TransferToken`, decodes the BEK, then
  `restoreWithBek` (fetch `/encrypted-blob` → `decryptBlobWithBek` → unpack frame
  → write). This is the browser-driven variant.
- **`restoreViaPassphrase`** (restore.ts:325) — headless. `_deriveBekViaPassphrase`
  pulls `client.getCredentialWrap()` + `client.getWrappedKey(projectId)`, runs
  PBKDF2 → unwrap AWK → unwrap BEK (`deriveBekFromMaterial`), then `restoreWithBek`.
- **`restoreWithBek`** (restore.ts:276) — the shared tail: fetch encrypted blob,
  AES-GCM decrypt, unpack, write. Both entry points funnel here.

Distinctions to keep straight:

- **passphrase-restore** — CLI derives the BEK locally from a passphrase
  (PBKDF2 only); no browser. Needs `--jwt` (Python) / an authenticated
  `VaultClient` (TS).
- **loopback (browser)-restore** — browser does the passkey unwrap and POSTs the
  raw BEK back over loopback; CLI never sees the passphrase/passkey.
- **mnemonic-restore** — Python-only legacy path; rebuilds the device key from a
  BIP39 phrase, not the account AWK/BEK hierarchy. The BEK/blob hierarchy is not
  used; it pulls per-ceremony backups via `VaultClient`.

---

## 2. What it would take to actually work

A same-language round-trip cannot be exercised with mocks because the restore
half is defined by what the vault returns. It needs:

1. A **live dev vault** (`tn_proto_web`, run as `python -m src` with
   `TN_DEV_AUTH_BYPASS=1`, ephemeral Mongo + blob dir). The regression suite
   already has this as `regression/_shared/vault_subprocess.py::vault_server`.
2. A project with a **pushed backup**:
   - For loopback/passphrase restore: an account + project whose encrypted blob
     is reachable at `/api/v1/projects/{id}/encrypted-blob`, plus the per-project
     `wrapped-key` row and an account `credentials` row carrying the PBKDF2 wrap
     material — produced by `init upload` or a `wallet sync` push.
   - For the claim-URL/init-link variant: a pending-claim row produced by
     `tn.init(link=True)`.
3. The **recovery secret** matching the producer: the account **passphrase**
   (passphrase path), the **passkey** the browser unwraps (loopback path), or the
   BIP39 **mnemonic** (mnemonic path). For the claim-URL variant the BEK is in the
   URL fragment.
4. An **empty target identity dir** (`machine_b_tmpdir` shape) and a bearer JWT
   (dev-auth login) so the GET is authorized.

Then: run restore into the empty dir, `tn.init(yaml_path=<restored>/tn.yaml)`,
and assert continuity.

---

## 3. Setup / preconditions

- Dev vault up and reachable; `TN_VAULT_URL` pointed at it; `TN_NO_LINK` cleared.
  (Mirrors `c8_restore_new_machine/conftest.py::hermetic_machine_with_live_vault`.)
- Mongo reachable on `localhost:27017` (or `$VAULT_MONGO_URI`); CI runs it as a
  service.
- An account (dev-auth `handle="alice"`) with a registered **PBKDF2** credential
  (so the headless passphrase path is exercisable — Argon2id forces the browser).
- A project with a **real backup pushed** (init upload or `wallet sync` push), so
  `/encrypted-blob`, `/wrapped-key`, and `/account/credentials` all return rows.
- The recovery secret on hand: the passphrase for the passphrase path, a
  scriptable passkey/PRF stand-in for the loopback path, the mnemonic for the
  mnemonic path.
- A fresh empty `out_dir` for the restore target. Producer runtime closed
  (`tn.flush_and_close()`) before restore, to prove restore doesn't lean on the
  producer's live state.

---

## 4. PASS conditions

1. `wallet restore` exits **0**.
2. Restored `keys/` files + `tn.yaml` **byte-match** the originals the producer
   sealed (the decrypted body is the exact set the export wrote; private key
   material is present, not just public).
3. `tn.init(yaml_path=<restored>/tn.yaml)` loads, and the restored
   `cfg.device.did` **equals** the producer's ceremony DID.
4. The restored ceremony can **`read` its own prior entries**, and — proving the
   *private* key round-tripped — can **sign a new entry** that
   `tn.read(verify=True)` accepts (no `VerifyError`).
5. The user's real home/identity dir is untouched (restore writes only to
   `out_dir` / the target machine dir).

---

## 5. FAIL conditions (the test MUST catch)

- **Wrong passphrase / wrong mnemonic** — PBKDF2 derives the wrong credential
  key, AWK/BEK unwrap fails the GCM tag → `RestoreError` ("unwrap failed (wrong
  passphrase or KDF mismatch)") / bad-mnemonic exit; restore must NOT silently
  write a partial keystore. Mnemonic path must reject a malformed phrase
  (`IdentityError`).
- **Missing project** — `/encrypted-blob` (and the `/encrypted-backup` fallback)
  both 404 → `RestoreError` "encrypted blob not found"; non-zero exit.
- **Tampered blob** — any bit-flip in `nonce||ct+tag` fails the AES-GCM auth tag
  → `RestoreError` "decryption failed (wrong BEK or corrupted blob)"; nothing
  written.
- **Partial / empty backup** — blob shorter than `12+16` bytes → `RestoreError`
  "ciphertext too short"; a decrypted body missing `tn.yaml` or with an empty
  `keys/` must fail loudly, not produce a half-laid-out dir.
- **Wrong-length BEK** — `raw_bek_b64` not decoding to 32 bytes → `RestoreError`
  "expected 32".
- (Loopback) **state-nonce mismatch / missing token fields / non-loopback peer**
  — receiver rejects (400/403); a stale cross-run token must not be delivered.

---

## 6. Current test audit

### Python — `python/tests/test_wallet_restore.py` (24 tests, all PASS locally)

**Verdict: NOT a round-trip. Mock/loopback-stub only; no live vault, no CLI verb,
no passphrase derivation chain.**

- `LoopbackReceiver` lifecycle (lines 51–392): bind/accept/reject/timeout/CORS/
  peer-IP. Exercises the transport, never the restore.
- `_decrypt_blob_with_bek` round-trip + wrong-key + short-input (402–428): unit
  AES-GCM with a **locally generated** BEK — no vault.
- `_write_restored_bytes` frame-unpack + raw fallback (446–473): local bytes.
- `_restore_with_token` "full flow" (479–517): HTTP layer **monkeypatched**
  (`monkeypatch.setattr(wr, "_http_request", fake_request)`, line 501) returning a
  hand-built `ciphertext_b64`. The BEK and ciphertext are fabricated in-test
  (483–488). This is the closest to end-to-end and it is fully mocked.
- 404 + bad-BEK-length error paths (520–553): mocked.

What is **never** touched by this file:
- `cmd_wallet_restore` / `_cmd_wallet_restore_account_bound` / `_restore_via_passphrase`
  (the CLI verb).
- `wallet_restore_passphrase.py` — the PBKDF2 → AWK-unwrap → BEK-unwrap chain
  (`_derive_bek_via_passphrase`, `_derive_credential_key_pbkdf2`, `_aes_gcm_unwrap`,
  `_fetch_credential_with_wrap`, `_fetch_wrapped_key`) has **zero** coverage.
- Any real vault fetch.

### TS — `ts-sdk/test/wallet_restore.test.ts` + `restore_loopback.test.ts`

Both are in the `package.json` `test` allowlist, so they run.

**Verdict: NOT a round-trip. Mock-fetch + loopback-stub; the two public restore
entry points are untested.**

- `wallet_restore.test.ts`: `decryptBlobWithBek` round-trip / wrong-BEK / short /
  bad-length (136–160); `tryUnpackExportFrame` zip + legacy + opaque (164–191);
  `restoreWithBek` "full path" (195–238) and error paths (240–302) — all with a
  **mock `fetchImpl`** returning a locally sealed blob. Header comment is explicit:
  "One integration test wires a mock fetch so we exercise the full restoreWithBek
  without a live vault" (lines 5–6).
- `restore_loopback.test.ts`: `LoopbackReceiver` transport only (token delivery,
  state mismatch, missing fields, CORS, GET-405, timeout). No restore.

What is **never** touched:
- `restoreViaLoopback` (restore.ts:370) and `restoreViaPassphrase` (restore.ts:325)
  — the actual public verbs — and `_deriveBekViaPassphrase` (restore.ts:306) /
  `deriveBekFromMaterial`. Only the shared `restoreWithBek` tail is mock-driven.

### Regression crawl — `regression/crawl/c8_restore_new_machine/` (the real round-trip)

This silo **is** a genuine same-language Python round-trip over a **live vault
subprocess**:

- `test_restore_recovers_same_ceremony_did.py`: machine A `tn.init(link=True)` →
  `flush_and_close` → machine B dev-auth + `fetch_pending_claim` + decrypt +
  lay out → `tn.init(yaml_b)` → assert B's DID == A's DID, user home untouched.
- `test_restore_can_sign_new_entries.py`: same, plus B **signs** a new entry and
  `tn.read(verify=True)` must accept it — proves the private key round-tripped.

**But two caveats keep this from being the contract's coverage:**

1. It exercises the **`init --link` / pending-claim** producer and a
   **reimplemented** restore (`restore_keystore_to` in
   `regression/_shared/vault_test_helpers.py`, which calls `tn.export.decrypt_body_blob`
   directly). It does **not** drive the `tn wallet restore` CLI verb, nor
   `restoreViaPassphrase` / `restoreViaLoopback`. A `grep` of `regression/` for
   `wallet restore` / `restoreViaPassphrase` / `restoreViaLoopback` returns
   nothing.
2. The CI c8 job runs `make -C regression c8 || echo "...placeholder pass"` and
   does **not** check out `tn_proto_web`, so the `vault_server` fixture
   `pytest.skip`s and the job soft-passes. The round-trip only really runs where
   a developer has the vault repo + Mongo locally.

---

## 7. Gap to a real round-trip test

What is missing to cover the `wallet restore` contract for real:

1. **A live-vault harness wired to the actual verb.** Reuse
   `regression/_shared/vault_subprocess.py::vault_server` +
   `c8/conftest.py::hermetic_machine_with_live_vault` + `machine_b_tmpdir`, but
   invoke `cmd_wallet_restore` / `restoreViaPassphrase` / `restoreViaLoopback`
   instead of the inline `restore_keystore_to` helper. CI must also **check out
   `tn_proto_web`** and drop the `|| echo placeholder pass` so the job can't
   green-wash a skip.
2. **A real pushed account-bound backup**, not just a pending-claim. Drive
   `init upload` (or `wallet sync` push) so `/encrypted-blob`, `/wrapped-key`, and
   `/account/credentials` are populated — that is the producer half the loopback
   and passphrase paths actually read.
3. **Passphrase path coverage**: register a PBKDF2 credential on the dev account,
   then run `_restore_via_passphrase` / `restoreViaPassphrase` headlessly with the
   passphrase + a dev-auth JWT, and assert the byte-match + sign-new-entry PASS
   conditions. This whole chain is currently at zero coverage in both languages.
4. **Loopback path coverage**: a scripted browser/PRF stand-in that POSTs a
   real `TransferToken` (real `vault_jwt`, real `raw_bek_b64`) so
   `restoreViaLoopback` / `_cmd_wallet_restore_account_bound` run end-to-end
   against the live blob, not a mock fetch.
5. **Mnemonic path coverage**: `tn wallet restore --mnemonic ...` against a vault
   with linked ceremonies, asserting identity + per-ceremony pull.

---

## Report summary

**Verdict:** `wallet restore` has **no same-language round-trip test that drives
the CLI verb**. Python (`test_wallet_restore.py`) and TS
(`wallet_restore.test.ts` + `restore_loopback.test.ts`) are entirely
mock-fetch + loopback-stub: they cover the transport receiver and the shared
`_decrypt_blob_with_bek` / `restoreWithBek` tail with fabricated blobs, never a
vault. The genuine live-vault round-trip lives only in the `c8` regression silo,
and even that (a) drives `init --link` + a reimplemented decrypt helper rather
than the `wallet restore` verb, and (b) soft-passes in CI because the vault repo
isn't checked out (`make c8 || echo placeholder`).

**Setup a real round-trip needs:** live `tn_proto_web` dev vault + Mongo;
a dev account with a **PBKDF2** credential; a project with a **real pushed
backup** (`init upload` / `wallet sync` push, not just a pending-claim) so
`/encrypted-blob` + `/wrapped-key` + `/account/credentials` return rows; the
matching recovery secret (passphrase / passkey / mnemonic); an empty target dir;
producer closed before restore. Then restore → `tn.init` → assert byte-match,
DID match, and sign-a-new-entry-and-`read(verify=True)`.

**Untested restore variants:** the **passphrase** path (PBKDF2→AWK→BEK chain) has
**zero** coverage in both languages; the **loopback/browser** path's public verb
(`_cmd_wallet_restore_account_bound` / `restoreViaLoopback`) is never run
end-to-end (only the mock-fetch tail); the **mnemonic** path
(`cmd_wallet_restore` legacy branch) is untested. The c8 silo's `init --link`
claim-URL flow is the only restore shape with real round-trip coverage, and it
bypasses the verb.
