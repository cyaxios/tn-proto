# `wallet sync` — same-language round-trip test contract

Test contract for the `tn wallet sync` verb's PUSH ↔ PULL/RESTORE round-trip,
within a single language implementation (Python↔Python or TS↔TS). The bar is
the one `ts-sdk/scripts/plumb_awk_bek.mts` already proves against a live dev
vault: **pushed body bytes == restored body bytes** (`MATCH=true`).

This is an **integration** contract, not a unit one. A real same-language
round-trip cannot be satisfied by a mocked `fetch`/`VaultClient` — it requires a
**live dev vault** that actually stores the wrapped key, stores the encrypted
blob, and re-serves both. The current automated tests are hermetic mocks (see
§6); they prove handler/wiring logic but NOT a real body round-trip (§7).

Sources of truth:
- Python: `python/tn/cli.py` — `cmd_wallet_sync` (~568), `_pull_absorb_step`
  (~733), `_stage_account_inbox` (~643), `_cmd_wallet_sync_pull` (~785); push
  body via `python/tn/wallet.py::sync_ceremony` (~196).
- TS: `ts-sdk/src/cli/wallet_sync.ts` — `walletSyncCmd` (~495), `pushCeremonyBody`
  (~407), `pullAbsorbStep` (~278), `stageAccountInbox` (~215).
- Round-trip template: `ts-sdk/scripts/plumb_awk_bek.mts` (standalone script).

---

## 1. Flow

`tn wallet sync` is two-way. Bare invocation runs **PULL+ABSORB then PUSH**;
flags carve out the legs:

| Invocation | Pull/absorb | Push |
|---|---|---|
| `tn wallet sync` | yes | yes |
| `tn wallet sync --pull` | stage only (no absorb), exit | no |
| `tn wallet sync --push-only` | no | yes |
| `tn wallet sync --drain-queue` | no | yes (retry/drain) |

### PUSH (encrypt body frame → PUT)

The supported model is **AWK/BEK whole-body** (D-20 / D-22), NOT the deprecated
per-file wallet-passphrase sealing.

1. Collect the ceremony body — every keystore file (minus `*.lock`) keyed
   `body/keys/<name>` plus `body/tn.yaml`
   (`wallet_sync.ts::collectBodyMembers`; Python `wallet._ceremony_files`).
2. Resolve the project BEK:
   - GET wrapped-key for the project. If present → **derive** the existing BEK
     from the account passphrase (`deriveBekFromMaterial`).
   - 404 → **mint**: generate a fresh 32-byte BEK, derive the AWK from
     passphrase + credential (`deriveAwkFromMaterial`), wrap the BEK under the
     AWK (`wrapBekUnderAwk`), and PUT wrapped-key FIRST (the encrypted-blob PUT
     checks project ownership against `project_wrapped_keys` — order matters,
     per `project_minter.js` step 5).
3. Encrypt the body STORED-zip under the BEK as a **no-AAD `nonce||ct` frame**
   (`encryptBodyBlob`). `ciphertext_b64` carries the whole frame.
4. PUT the frame to `encrypted-blob-account` with **If-Match**: the current blob
   `generation` (or `"*"` for the first write).

### PULL / RESTORE (download inbox → absorb; or restore body)

- `--pull`: GET `/api/v1/account/inbox` (the account-scoped aggregator —
  every snapshot addressed to any DID this account owns), download each
  unconsumed snapshot to `<inbox_dir>/<from_did>/<ceremony_id>/<ts>.tnpkg`,
  STAGE only (operator runs `tn absorb <path>` separately). Idempotent.
- bare sync pull leg: same staging, then **absorb** each snapshot through a
  fresh per-file runtime. The absorb engine keeps revoked leaves revoked; an
  **INFORMED leaf-reuse (equivocation)** — a publisher re-adding a leaf it knew
  was revoked — is surfaced as an `ALERT`.
- The body restore (the inverse of PUSH) is the verb `tn wallet restore
  --passphrase` → `restore.ts::restoreViaPassphrase` /
  `decryptBlobWithBek` (Python `_restore_via_passphrase`): GET wrapped-key,
  derive BEK from passphrase, GET `encrypted-blob`, read `ciphertext_b64` as the
  whole frame, decrypt, unzip to disk. A body pushed by PUSH round-trips through
  this restore — that equivalence is the contract.

A real same-language round-trip = **PUSH the body to a vault, then restore it
back (`restoreViaPassphrase`) and confirm the restored bytes match the pushed
bytes**, exactly as `plumb_awk_bek.mts` does.

---

## 2. What it would take to actually work

A real round-trip needs a **LIVE dev vault** — the body must actually be
stored and re-served, with real wrapped-key custody and real If-Match
generation tracking. Mock `fetch` cannot exercise this (a mock that re-serves
exactly what it was handed is circular: it proves nothing about storage).

Concrete live-vault dependencies (the `plumb_awk_bek.mts` set):

- **Dev vault up** on `http://127.0.0.1:34987` with **`TN_DEV_AUTH_BYPASS=1`**.
- **`POST /api/v1/dev/login`** — mints an account JWT plus the AWK passphrase
  credential for a handle (e.g. `{ handle: "frank" }` → `{ account_id, token,
  passphrase }`). This is the dev shortcut around the DID challenge-response.
- **A project** — created implicitly by PUTting the wrapped-key under a fresh
  project id (the mint path registers the project under the account).
- The account routes the round-trip touches:
  - `GET /api/v1/account/credentials` — the PBKDF2 credential (AWK material).
  - `GET`/`PUT` wrapped-key (`.../wrapped-key`) — BEK custody.
  - `GET`/`PUT` `encrypted-blob` / `encrypted-blob-account` — the body frame
    with If-Match generation enforcement.
  - `GET /api/v1/account/inbox` + snapshot download — for the PULL leg.

Mapping to the verb: the dev-login token is injected as the `VaultClient` bearer
(`VaultClient.unauthed({ token })` in the plumb script). The verb's normal path
authenticates AS the device DID (challenge/verify); the dev-login bypass swaps
that for a minted JWT so a headless test can drive the account routes without a
browser claim ceremony.

The repo already ships a sibling live-vault harness pattern:
`ts-sdk/test/e2e_docker.test.ts` drives `tn-js` as a subprocess against a docker
vault stack on `localhost:38790` and **skips gracefully when the stack isn't
reachable** (CI-safe). A real `wallet sync` round-trip test should follow that
opt-in/skip-when-down shape (or gate on `TN_DEV_AUTH_BYPASS`/`PLUMB_VAULT`).

---

## 3. Setup / preconditions

1. Start the dev vault (`tn_proto_web` / vault service) with
   `TN_DEV_AUTH_BYPASS=1`, listening on `127.0.0.1:34987` (override via
   `PLUMB_VAULT`).
2. `POST /api/v1/dev/login` with a handle → capture `{ account_id, token,
   passphrase }`.
3. Construct a `VaultClient` bearing that token (unauthed + token, no DID
   challenge).
4. Build a ceremony with a real body:
   - TS test path: a body Map (keystore members + `tn.yaml`), or a `Tn.init`
     ceremony whose keystore + yaml `collectBodyMembers` packs.
   - For the bare verb: a `tn.yaml` marked `mode: linked` with a real
     `linked_vault` (the dev vault URL) and a `linked_project_id`, and (for the
     pull leg) `account_bound: true` in `.tn/<stem>/sync/state.json`.
5. PUSH the body: mint/derive BEK, encrypt the frame, PUT wrapped-key (mint
   path) then PUT `encrypted-blob-account` with `If-Match: *`.

---

## 4. PASS conditions

- **Body match (the bar):** restored body bytes == pushed body bytes, file for
  file — the `plumb_awk_bek.mts` `MATCH=true` assertion
  (`Buffer.from(restored).equals(Buffer.from(payload))`). For a multi-member
  body, every `body/keys/<name>` and `body/tn.yaml` round-trips byte-identical.
- **Mint path:** wrapped-key PUT happens before the blob PUT; first blob write
  carries `If-Match: *`.
- **Derive path:** no wrapped-key PUT (row already exists); blob PUT carries
  `If-Match: <generation>` from the existing blob.
- **Pull leg:** account-inbox snapshots are downloaded and absorbed; staged
  files land under `<inbox_dir>/<from_did>/<ceremony_id>/<ts>.tnpkg`; re-running
  is idempotent (already-staged skipped, consumed items not re-downloaded).
- **Informed equivocation surfaced:** an absorbed snapshot re-adding a
  known-revoked leaf produces the `ALERT: ... INFORMED leaf-reuse` line and is
  counted.
- **Exit 0** on each success path; expected banner printed (`Synced ... ->
  <vault>` / `Drained sync queue ...` / `Pulled N snapshot(s)`).

---

## 5. FAIL conditions the test MUST catch

- **Wrong passphrase:** restore with a passphrase other than the one that
  wrapped the BEK must **fail the BEK unwrap** (AEAD auth failure), not silently
  return garbage or the wrong plaintext.
- **If-Match conflict:** a second concurrent push against a stale generation
  must be **rejected by the vault** (412 / precondition-failed), surfacing as
  `push failed for <ceremony>` (exit 1) — not a silent last-writer-wins
  clobber.
- **Tampered blob:** flipping any byte of the stored `ciphertext_b64` frame must
  fail the GCM tag check on restore, not decrypt.
- **Not-linked path:** an unlinked + unbound ceremony dies cleanly
  (`not linked and not account-bound`, exit 1); `--push-only` on an unlinked
  ceremony dies (`is not linked; nothing to push`, exit 1); `--pull` on an
  unbound ceremony dies exit 2 (`no account binding for this ceremony`).
- **Missing passphrase on a linked push:** dies `--passphrase required` (exit 1).
- **Missing `linked_project_id`:** dies `... has no linked_project_id; relink to
  repair` (exit 1).

---

## 6. Current test audit

### TypeScript — `ts-sdk/test/cli_wallet_sync.test.ts`

**Verdict: MOCK, not a real round-trip.** Hermetic by design and so labelled
in its own header (lines 6–13: "the vault is a mock `fetch` ... No live vault,
no subprocess — so c8 sees every line").

- The vault is `mockVault(...)` (lines 140–197), a `fetch` shim that pattern-
  matches URL suffixes and returns canned responses: auth challenge/verify
  (159–162), account inbox + snapshot (165–172), wrapped-key GET/PUT (174–180),
  credentials (181–183), encrypted-blob GET (184–190), and the
  **`encrypted-blob-account` PUT returns `{ generation: 1 }` and discards the
  body** (191–193). Nothing is stored or re-served.
- Crypto is real on the PUSH side: `buildVaultMaterial` (103–129) builds the
  PBKDF2 credential and wrapped BEK with the actual `awk_bek` primitives under
  the two pinned AADs, so the mint/derive **unwrap** runs real crypto and a
  wrong AAD/KDF would fail (header lines 14–17). The ceremony, keystore, and
  absorb are real (`Tn.init`, `NodeRuntime`).
- But the round-trip is **never closed**: the test asserts the PUT *body shape*
  (`ciphertext_b64` is a string, frame length > 12+16, lines 320–323) — it does
  NOT push to a store and restore back. There is no `restoreViaPassphrase` call,
  no `MATCH` assertion. The "frame round-trips" comment (line 320) is asserting
  frame *structure*, not an actual store→restore equality.
- 14/14 tests pass (verified by running the suite). The mock proves the verb's
  branching, ordering (wrapped-key before blob), If-Match selection, exit codes,
  banners, and pull/absorb wiring — **handler logic, not body custody**.

### Python — `python/tests/test_cli_sync_pull.py`

**Verdict: MOCK, and PULL-LEG ONLY.** Header lines 3–4: drives
`_cmd_wallet_sync_pull` against an `httpx.MockTransport`-backed `VaultClient`.

- It only exercises the `--pull` stage leg (`_cmd_wallet_sync_pull`, imported
  line 31; called lines 188, 228, 258, 265). It asserts the account-inbox
  aggregator is consulted, snapshots land in `inbox_dir`, consumed items are
  skipped, idempotency, and the unbound-dies-exit-2 case.
- It does **not** drive `cmd_wallet_sync` bare/`--push-only`/`--drain-queue`,
  does **not** push a body, and does **not** restore — no round-trip.
- The Python PUSH itself (`wallet.py::sync_ceremony`, ~196) still uses the
  **DEPRECATED per-file `client.upload_file` path** (line 221), not the AWK/BEK
  whole-body frame the TS verb pushes. So even a Python push test would not
  exercise the same body model as TS, and there is **no Python equivalent of
  the AWK/BEK body round-trip** under test today.

### `plumb_awk_bek.mts`

A **standalone script**, NOT wired into the suite. The `ts-sdk/package.json`
`test` script enumerates every test file explicitly and `plumb_awk_bek.mts` is
absent (and `run_set_guard.test.ts` enforces that allowlist). It is the only
artifact in the repo that closes a **real** AWK/BEK body round-trip against a
live dev vault (dev-login → mint wrapped-key → push no-AAD frame →
`restoreViaPassphrase` → `MATCH`), but it must be run by hand
(`node --import tsx scripts/plumb_awk_bek.mts` with the dev vault up) and
nothing in CI invokes it.

| Language | File | Kind | Covers push? | Covers restore? | Real round-trip? |
|---|---|---|---|---|---|
| TS | `cli_wallet_sync.test.ts` | mock `fetch` | yes (shape only) | no | **no** |
| TS | `plumb_awk_bek.mts` | live dev vault | yes | yes | **yes** (but standalone, not in suite) |
| Py | `test_cli_sync_pull.py` | httpx mock | no (pull leg only) | no | **no** |

---

## 7. Gap to a real round-trip test

What's missing is an **opt-in live-vault integration test** that closes the loop
inside the suite, per language:

1. **Harness** — follow `e2e_docker.test.ts`: detect the dev vault
   (`TN_DEV_AUTH_BYPASS` vault on `:34987`, or `PLUMB_VAULT`/docker stack),
   `test.skip` when unreachable so CI without a vault stays green, run for real
   locally. Gate behind an env flag (e.g. `RUN_E2E=1`) like the vault Playwright
   harness.
2. **TS** — promote `plumb_awk_bek.mts` into a real `test/` file (or have the
   verb-level test drive `walletSyncCmd` PUSH against the live vault, then
   `restoreViaPassphrase` and assert `MATCH`). Add the FAIL cases from §5
   against the live vault: wrong-passphrase unwrap failure, If-Match conflict on
   concurrent push (real 412), tampered-blob GCM failure.
3. **Python** — there is a deeper gap: the Python push must first move off the
   deprecated `upload_file` per-file path onto the AWK/BEK whole-body frame
   (parity with TS `pushCeremonyBody` / `project_minter.js`) before a faithful
   Python same-language round-trip can exist. Until then, Python has no
   equivalent of the `plumb_awk_bek.mts` body round-trip.
4. **Assertion bar** — the live test's success condition is the
   `plumb_awk_bek.mts` one: `restored bytes == pushed bytes` (`MATCH=true`),
   plus the pull-leg absorb count and the informed-equivocation alert when a
   known-revoked leaf is re-added.
