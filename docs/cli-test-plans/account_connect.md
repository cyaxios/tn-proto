# Test contract: `account connect` same-language round-trip

Scope: the `account connect <code>` verb in both language implementations,
exercised against a **live dev vault**. This is the headless companion to
the dashboard's "Connect a new app or device" action: a connect **code** is
minted by the account owner in the browser (or by any auth'd API caller),
copied out-of-band, and redeemed by the CLI to bind a device DID to the
account.

"Same-language round-trip" means: mint a code AND redeem it within one
language's surface end-to-end (TS mints via `fetch` + redeems via
`AccountNamespace.connect`; Python mints via `httpx`/dashboard + redeems via
`redeem_connect_code`), with the binding side-effects asserted.

Implementation under test:

- Python CLI verb: `python/tn/cli.py::cmd_account_connect` (around line 845)
  → SDK: `python/tn/vault_client.py::redeem_connect_code` (line 80).
- TS CLI verb: `ts-sdk/bin/tn-js.mjs::accountCmd` (line 1322)
  → namespace: `ts-sdk/src/account/index.ts::AccountNamespace.connect` (line 142).
- Server (shared by both): `tn_proto_web/src/routes_account_connect.py`
  — `mint_code` (POST `/api/v1/account/connect-codes`, auth'd) and
  `redeem_code` (POST `/api/v1/account/connect-codes/redeem`, **unauth'd**).

---

## 1. Flow

### Where connect codes are minted

There is exactly one mint route, used by every minter:

`POST /api/v1/account/connect-codes` → `routes_account_connect.py::mint_code`
(line 236). It is **authenticated** (`Depends(_require_account_id)`), takes
`{project_name, name?}`, and returns `{code_id, code, project_name, name,
expires_at}`. The `code` (`tn_connect_<urlsafe-b64>`) is shown **once**; the
vault persists only `sha256(code)` (`account_connect_codes` collection,
`code_hash`). Default TTL 24h.

Minters:

- **Dashboard UI**: `tn_proto_web/static/account/identities.js` — the
  "Connect a new app or device" card (line ~191), button
  `#btn-connect-mint` (line ~235) → `authedFetch("/api/v1/account/connect-codes", {POST})`
  (line ~665). Pending codes listed via GET, revoked via DELETE `/{code_id}`.
- **Tests / harness**: both TS test files mint via dev-auth bypass —
  `POST /api/v1/dev/login` (mounted only when `TN_DEV_AUTH_BYPASS=1`,
  `routes_dev_auth.py`) to get a bearer token, then `POST .../connect-codes`.

Neither SDK has a "mint" helper — minting is always an authenticated API/UI
action, and the CLI verb is **redeem-only**. (The TS happy-path live test and
the CLI live test reproduce minting inline with `fetch` against dev/login +
the mint route.)

### Redeem (`account connect <code>`), per language

Both languages do the identical wire dance (proven byte-for-byte by the
`connect signature matches Python` test):

1. Load the device Ed25519 key.
   - Python: from `identity.json` (`_default_identity_path()` →
     `Ed25519PrivateKey.from_private_bytes(identity.device_private_key_bytes())`).
   - TS: from the **ceremony keystore** (`cfg.keystorePath` → `loadKeystore` →
     `ks.device`). Note the asymmetry: Python signs with the machine-global
     identity key; TS signs with the ceremony's device key.
2. `message = sha256(code.utf8())`.
3. `signature = Ed25519.sign(device_sk, message)`;
   `signature_b64 = STANDARD base64` (not url-safe — the server uses
   `base64.b64decode`).
4. `POST /api/v1/account/connect-codes/redeem` with
   `{code, did, signature_b64}` (unauthenticated).
5. Server (`redeem_code`, line 292): hash the code, atomically consume the
   row (`find_one_and_update` on `code_hash` + unconsumed + unexpired),
   verify the Ed25519 signature against the DID's pubkey over `sha256(code)`,
   cross-account-collision check, then `$addToSet` the DID into
   `accounts.minted_dids[]` with `source:"connect"` and merge into
   `account_projects`. Returns `{did, name, account_id, project_id,
   project_name, recipient_dids, bound_at}`.
6. On success, persist the binding (see §4).

> **DID challenge-response clarification.** The connect verb does **not** use
> a server-issued nonce challenge. The proof-of-key is the client signing
> `sha256(code)` — the code is the challenge, the signature is the response,
> in a single round-trip. The nonce/challenge flow (`POST /auth/challenge`)
> belongs to the *browser* DID flow in `routes_account_dids.py` and to
> ordinary `/account/*` JWT auth — the connect endpoint is deliberately
> unauthenticated because the redeemer has no JWT yet. The live tests only
> use `/auth/challenge` as a **reachability probe**, not as part of connect.

---

## 2. What it would take to actually work

A real same-language round-trip needs, in order:

1. **A live dev vault** reachable at `TN_TEST_VAULT_URL`
   (default `http://localhost:38790`) backed by a real Mongo — because the
   redeem path is pure DB state machine (consume row, addToSet DID, upsert
   project). Nothing about it is mockable end-to-end without the server.
2. **A mintable account** + **the mint route**: `TN_DEV_AUTH_BYPASS=1` so
   `/api/v1/dev/login` mints a bearer token and an account, then
   `POST /api/v1/account/connect-codes` returns a live single-use code.
3. **Redeem it**: run the verb with that code. The Ed25519 signature over
   `sha256(code)` must verify server-side, and the DID must not already
   belong to a different account.
4. **The binding must persist**:
   - the ceremony's **sync-state** records `account_id` + `account_bound`
     (so `sync --pull` / `absorb` can find the account), and
   - the **machine-global identity** is stamped with the linked account id
     (so a later `init` of a different project warm-attaches).

The TS surface already has all of this wired and passing (when the stack is
up). The Python surface has the SDK-level wire test but **no live round-trip
and no CLI-level test** — see §6.

---

## 3. Setup / preconditions (concrete)

1. **Bring up the dev vault stack** (the harness the live tests target):
   `tn-e2e/infra/docker-compose.yml` — `mongo:7` (internal) + `tne2e-vault`
   published on host **38790** (`38790:8790`) with `TN_DEV_AUTH_BYPASS: "1"`.
   ```
   docker compose -f tn-e2e/infra/docker-compose.yml up -d mongo vault
   ```
   Verify: `POST http://localhost:38790/api/v1/auth/challenge` returns 200/400
   (this is the exact reachability gate both TS test files use).
2. **Export** `TN_TEST_VAULT_URL=http://localhost:38790` (or rely on the
   default).
3. **Mint a connect code** for an account:
   `POST /api/v1/dev/login {handle}` → `{token, account_id}`; then
   `POST /api/v1/account/connect-codes` (Bearer token) `{project_name}` →
   `{code}`. (TS: inline in the test's `mintConnectCode`. Python: equivalent
   `httpx` calls would need to be written — they do not exist yet.)
4. **A ceremony + a device identity to bind**:
   - TS: `Tn.init(yamlPath)` seeds a ceremony with a keystore + device DID.
   - Python: an `identity.json` (machine-global device key) + a discoverable
     `tn.yaml` ceremony for the sync-state write.

---

## 4. PASS conditions

A green round-trip asserts ALL of:

- **Verb succeeds, exit 0.**
  - Python: prints `Connected to vault account <id>` (+ project_id /
    project_name / did), returns 0.
  - TS CLI: prints a JSON receipt `{ok:true, verb:"account.connect",
    account_id, did, project_id, project_name, global_identity_stamped}`,
    exit 0.
- **Response carries `account_id`** (string, non-empty) and it **equals the
  minter's account** (`result.accountId === minterAccountId`). `did` echoes
  the redeemer's DID; `project_id` present when project-scoped.
- **Ceremony sync-state records the binding** —
  `.tn/sync/state.json` has `account_id == <id>` and `account_bound == true`,
  and any in-flight `pending_claim` is cleared (Python `mark_account_bound`;
  TS `markAccountBound`, `getAccountId`, `isAccountBound`).
- **Global identity stamped** with the linked account —
  Python: `identity.linked_account_id == account_id` written to
  `identity.json`. TS: `Identity.linkedAccountId`/`linkedVault` saved
  (best-effort; receipt's `global_identity_stamped:true`).
- **Server state** (optional deep assert): DID is in
  `accounts.minted_dids[]` with `source:"connect"`; a project doc exists in
  `account_projects` with this DID as a publisher; the code row is
  `consumed_at != null` (burned).

---

## 5. FAIL conditions (the test MUST catch each)

| Case | Server | Expected client behavior |
| --- | --- | --- |
| **Unknown / invalid code** | 404 "connect code not found" | Python: `VaultError(status=404)` → `_die` exit 1. TS: `AccountConnectError{status:404}` → CLI exit ≠0, stderr matches `404`. |
| **Already-redeemed (replayed) code** | 409 "connect code already used" | Non-2xx surfaced; second redeem of the same code throws (TS test asserts status ≥ 400). |
| **Expired code** | 410 "connect code expired" | Surfaced as VaultError / AccountConnectError with status 410. |
| **Wrong DID / bad signature** | 401 "signature verification failed" (server *undoes* the consume so the code survives for retry); 400 on malformed base64 | Surfaced as error, exit ≠0. |
| **DID already bound to another account** | 409 "DID ... already bound to another account" (code is **burned**, not undone) | Surfaced as error, exit ≠0. |
| **No `--vault` and no linked vault** | n/a (never hits network) | Python: `base_url = args.vault or identity.linked_vault`; if both empty the redeem can't resolve a URL. TS CLI: `die("account connect: --vault <url> required (ceremony has no linked_vault to fall back to)")`, exit ≠0. |
| **Missing `<code>` positional** | n/a | Both: usage error, exit ≠0. |
| **TS: ceremony has no keystorePath** | n/a | `die("account connect: ceremony ... has no keystorePath")`. |

---

## 6. Current test audit

### TypeScript — REAL round-trip (live-vault, dev-auth mint)

`ts-sdk/test/account_connect.test.ts`:
- Mints a **real** code via dev-auth bypass: `mintConnectCode` calls
  `POST /dev/login` then `POST /account/connect-codes` (lines 42–60).
- `connect signature matches Python` (line 124) — deterministic Ed25519 sig
  over `sha256(code)`, the cross-language wire-parity anchor (unit, always
  runs).
- `AccountNamespace.connect — happy path against live vault` (line 139) —
  real mint + real redeem; asserts `accountId === minterAccountId`, `did`,
  and sync-state (`getAccountId`, `isAccountBound`). **Gated on
  `reachable`.**
- `replayed code` (line 161) → asserts second redeem throws status ≥ 400.
- `invalid code` (line 183) → asserts `AccountConnectError.status === 404`.
- Unit: `markAccountBound`/`getAccountId`/`isAccountBound` + `pending_claim`
  clearing (lines 62, 83) — always run.

`ts-sdk/test/cli_wallet_account.test.ts`:
- `tn-js account connect — exits 0 ... persists account_id to sync state`
  (line 156) — spawns the **CLI subprocess** with a real minted code,
  asserts exit 0, JSON receipt `account_id === minterAccountId`, and
  `.tn/sync/state.json` `{account_id, account_bound:true}` (lines 159–176).
- `invalid code surfaces 404 via non-zero exit` (line 182).
- `missing positional errors` (line 197) — always runs.

**Verdict (TS): PASS — genuine same-language round-trip exists** at both the
namespace and CLI levels, using a real minted code against a live vault. The
only gap is operational: the live tests **skip** when the stack is down
(confirmed below). The CLI test does NOT assert the global-identity stamp
(`global_identity_stamped` field / `Identity` write) — a minor coverage gap.

### Python — MOCKED only; no live round-trip, no CLI test

`python/tests/test_vault_client_connect.py` — the only connect-focused Python
test. It exercises **`redeem_connect_code` against `httpx.MockTransport`**,
not a live vault:
- `test_redeem_connect_code_builds_canonical_request` (line 62) — asserts the
  POST URL/body and that `signature_b64` verifies over `sha256(code)`; the
  server response is a **hand-written mock dict** (lines 73–84).
- `test_redeem_connect_code_raises_on_non_2xx` (line 114) — mock 404 →
  `VaultError(status=404)`.
- `test_redeem_connect_code_uses_resolve_vault_url` (line 136) — `TN_VAULT_URL`
  resolution, mocked 200.

`cmd_account_connect` (the CLI verb that loads identity, persists sync-state
via `mark_account_bound`, AND stamps `identity.linked_account_id`) has **no
test at all.** `test_cli_sync_pull.py` only *simulates* the binding by calling
`mark_account_bound(yaml_path, "acct_test_01HVAULT")` directly (line 59) and
asserts sync-pull's behavior with/without a binding — it never runs
`account connect`.

**Verdict (Python): PARTIAL / GAP.** The wire contract of the SDK redeem call
is well covered (mocked), and matches TS byte-for-byte. But there is:
1. no live-vault redeem (the mocked response can drift from the real
   `RedeemResponse` server shape silently — only TS catches server drift), and
2. **zero coverage of the CLI verb's persistence side-effects** — the
   sync-state write and the `identity.linked_account_id` global stamp
   (`cli.py` lines 896–903) are entirely untested.

### Live-run evidence

Ran `account_connect.test.ts` once (tsx runner): 3 unit/crypto tests
**pass**, all 3 live-vault tests **skip** with `# vault not reachable` —
i.e. no dev vault was up on :38790, so the round-trip itself is currently
unexercised locally. Bringing up `tn-e2e/infra/docker-compose.yml` is the
precondition that flips those three from skip to real.

---

## 7. Gap to a real round-trip test

Two things are missing for a fully-exercised, language-symmetric contract:

1. **A standing live-vault harness in CI/local.** The TS live tests are
   already written but skip unless `:38790` is up. The harness exists
   (`tn-e2e/infra/docker-compose.yml`, vault + mongo + `TN_DEV_AUTH_BYPASS=1`);
   what's missing is a CI job (or a documented local step) that starts it
   before the `account_connect` / `cli_wallet_account` suites so the live
   assertions actually run rather than skip. Until then, the "round-trip"
   coverage is latent.

2. **A Python live round-trip + CLI test** mirroring the TS ones. Needs:
   - a Python `mintConnectCode` equivalent (`httpx` to `/dev/login` then
     `/account/connect-codes`) — does not exist yet;
   - a test that drives `cmd_account_connect` (or the `tn account connect`
     subprocess) end-to-end against the live vault and asserts BOTH
     persistence side-effects: ceremony `.tn/sync/state.json`
     (`mark_account_bound`) **and** the `identity.json`
     `linked_account_id` stamp. Neither is touched by any current Python test.

The cross-language **wire parity** is already nailed down by the deterministic
signature test, so the remaining work is purely about (a) running the live TS
path and (b) bringing the Python CLI path up to the same live + persistence
bar.
