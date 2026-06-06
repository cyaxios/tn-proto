# PARITY ledger: `account connect` (connection / DID-bind code path)

Audit-grade line-by-line behavioral parity for `tn account connect <code>` —
Python vs TypeScript. Every side-effect row cites exact `file:line` on **both**
sides; `MISSING` is a real finding, not an omission. Runtime-confirmed against
the live dev vault (`http://localhost:38790`, `TN_DEV_AUTH_BYPASS=1`) on
2026-06-06; raw diffs in §4.

Repo: `C:\codex\tn\tn_proto`. Tag context: 0.4.3a1-era artifacts
(`tn-e2e/.venv_rel` wheel; `ts-sdk/dist`).

---

## 0. Verdict

| Bucket   | Count |
|----------|-------|
| MATCH    | 9     |
| DIVERGE  | 6     |
| MISSING  | 2     |

**Must-fix (P0): RESOLVED 2026-06-06.** The key-source asymmetry (rows 1–2) is
fixed with a shared **signing-identity cascade**: both CLIs now route
`account connect` through one resolver that picks the same key in the same
order — `supplied (--identity, tier 2) > machine-global identity.json (tier 1,
default) > per-ceremony keystore (tier 3, headless fallback)`. Resolver:
`python/tn/sync_state.py:299` (`resolve_signing_identity`) and
`ts-sdk/src/account/signing_identity.ts:67` (`resolveSigningIdentity`); wired at
`python/tn/cli.py:912` and `ts-sdk/bin/tn-js.mjs:1374`. Proven live: on a machine
with a global identity, the Python wheel and the TS node CLI sharing one
`TN_IDENTITY_DIR` both bound the **same** DID
(`z6MkvUT6nSknzZuLnLZKcKsTM46pBxKh51nu1sEyWH2n8ti1`) — a single entry in
`accounts.minted_dids[]`, not two. Headless (empty `TN_IDENTITY_DIR`) both fall
back to their ceremony keystore DID. See §3 and §6. Everything else below is
contained blast-radius (stdout shape, exit code, `linked_vault` stamp).

---

## 1. Call-chain maps (in execution order)

### Python

| Step | Function | file:line |
|------|----------|-----------|
| CLI entry | `cmd_account_connect(args)` | `python/tn/cli.py:880` |
| load global identity | `_load_identity_or_die(_default_identity_path())` | `python/tn/cli.py:905-906` → `cli.py:2510`, `identity.py:109` |
| resolve yaml (optional, discovers) | `_resolve_yaml_or_discover(args.yaml)` | `python/tn/cli.py:908` → `cli.py:1372` |
| derive signing key (**identity device key**) | `Ed25519PrivateKey.from_private_bytes(identity.device_private_key_bytes())` | `python/tn/cli.py:910` → `identity.py:284` |
| resolve vault URL | `base_url = args.vault or identity.linked_vault` | `python/tn/cli.py:911` |
| redeem (network) | `redeem_connect_code(args.code, identity.did, sk, base_url)` | `python/tn/cli.py:914` → `vault_client.py:80` |
| └ build message | `hashlib.sha256(code.encode("utf-8")).digest()` | `vault_client.py:125` |
| └ sign + std-b64 | `sk.sign(message)` / `base64.b64encode` | `vault_client.py:126-127` |
| └ URL + POST | `resolve_vault_url(base_url)` + `client.post(url, json=payload)` | `vault_client.py:133`, `139` |
| └ error map | `raise VaultError(...)` | `vault_client.py:143-149` |
| validate account_id | `resp.get("account_id")` guard | `python/tn/cli.py:921-926` |
| persist sync-state | `mark_account_bound(yaml_path, account_id)` | `python/tn/cli.py:931` → `sync_state.py:230` |
| stamp global identity | `identity.linked_account_id = ...; identity.ensure_written()` | `python/tn/cli.py:936-938` → `identity.py:345` |
| stdout receipt | 4× `print(...)` | `python/tn/cli.py:940-947` |
| exit | `return 0` | `python/tn/cli.py:948` |

### TypeScript

| Step | Function | file:line |
|------|----------|-----------|
| CLI entry | `accountCmd()` | `ts-sdk/bin/tn-js.mjs:1344` |
| arg parse | manual loop | `bin/tn-js.mjs:1348-1353` |
| **require** `--yaml` | `if (!opts.yaml) die(...)` | `bin/tn-js.mjs:1358` |
| open ceremony, read cfg | `tnInit(opts.yaml)` → `tn.config()` | `bin/tn-js.mjs:1360-1362` |
| require keystorePath | `if (!keystorePath) die(...)` | `bin/tn-js.mjs:1363-1364` |
| load keystore (**ceremony device key**) | `loadKeystore(keystorePath)` → `ks.device` | `bin/tn-js.mjs:1365` → `src/runtime/keystore.ts:32-40` |
| resolve vault URL | `--vault` → `cfg.ceremony.linked_vault` → die | `bin/tn-js.mjs:1368-1376` |
| redeem (network) | `AccountNamespace.connect(code, vaultUrl, ks.device, {yamlPath})` | `bin/tn-js.mjs:1379` → `src/account/index.ts:142` |
| └ build message | `createHash("sha256").update(code,"utf8").digest()` | `src/account/index.ts:67`, called `:152` |
| └ sign + std-b64 | `deviceKey.sign(message)` / `Buffer.from().toString("base64")` | `src/account/index.ts:153-154`, `:62` |
| └ URL + POST | `${baseUrl}/api/v1/account/connect-codes/redeem` + `fetchImpl(...)` | `src/account/index.ts:156-161` |
| └ error map | `throw new AccountConnectError(...)` | `src/account/index.ts:163-174` |
| └ validate account_id | `typeof accountId !== "string"` guard | `src/account/index.ts:177-183` |
| └ persist sync-state (inline) | `if (opts.yamlPath) markAccountBound(...)` | `src/account/index.ts:185-187` → `:105` |
| stamp global identity | `Identity.loadOrMint(); identity.linkedAccountId/linkedVault = ...; save()` | `bin/tn-js.mjs:1389-1394` → `src/identity.ts:154`, `:176` |
| stdout receipt (JSON) | `stdout.write(JSON.stringify({...}))` | `bin/tn-js.mjs:1400-1410` |
| error path | `die(...)` (no explicit success return; `process.exitCode` defaults 0) | `bin/tn-js.mjs:1411-1416` |

---

## 2. Side-effect ledger

| # | Python effect (file:line) | TS (file:line or MISSING) | Verdict | Severity | Detail |
|---|---------------------------|---------------------------|---------|----------|--------|
| 1 | **Signing key source = CASCADE** `resolve_signing_identity` `sync_state.py:299`, wired `cli.py:912` | **CASCADE** `resolveSigningIdentity` `signing_identity.ts:67`, wired `tn-js.mjs:1374` | **MATCH** ✅ | ~~P0~~ RESOLVED | Both resolve the SAME key via the same cascade `supplied>machine>ceremony`. Live: with a shared global identity both bound `z6MkvUT6…` (one `minted_dids[]` entry); headless both fall back to the ceremony keystore DID. Tier 2 = `--identity <path>` (added on both). See §3, §6. |
| 2 | **`did` sent in POST body = resolved cascade DID** `signer.did` `cli.py:931` | **= resolved cascade DID** `signer.deviceKey.did` via `account/index.ts:150` `tn-js.mjs:1394` | **MATCH** ✅ | ~~P0~~ RESOLVED | Direct consequence of #1: the field the server `$addToSet`s now agrees across CLIs on one machine. |
| 3 | signing message = `sha256(code.utf8())` `vault_client.py:125` | `sha256(code.utf8())` `account/index.ts:67,152` | MATCH | — | Single round-trip; no server nonce. Identical on both sides (subtlety confirmed: connect signs the code hash, not a challenge nonce). |
| 4 | signature b64 = **standard** `base64.b64encode` `vault_client.py:127` | **standard** `Buffer.toString("base64")` `account/index.ts:62,154` | MATCH | — | Server uses `base64.b64decode` (standard alphabet). Both correct. |
| 5 | POST route `/api/v1/account/connect-codes/redeem` `vault_client.py:133` | same `account/index.ts:156` | MATCH | — | Identical path. Unauthenticated (no bearer). |
| 6 | POST body `{code, did, signature_b64}` `vault_client.py:128-132` | `{code, did, signature_b64}` `account/index.ts:160` | MATCH | — | Same three keys, same names. |
| 7 | request headers: **`User-Agent: tn-protocol/<ver>` only** `vault_client.py:65,136` | `User-Agent: tnproto-sdk-ts/0.4.3` + `Accept` + `Content-Type` `account/index.ts:21-25,159` | DIVERGE | P3 | Different UA strings (TS hard-codes a stale `0.4.3`); TS adds explicit `Accept`/`Content-Type`. Cosmetic / observability only; both bodies are JSON. |
| 8 | vault-URL fallback chain: `args.vault → identity.linked_vault → TN_VAULT_URL → DEFAULT_VAULT_URL` `cli.py:911`, `vault_client.py:68-76,37` | `--vault → cfg.ceremony.linked_vault → die` `tn-js.mjs:1368-1376` | DIVERGE | P2 | Python honors the env var **and** a hosted default and the global identity's `linked_vault`; TS reads only the ceremony's `linked_vault` and errors otherwise. Different "no `--vault`" behavior. |
| 9 | `--yaml` **optional** — discovers via `_resolve_yaml_or_discover` `cli.py:908,1372` | `--yaml` **required** — `die` if absent `tn-js.mjs:1358` | DIVERGE | P2 | Python runs from a project dir with no `--yaml`; TS hard-fails. |
| 10 | sync-state write: `account_id` set `sync_state.py:237` | `state.account_id = accountId` `account/index.ts:107` | MATCH | — | Same field, same value. Confirmed live (§4). |
| 11 | sync-state write: `account_bound = True` `sync_state.py:238` | `state.account_bound = true` `account/index.ts:108` | MATCH | — | Confirmed live. |
| 12 | sync-state: `pending_claim` popped `sync_state.py:239` | `delete state.pending_claim` `account/index.ts:109` | MATCH | — | Behaviorally identical (no-op when absent, as in the test). |
| 13 | sync-state file serialization: **`json.dumps(indent=2, sort_keys=True)`** `sync_state.py:120` | `JSON.stringify(state, null, 2)` (**insertion order, no sort**) `account/index.ts:100` | DIVERGE | P3 | Same keys/values, different byte order (`account_bound` before `account_id` in Py; reversed in TS). No trailing newline in either. Byte-diff only. |
| 14 | sync-state write is **atomic-via-rename** (`tmp` + `os.replace`) `sync_state.py:119-121` | **direct `writeFileSync`** (non-atomic) `account/index.ts:100` | DIVERGE | P3 | Python is crash-safe; TS can leave a truncated state.json on a mid-write crash. |
| 15 | sync-state save **swallows OSError** (best-effort) `sync_state.py:122-123` | no try/catch around save `account/index.ts:97-101` | DIVERGE | P3 | A write failure aborts the TS connect (and the global stamp never runs); Python logs+continues. Edge-case behavior differs. |
| 16 | global identity stamp: `linked_account_id` set when changed `cli.py:936-938` | `linkedAccountId` set when changed `tn-js.mjs:1390-1391` | MATCH | — | Both gate on inequality; both persist via the identity-write path. Confirmed live (both stamped `01KTF6X84…`). |
| 17 | global identity stamp: **`linked_vault` NOT touched** (stays whatever it was) `cli.py:936-938` | **`linked_vault` ALSO stamped** to `vaultUrl` `tn-js.mjs:1390,1392` | **DIVERGE** | P1 | Live: Python left `linked_vault: null`; TS wrote `linked_vault: "http://localhost:38790"`. Real state divergence — TS's warm-attach (`init` reads `linked_vault`) gets primed by connect; Python's does not. |
| 18 | global stamp failure handling: **un-guarded** — `ensure_written` exception propagates and fails the verb `cli.py:938` | **try/catch, best-effort** — prints WARN, continues, reports `global_identity_stamped:false` `tn-js.mjs:1388-1398` | DIVERGE | P2 | TS treats the global stamp as non-fatal (sync-state already persisted inside `connect`); Python lets it abort. Different failure semantics. |
| 19 | global-identity write content: includes `prefs`, `prefs_version`, `mnemonic_stored`, `seed_b64` `identity.py:354-366` | omits `prefs`/`prefs_version`/`mnemonic_stored` unless pre-present in `_raw` `identity.ts:181-191` | DIVERGE | P3 | Live identity.json after connect: Python has `prefs`/`prefs_version`; TS has neither. `version` default also differs (`IDENTITY_SCHEMA_VERSION` vs literal `1`). Pre-existing identity-file shape gap surfaced by connect, not unique to it. |
| 20 | stdout receipt: **human-readable**, 4 lines (`Connected to vault account …` + `project_id`/`project_name`/`did`) `cli.py:940-947` | **single-line JSON** `{ok,verb,account_id,did,project_id,project_name,global_identity_stamped}` `tn-js.mjs:1400-1410` | **DIVERGE** | P1 | Totally different stdout contract. TS emits machine-parseable JSON incl. `ok`/`verb`/`global_identity_stamped`; Python emits prose and conditionally omits `project_id`/`project_name` when falsy. No common parse surface. |
| 21 | success exit code `return 0` `cli.py:948` | implicit `process.exitCode` 0 (no explicit set) `tn-js.mjs` (after 1410) | MATCH | — | Both 0 on success. Confirmed live. |
| 22 | **error exit code = 1** (`_die(..., code=1)`) `cli.py:916-919`, `cli.py:95` | **error exit code = 2** (`die` → `exit(2)`) `tn-js.mjs:1413`, `:78-81` | **DIVERGE** | P2 | Live (unknown-code 404): Python exit **1**, TS exit **2**. Scripts branching on exit code break across CLIs. |
| 23 | error stderr text: `tn: error: connect-code redeem failed (status=404): <server body>` `cli.py:916-918` | `tn-js: account connect: POST …/redeem returned 404 (status=404)` `tn-js.mjs:1413`, error from `account/index.ts:170-173` | DIVERGE | P3 | Python surfaces the server JSON body; TS surfaces only the status. Different prefix (`tn: error:` vs `tn-js:`). |
| 24 | error body capture cap = `resp.text[:512]` `vault_client.py:144` | `(await resp.text()).slice(0,512)` `account/index.ts:166` | MATCH | — | Same 512-char cap on the captured body (though TS doesn't print it — see #23). |
| 25 | network timeout = 30s (`DEFAULT_TIMEOUT`) `vault_client.py:31,136` | **no timeout** on `fetch` `account/index.ts:157` | MISSING | P3 | Python bounds the POST at 30s; TS `fetch` has no timeout/abort. TS can hang indefinitely on a stalled vault. |
| 26 | reads `account_bound`/`account_id` back anywhere in-verb? No. | `getAccountId`/`isAccountBound` exist `account/index.ts:113-124` but **unused by connect** | MISSING | P4 | Neither verb reads state back; the TS helpers are dead in this path (parity-neutral, noted for completeness). |

---

## 3. The key-source question — answered

The documented subtlety ("Python signs with the machine-global identity device
key; TS signs with the ceremony keystore key") is **real and material**, proven
three ways:

1. **Static** (rows 1–2): Python `cli.py:910` derives the key from
   `identity.device_private_key_bytes()` and sends `identity.did`
   (`cli.py:914`). TS `tn-js.mjs:1365` loads `ks.device` from the ceremony
   keystore (`keystore.ts:36-40`) and `connect` sends `deviceKey.did`
   (`account/index.ts:150`).

2. **On-disk** (the two DIDs differ): for the Python ceremony,
   `identity.json.did = z6MkvGam…` while `keys/local.public = z6Mku26c…` —
   **different keys**. So Python binds a DID the ceremony keystore does not
   even hold. (For the TS ceremony the two happened to coincide because TS
   `init` seeds the global identity from the same seed — itself an init-path
   asymmetry, out of scope here.)

3. **Server truth** (`GET /api/v1/account/dids`): after both redeems against the
   same account, `minted_dids[]` contains **both** the Python identity DID and
   the TS keystore DID, each `source:"connect"`. The bind target genuinely
   forks by language.

**Does it matter?** Yes. The bound DID is the principal for subsequent
DID-challenge auth on `/account/*`. A device connected via Python authenticates
as its *global identity*; the same device connected via TS authenticates as its
*per-ceremony* key. Two ceremonies on one machine connected via TS bind two
distinct DIDs; via Python they would (re)bind the one identity DID. This is a
protocol-identity decision that must be deliberately chosen, not left to
language. → **P0 must-fix.**

> **RESOLVED 2026-06-06 — signing-identity cascade.** The decision is now made
> in one place per language and applied identically. `resolve_signing_identity`
> (`python/tn/sync_state.py:299`) and `resolveSigningIdentity`
> (`ts-sdk/src/account/signing_identity.ts:67`) implement a first-available-wins
> cascade:
> 1. **tier 2 — supplied:** an explicit `--identity <path>` override (added to
>    both CLIs; `cli.py` `--identity`, `tn-js.mjs` `--identity`). Wins outright.
> 2. **tier 1 — machine:** the machine-global `identity.json` under
>    `TN_IDENTITY_DIR`/default. The DEFAULT when present — Python's historical
>    behaviour, now also TS's.
> 3. **tier 3 — ceremony:** the per-ceremony keystore (`<keystore>/local.private`).
>    The headless/CI fallback — TS's historical behaviour, now also Python's.
>
> Python gains the ceremony fallback; TS gains the machine preference. The
> chosen key's DID is what `redeem_connect_code` / `AccountNamespace.connect`
> send as `did`, so the bound principal no longer forks by binary. Proven live
> in §6 (same machine ⇒ same DID; headless ⇒ keystore DID), regression-tested in
> `python/tests/test_account_connect_cascade.py` and
> `ts-sdk/test/account_connect_cascade.test.ts`.

---

## 4. Runtime confirmation (live dev vault)

Setup: two isolated workspaces under `C:\tmp\parity-connect\{py,ts}`, each with
its own `TN_IDENTITY_DIR`. One dev account minted via
`POST /api/v1/dev/login`; two connect codes minted from it via
`POST /api/v1/account/connect-codes` (bearer = dev JWT). Account
`01KTF6X84BT7WS1NP9V7G36XQ7`.

### 4.1 Python redeem (code `tn_connect_lWtop7Dl…`)

stdout (exit 0):
```
Connected to vault account 01KTF6X84BT7WS1NP9V7G36XQ7
  project_id:   proj_01KTF6XJXX8WT2JBANJ9EE1AV2
  project_name: parity-py
  did:          did:key:z6MkvGamvV6kGEs5fRv8CgtwVdY1BV9rDbVk6k26GNTVRzFG   ← IDENTITY DID
```

`.tn/pyproj/.tn/sync/state.json`:
```json
{
  "account_bound": true,
  "account_id": "01KTF6X84BT7WS1NP9V7G36XQ7"
}
```

`identity.json` delta: `linked_account_id` → set; **`linked_vault` stays `null`**.

### 4.2 TS redeem (code `tn_connect_AsKeEZNU…`)

stdout (exit 0):
```json
{"ok":true,"verb":"account.connect","account_id":"01KTF6X84BT7WS1NP9V7G36XQ7","did":"did:key:z6Mkh2oaC4QesuKL81S7hs5SGL41vbsMwBTDuGeirguM5E8n","project_id":"proj_01KTF6Y2TSZ8ED2QD0S8VNCV90","project_name":"parity-ts","global_identity_stamped":true}
```
(`did` = **KEYSTORE DID**.)

`.tn/tsproj/.tn/sync/state.json` (note key order):
```json
{
  "account_id": "01KTF6X84BT7WS1NP9V7G36XQ7",
  "account_bound": true
}
```

`identity.json` delta: `linked_account_id` → set; **`linked_vault` → `"http://localhost:38790"`**.

### 4.3 Server account state (both DIDs landed)

`GET /api/v1/account/dids`:
```json
{"minted_dids":[
  {"did":"did:key:z6MkvGam…","nickname":"parity-py","source":"connect","revoked_at":null},
  {"did":"did:key:z6Mkh2oa…","nickname":"parity-ts","source":"connect","revoked_at":null}
],"package_dids":[]}
```

### 4.4 Error path (unknown code), both CLIs

```
PY:  tn: error: connect-code redeem failed (status=404): {"detail":"connect code not found"}   → exit 1
TS:  tn-js: account connect: POST /api/v1/account/connect-codes/redeem returned 404 (status=404) → exit 2
```

Confirms rows 1/2/17/20/22/23 directly.

---

## 5. Prioritized MUST-FIX

| Pri | Rows | Fix |
|-----|------|-----|
| ~~P0~~ ✅ | 1, 2 | **DONE 2026-06-06.** Single canonical bind key via the `resolve_signing_identity` / `resolveSigningIdentity` cascade (`supplied > machine > ceremony`), wired through both `account connect` paths. Same operator on one machine now binds one DID. See §3, §6. |
| **P1** | 17 | Align `linked_vault` stamping. Pick one: either both stamp it on connect (helps warm-attach) or neither does. TS currently primes warm-attach; Python doesn't. |
| **P1** | 20 | Align the stdout contract. Recommend both emit the same machine-parseable JSON (or both human). Today there is no shared parse surface for `account connect` output. |
| **P2** | 22 | Unify error exit codes (1 vs 2). Pick one convention repo-wide for these verbs. |
| **P2** | 8, 9 | Align fallback/required-arg behavior: `--yaml` optional+discover vs required; vault-URL fallback chain (env + hosted default + identity.linked_vault) vs ceremony-only. |
| **P2** | 18 | Decide whether a global-stamp failure should be fatal (Python) or best-effort (TS) and converge. |
| **P3** | 7,13,14,15,19,23,25 | Lower-stakes hygiene: UA string (and stale `0.4.3`), sync-state key sort + atomic write + error-swallow, identity-file field completeness, error-body surfacing, and the missing `fetch` timeout in TS. |

---

## 6. Runtime confirmation of the cascade fix (live dev vault)

Setup: shared `TN_IDENTITY_DIR`, one dev account
(`01KTF8PYTDW60XCJRR05YPZK3X`) via `POST /api/v1/dev/login`, two connect codes
via `POST /api/v1/account/connect-codes`. Python redeem via the editable-source
wheel (`tn-e2e/.venv_rel/Scripts/tn.exe`), TS redeem via
`ts-sdk/bin/tn-js.mjs` (rebuilt `npm run build`).

### 6.1 Machine-identity present ⇒ both bind the SAME DID

The adversarial case: the **Python** ceremony's own keystore DID
(`z6Mkga…`) differed from the machine identity DID (`z6MkvUT6…`), while the
**TS** ceremony's keystore DID happened to equal the machine DID (the init-seed
asymmetry from §3.2). The cascade still made both bind the machine DID:

```
PY:  tn account connect <CODE_PY> --yaml <pyproj> →
       did: did:key:z6MkvUT6nSknzZuLnLZKcKsTM46pBxKh51nu1sEyWH2n8ti1   ← MACHINE (not its z6Mkga… keystore)
TS:  tn-js account connect <CODE_TS> --yaml <tsproj> →
       {"did":"did:key:z6MkvUT6nSknzZuLnLZKcKsTM46pBxKh51nu1sEyWH2n8ti1", ...}   ← MACHINE
```

`GET /api/v1/account/dids` after both redeems — **one** entry, not two:

```json
{"minted_dids":[
  {"did":"did:key:z6MkvUT6nSknzZuLnLZKcKsTM46pBxKh51nu1sEyWH2n8ti1",
   "nickname":"cascade-ts","source":"connect","revoked_at":null}
],"package_dids":[]}
```

(Both redeems bound the same DID; the server `$addToSet` deduped to a single
row. Pre-fix this readout carried two distinct DIDs — see §4.3.)

### 6.2 No machine identity (empty `TN_IDENTITY_DIR`) ⇒ tier-3 keystore fallback

```
PY:  did: did:key:z6MkpRB87see4jdC78bpa5vSR7R1iAhYX9ArUcsgh1GQ7v4b   = py ceremony keystore DID
TS:  {"did":"did:key:z6MkoJUoK3Cxoqr8QFXp6S8uvute9u53sg1EtZBtk9vdedTn", ...} = ts ceremony keystore DID
```

Python gained the headless fallback it lacked; TS kept its keystore behaviour.

### 6.3 Regression tests

- Python: `python/tests/test_account_connect_cascade.py` (6 cases) — each tier,
  cross-CLI same-DID, exhaustion error, sign-under-bound-DID. Passes with
  `test_vault_client_connect.py` + `test_cli_sync_pull.py` (12 total).
- TS: `ts-sdk/test/account_connect_cascade.test.ts` (6 cases, in the
  `package.json` run set + `run_set_guard` allowlist check). Passes with
  `account_connect.test.ts` + `cli_wallet_account.test.ts`.

---

*Generated 2026-06-06 from static read of the 0.4.3a1 wheel/dist sources plus a
live round-trip against the dev vault. §0–§5 are the original audit; the
RESOLVED annotations and §6 record the 2026-06-06 cascade fix
(`resolve_signing_identity` / `resolveSigningIdentity`). All `file:line`
citations verified against the working tree at fix time.*
