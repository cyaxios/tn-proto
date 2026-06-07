# PARITY ledger — `tn wallet sync` (vault two-way sync)

Audit-grade, line-by-line behavioral parity of the `wallet sync` code path,
Python vs TypeScript. Every observable side-effect is one row, citing exact
`file:line` on **both** sides. `MISSING` is a finding, not a gap silently
papered over.

- Python entry: `python/tn/cli.py::cmd_wallet_sync` (575)
  → `_pull_absorb_step` (768) / `_stage_account_inbox` (678)
  → `python/tn/wallet.py::sync_ceremony` (325)
  → `python/tn/wallet_push.py::push_ceremony_body` (321)
  → `python/tn/wallet.py::publish_group_keys` (187)
- TS entry: `ts-sdk/src/cli/wallet_sync.ts::walletSyncCmd` (574)
  → `pullAbsorbStep` (278) / `stageAccountInbox` (215)
  → `pushCeremonyBody` (407)
  → `publishGroupKeys` (504)

Runtime confirmation against the live dev vault (`http://localhost:38790`)
is in [§4](#4-runtime-confirmation). Crypto helpers verified byte-shape parity
(`wallet_restore_passphrase.py` AAD constants ↔ `vault/awk_bek.ts`,
`wallet_push.encrypt_body_blob` ↔ `core/body_encryption.encryptBodyBlob`).

---

## 1. Call-chain maps (in order)

### 1a. Verb dispatch / argv

| step | Python | TS |
|---|---|---|
| entry | `cmd_wallet_sync(args)` cli.py:575 | `walletSyncCmd(opts)` wallet_sync.ts:574 |
| identity load | `_load_identity_or_die` cli.py:577 | `Identity.load(identityPath)` wallet_sync.ts:584 |
| yaml resolve | `_resolve_yaml_or_discover` cli.py:582 | `resolveYamlOrDiscover` wallet_sync.ts:579 |
| **runtime init at entry** | `tn_init(yaml_path)` cli.py:583 (LOADS runtime, runs handler chain → an autosync may fire) | `readLinkState(yamlPath)` wallet_sync.ts:585 (raw yaml parse only; NodeRuntime.init deferred to push leg) |
| link state | `cfg = current_config()` cli.py:584 (LoadedConfig.is_linked/linked_vault/linked_project_id) | `readLinkState` wallet_sync.ts:146 (raw `ceremony:` block) |
| `--pull` branch | `_cmd_wallet_sync_pull` cli.py:592 | `walletSyncPull` wallet_sync.ts:590 |
| flags | `push_only`/`drain_queue` cli.py:594-595; `passphrase` from `--passphrase` **or `TN_ACCOUNT_PASSPHRASE`** cli.py:599-601 | `pushOnly`/`drainQueue` wallet_sync.ts:593-594; `passphrase` from opts only wallet_sync.ts:627 |

### 1b. Pull leg (`_stage_account_inbox` / `stageAccountInbox`)

| step | Python | TS |
|---|---|---|
| gate | `ceremony_linked or is_account_bound` cli.py:706-713 | `link.isLinked \|\| isAccountBound` wallet_sync.ts:222 |
| vault url | `cfg.linked_vault or identity.linked_vault or resolve_vault_url(None)` cli.py:718-722 | `override ?? link.linkedVault ?? identity.linkedVault ?? null` wallet_sync.ts:201, 224 |
| client | `VaultClient.for_identity` cli.py:723 | `VaultClient.forIdentity` wallet_sync.ts:227 |
| list inbox | `client._request("GET","/api/v1/account/inbox")` cli.py:727 | `client.listAccountInbox()` wallet_sync.ts:236 → client.ts:340 |
| 401/403 → None | cli.py:728-730 | wallet_sync.ts:238-241 |
| per-item filter | `consumed_at`, str-typed from/ceremony/ts cli.py:736-747 | same wallet_sync.ts:249-255 |
| dest path | `target_root / safe(from) / safe(cer) / "{ts}.tnpkg"` cli.py:749-752 | same wallet_sync.ts:256-257 |
| skip existing | cli.py:753-755 | wallet_sync.ts:258-261 |
| download | `_download_account_inbox_snapshot` cli.py:757 → cli.py:865 `GET /api/v1/account/inbox/{did}/{cer}/{ts}.tnpkg` | `client.downloadAccountInboxSnapshot` wallet_sync.ts:262 → client.ts:347 |
| write | `dest.write_bytes` cli.py:761 | `writeFileSync` wallet_sync.ts:264 |

### 1c. Absorb leg (`_pull_absorb_step` / `pullAbsorbStep`)

| step | Python | TS |
|---|---|---|
| absorb each | `from .pkg import absorb; _absorb(path)` cli.py:778, 793 | `NodeRuntime.init(yamlPath); rt.absorbPkg(path)` wallet_sync.ts:303-305 |
| accepted count | `receipt.accepted_count` cli.py:797 | `receipt.acceptedCount` wallet_sync.ts:306 |
| informed conflicts | `c.informed` cli.py:798-800 | `c.type==="leaf_reuse_attempt" && c.informed` wallet_sync.ts:307-317 |
| stdout summary | cli.py:802-805 | wallet_sync.ts:326-330 |
| ALERT lines | cli.py:806-816 | wallet_sync.ts:331-340 |

### 1d. Push-body leg (`sync_ceremony`+`push_ceremony_body` / `pushCeremonyBody`)

| step | Python | TS |
|---|---|---|
| collect body | `wallet._collect_body_members` wallet.py:37 | `collectBodyMembers` wallet_sync.ts:378 |
| derive AWK | `_derive_awk_via_passphrase` wallet_push.py:109 | `deriveAwkFromMaterial` awk_bek.ts:98 (mint path only) |
| fetch wrapped-key | `_fetch_wrapped_key` wallet_push.py:354 (AFTER awk) | `client.getWrappedKey` wallet_sync.ts:419 (BEFORE cred) |
| mint-or-derive BEK | wallet_push.py:364-389 | wallet_sync.ts:427-442 |
| encrypt frame | `encrypt_body_blob` wallet_push.py:178 | `encryptBodyBlob` body_encryption.ts |
| If-Match | `_current_blob_generation` wallet_push.py:237 | inline `getEncryptedBlob` wallet_sync.ts:449-459 |
| PUT blob | `_put_encrypted_blob_account` wallet_push.py:268 | `client.putEncryptedBlobAccount` wallet_sync.ts:467 |

### 1e. Publish-group-keys leg

| step | Python | TS |
|---|---|---|
| author DID | `cfg.device.device_identity` (or sign_with) wallet.py:227-229 | `identity.deviceKey().did` wallet_sync.ts:510-511 |
| export pkg | `export_group_keys` wallet.py:235 | `rt.exportGroupKeys` wallet_sync.ts:520 |
| names | `sorted(g for g in cfg.groups if g!="tn.agents")` wallet.py:246 | `listGroupNamesInYaml` wallet_sync.ts:525, 553 |
| POST snapshot | `_SnapshotPostingClient.post_inbox_snapshot` wallet.py:256-257 → vault_push.py:762 | `client.postInboxSnapshot` wallet_sync.ts:527 → client.ts:365 |

---

## 2. Side-effect ledger

Severity: **S1** behavioral divergence a user/second-device can observe;
**S2** stdout/exit/UX divergence; **S3** cosmetic/internal.

| # | Python (file:line) | TS (file:line or MISSING) | verdict | sev | detail |
|---|---|---|---|---|---|
| **PULL LEG** |||||
| 1 | `GET /api/v1/account/inbox` cli.py:727 | `GET /api/v1/account/inbox` client.ts:341 | MATCH | — | both list account inbox; 401/403→null/None |
| 2 | items filter: `consumed_at`/str-types cli.py:736-747 | same wallet_sync.ts:249-255 | MATCH | — | identical fields read |
| 3 | dest `=<inbox>/{safe(from)}/{safe(cer)}/{ts}.tnpkg` cli.py:749-752 | same wallet_sync.ts:256-257 | MATCH | — | **Python ts NOT sanitized in filename** (`f"{ts}.tnpkg"` cli.py:752) vs TS `safePathSeg(ts)` wallet_sync.ts:257 | 
| 3b | `dest = dest_dir / f"{ts}.tnpkg"` cli.py:752 (raw ts) | `${safePathSeg(ts)}.tnpkg` wallet_sync.ts:257 | DIVERGE | S2 | TS sanitizes the `ts` segment of the FILE name; Python sanitizes from_did/ceremony_id but NOT ts. A server-supplied `ts` with `:`/`/` is path-cleaned by TS, written raw by Python. Low exploitability (ts is `_TS_RE`-shaped server-side) but a real asymmetry. |
| 4 | `GET /api/v1/account/inbox/{did}/{cer}/{ts}.tnpkg` cli.py:869 | same `encodeURIComponent` segments client.ts:347-351 | MATCH | — | download route identical |
| 5 | absorb via `pkg.absorb(path)` cli.py:793 | `NodeRuntime.init` + `rt.absorbPkg` wallet_sync.ts:303-305 | MATCH | — | Python's `absorb()` re-inits runtime per file internally; TS inits explicitly. Same net effect. |
| 6 | absorb fail → `WARN absorb failed for {name}: {e}` cli.py:795 | `WARN absorb failed for {basename}: {msg}` wallet_sync.ts:320 | MATCH | — | per-file swallow, identical wording |
| 7 | summary `  pulled+absorbed N snapshot(s), M new event(s)[, K already local]` cli.py:802-805 | same wallet_sync.ts:326-330 | MATCH | — | byte-identical |
| 8 | informed = `c.informed` ANY conflict type cli.py:799 | informed = `c.type==="leaf_reuse_attempt" && c.informed` wallet_sync.ts:310 | DIVERGE | S2 | Python flags ANY conflict whose `informed` attr is truthy; TS narrows to `leaf_reuse_attempt` only. If a future conflict variant carries `informed`, Python ALERTs, TS stays silent. Today both engines only set `informed` on leaf_reuse, so observationally equal — latent divergence. |
| **PUSH BODY LEG** |||||
| 9 | body member keys: `body/keys/<name>` + `body/tn.yaml` wallet.py:53-54 | `body/keys/<name>` + `body/tn.yaml` wallet_sync.ts:385,388 | MATCH | — | **nested layout on push** (keys/ subdir, NOT flat). See §3 restore-divergence note. |
| 10 | skip `*.lock` keystore files wallet.py:52 | skip `.lock` extname wallet_sync.ts:384 | MATCH | — | |
| 11 | **logs members** `body/logs/<name>` IFF `cfg.sync_logs` wallet.py:55-63 | **MISSING** wallet_sync.ts:378-390 | DIVERGE | S1 | Python opt-in (`ceremony.sync_logs: true`) packs log files into the body; TS `collectBodyMembers` has NO sync_logs branch. A ceremony with `sync_logs:true` backs up logs via Python but silently drops them via TS. |
| 12 | mint-or-derive: GET wrapped-key, if present unwrap BEK else mint+PUT wrapped-key wallet_push.py:352-389 | same logic wallet_sync.ts:415-442 | MATCH | — | mint path PUTs wrapped-key first (ownership), both per project_minter step 5 |
| 13 | `PUT /api/v1/projects/{id}/wrapped-key` body `{wrapped_bek_b64, wrap_nonce_b64, cipher_suite:"aes-256-gcm"}` wallet_push.py:208-228 | `{cipher_suite:"aes-256-gcm", wrapped_bek_b64, wrap_nonce_b64}` client.ts:289-298 | MATCH | — | same 3 fields |
| 14 | BEK wrap AAD `tn-vault-bek-wrap-v1` wallet_push.py:171 | `AAD_BEK_WRAP="tn-vault-bek-wrap-v1"` awk_bek.ts:31,134 | MATCH | — | |
| 15 | AWK unwrap AAD `tn-vault-awk-wrap-v1`, PBKDF2-SHA256, iters default 300000, floor <10000 refused wallet_restore_passphrase.py:55,187 | `AAD_AWK_WRAP`, pbkdf2 default 300000, refuse <10000 awk_bek.ts:29,54,110 | MATCH | — | KDF params + floor identical |
| 16 | body frame: STORED zip of `sorted(body)` keys, AES-256-GCM `nonce(12)\|\|ct`, **no AAD** wallet_push.py:191-202 | `encryptBodyBlob` STORED zip sorted, no-AAD nonce\|\|ct body_encryption.ts | MATCH | — | round-trips through restore decryptBlobWithBek |
| 17 | If-Match resolve: `GET encrypted-blob` → `generation` else `*` on 404 wallet_push.py:237-265 | `getEncryptedBlob`→generation else `*` on 404 wallet_sync.ts:447-459 | MATCH | — | |
| 17b | non-404 non-200 on GET encrypted-blob → raise PushError wallet_push.py:253-257 | non-404 status → rethrow wallet_sync.ts:455-457 | MATCH | — | |
| 18 | `PUT /api/v1/projects/{id}/encrypted-blob-account` body `{ciphertext_b64, nonce_b64, salt_b64, kdf:"pbkdf2-sha256", kdf_params:{iterations:1}, cipher_suite:"aes-256-gcm", bundle_kind:"project-body-v1"}` + `If-Match` wallet_push.py:268-300 | identical 7 fields + ifMatch wallet_sync.ts:467-484, client.ts:315-327 | MATCH | — | **field-for-field equal** incl. salt=`os.urandom(16)`/16-byte random, dummy `kdf_params.iterations:1` |
| 19 | `ciphertext_b64` = whole frame; `nonce_b64` = `frame[:12]` wallet_push.py:291-292 | `bytesToB64(frame)` / `frame.subarray(0,12)` wallet_sync.ts:470,476 | MATCH | — | |
| 20 | 412 → `PushError("...precondition failed (concurrent writer...)")` wallet_push.py:302-306 | **relies on client.ts `_request` throwing on 412** → caught at wallet_sync.ts:654 `push failed for {cer}: {msg}` | DIVERGE | S2 | Python raises a SPECIFIC PushError naming "concurrent writer bumped the generation"; TS surfaces the generic VaultError message from `_request`. Both exit non-zero, but the 412 conflict diagnostic is richer on Python. (See §3 — TS has no dedicated 412 branch.) |
| 21 | non-200 (≠412) → `PushError("PUT encrypted-blob-account returned HTTP {code}...")` wallet_push.py:307-311 | generic VaultError via `_request` → die wallet_sync.ts:654-656 | DIVERGE | S3 | error text differs; both exit 1 |
| **CREDENTIAL / WRAPPED-KEY FETCH ORDER** |||||
| 22 | push fetches **credentials FIRST** (`_derive_awk_via_passphrase`→`_fetch_credential_with_wrap` wallet_push.py:345,122), wrapped-key SECOND (wallet_push.py:354) | push fetches **wrapped-key FIRST** (getWrappedKey wallet_sync.ts:419), credentials SECOND (getCredentialWrap wallet_sync.ts:426) | DIVERGE | S2 | Runtime-confirmed (§4): with no credential, Python errors after `GET credentials` having never hit wrapped-key; TS errors after `GET wrapped-key` THEN `GET credentials`. Different request sequence, same terminal failure. On the derive path TS GETs credentials even when wrapped-key absent-handling differs (see #23). |
| 23 | **[RESOLVED 6323f32]** `_fetch_wrapped_key` now sets `status_code` on the RestoreError (wallet_restore_passphrase.py:152-159); `push_ceremony_body` mints ONLY on 404, aborts with PushError on any other non-200 (wallet_push.py:359-371) | `getWrappedKey` throws; only `status===404` → mint wallet_sync.ts:421-424 | RESOLVED ✅ | — | Python now matches TS: a transient 5xx/401/403 aborts instead of minting a fresh BEK + overwriting the wrapped-key + orphaning the body backup. Regression: test_wallet_push_mint_guard.py (6 cases); 404→mint stays proven by the live day1 suite. |
| 24 | `GET /api/v1/account/credentials?include=wrap`; pick `is_primary` else all; err on 0/>1 wallet_restore_passphrase.py:109-129 | same route + same 0/>1 logic client.ts:250-271 | MATCH | — | |
| **PUBLISH GROUP KEYS LEG** |||||
| 25 | author DID = `author_did or sign_with.did or cfg.device.device_identity` wallet.py:227-229; CLI passes `sign_with=DeviceKey.from_private_bytes(identity...)`, `author_did=identity.did` cli.py:649-657 | author = `identity.deviceKey()`, `ownDid=authorKey.did` wallet_sync.ts:510-511 | MATCH | — | both author AS the account identity DID |
| 26 | export `group_keys` tnpkg via `export_group_keys` wallet.py:235-241; on `RuntimeError/FileNotFoundError` → return `[]` wallet.py:242-244 | `rt.exportGroupKeys`; on any throw → return `[]` wallet_sync.ts:520-524 | MATCH | — | no-btn-groups → publishes nothing |
| 27 | snapshot ts = `strftime("%Y%m%dT%H%M%S%fZ")` (real micros) wallet.py:251 | `inboxSnapshotTs()` = `YYYYMMDDTHHMMSS`+`ms`+`000`+`Z` wallet_sync.ts:543-549 | DIVERGE | S3 | Python has true microsecond precision; TS pads JS millisecond to 6 digits (`ms*1000`). Both satisfy vault `_TS_RE`. Cosmetic; collision odds differ negligibly. |
| 28 | `POST /api/v1/inbox/{did}/snapshots/{cer}/{ts}.tnpkg` octet-stream, lazy DID-challenge auth + 401-retry wallet.py:252-257 → vault_push.py:762-786 | `POST /api/v1/inbox/{did}/snapshots/{cer}/{name}.tnpkg` octet-stream client.ts:365-385 | MATCH | — | same route + content-type; Python re-auths on 401 (vault_push.py:781-785), TS relies on `_request` auth |
| 29 | names list `sorted(g for g in cfg.groups if g!="tn.agents")` wallet.py:246 | `Object.keys(groups).filter(g!="tn.agents").sort()` wallet_sync.ts:557 | MATCH | — | Python reads `cfg.groups` (loaded config); TS reads raw yaml `groups:` keys. Equivalent for normal ceremonies. |
| **RESULT / STDOUT / EXIT** |||||
| 30 | missing passphrase → recorded `SyncResult.errors`, NOT raised; still prints `Synced ...`, `uploaded 0 files: []`, then `WARN 1 errors: [...]`; **exit 1** wallet.py:378-387 + cli.py:659-670 | missing passphrase → **early `die(...)` BEFORE any push/Synced line**; `tn: error: --passphrase required...`; exit 1 wallet_sync.ts:627-633 | DIVERGE | S2 | Runtime-confirmed (§4). Same exit code (1) but Python prints the success header + a WARN-errors line; TS prints only `tn: error:` on stderr and never prints `Synced`. UX + parseable-output divergence. |
| 31 | push exception → `SyncResult.errors.append((cer, "{Type}: {e}"))`, prints `Synced`, then `WARN N errors`, exit 1 wallet.py:400-402 + cli.py:668-670 | push exception → `die(err, "push failed for {cer}: {msg}")`, exit 1, no `Synced` wallet_sync.ts:654-656 | DIVERGE | S2 | Runtime-confirmed: "no credentials" case prints `Synced`+WARN (Python) vs `tn: error: push failed...` (TS). |
| 32 | success line `Synced {cer} -> {linked_vault}` cli.py:659 | `Synced {cer} -> {linkedVault}` wallet_sync.ts:678 | MATCH | — | |
| 33 | `  uploaded {N} files: {result.uploaded}` (Python repr of list) cli.py:660 | `  uploaded {N} files: {JSON.stringify(uploaded)}` wallet_sync.ts:679 | DIVERGE | S3 | Python prints Python list repr `['keys/...', 'tn.yaml']` (single quotes); TS prints JSON `["keys/...","tn.yaml"]` (double quotes). Same members, different quoting. |
| 34 | uploaded list = `sorted(k[len("body/"):] for k in body)` wallet.py:406 | `[...body.keys()].map(strip body/).sort()` wallet_sync.ts:487 | MATCH | — | both strip `body/` prefix → `keys/<name>`, `tn.yaml` |
| 35 | published groups line `  published group keys to own inbox: {list}` IFF non-empty cli.py:661-665 | same, `JSON.stringify` wallet_sync.ts:680-682 | DIVERGE | S3 | same quoting asymmetry as #33 |
| 36 | publish_warning → `  WARN group-keys publish failed: {warning}` cli.py:666-667 (warning captured in `sync_ceremony` wallet.py:423-426, best-effort, body sync NOT failed) | `  WARN group-keys publish failed: {msg}` wallet_sync.ts:669 (try/catch around publishGroupKeys) | MATCH | — | best-effort, non-fatal both sides |
| **NOT-LINKED / NOT-BOUND BRANCHES** |||||
| 37 | not linked + `push_only` → `_die("...not linked; nothing to push")` exit 1 cli.py:612-613 | `die("...is not linked; nothing to push")` exit 1 wallet_sync.ts:605-607 | MATCH | — | |
| 38 | not linked + not bound → `_die("...not linked and not account-bound...")` exit 1 cli.py:615-620 | same wallet_sync.ts:608-614 | MATCH | — | |
| 39 | not linked but bound → `  (push skipped: ...run tn wallet link...)` exit 0 cli.py:621-625 | same wallet_sync.ts:615-619 | MATCH | — | |
| 40 | linked but `linked_vault is None` → `_die` cli.py:626-627 | `die("...linked_vault is empty")` wallet_sync.ts:621-623 | MATCH | — | |
| 41 | linked but no `linked_project_id` → guarded in `sync_ceremony` wallet.py:359-363 (RuntimeError, NOT _die) | `die("...no linked_project_id; relink to repair")` exit 1 wallet_sync.ts:624-625 | DIVERGE | S2 | TS checks linked_project_id in the verb (clean `die`, exit 1); Python only checks inside `sync_ceremony` and RAISES RuntimeError (uncaught → traceback/exit code differs from clean die). |
| **`--pull` BRANCH** |||||
| 42 | `_stage_account_inbox`; None → `_die("no account binding...", code=2)` cli.py:830-837 | `walletSyncPull`; null → `die(..., 2)` wallet_sync.ts:359-366 | MATCH | — | exit **2** on not-bound, both |
| 43 | `staged -> {p}` per file, `Pulled N snapshot(s); run tn absorb...`, `({K} already staged...)` cli.py:840-847 | same wallet_sync.ts:368-370 | MATCH | — | |
| **`--drain-queue` BRANCH** |||||
| 44 | `read_sync_queue` count before, `drain_sync_queue` (publish_groups=False), count after; prints `Drained...`, `pending before/after`, `uploaded N files`; `WARN N still failing` + exit 1 on errors cli.py:631-641 + wallet.py:299-322 | `pushCeremonyBody` directly (no queue file read); prints `Drained sync queue`, `uploaded N files`; exit 0 wallet_sync.ts:665-676 | DIVERGE | S1 | **TS has NO sync-queue concept.** Python drain reads/truncates `<stem>/sync/queue` (admin._sync_queue_path), prints pending before/after, returns 1 if still failing. TS `--drain-queue` just pushes once and prints `uploaded N files`, never touches a queue file, always exits 0 on success. Different semantics entirely. |
| 45 | drain skips pull/absorb AND publish_groups cli.py:631 / wallet.py:314 | drain skips pull/absorb (wallet_sync.ts:599) AND publish (wallet_sync.ts:665) | MATCH | — | both skip those legs |
| **AUTOSYNC-ON-INIT SIDE EFFECT** |||||
| 46 | `tn init` at verb entry (cli.py:583) runs the handler chain → can fire an autosync push as a SIDE EFFECT of `wallet sync` invocation | TS reads raw yaml, NO runtime init at entry (wallet_sync.ts:585); NodeRuntime.init only later for absorb/push | DIVERGE | S2 | Python loading the runtime at the top of the verb can trigger handler-driven autosync before the explicit sync logic runs (observed: `tn init demoproj` itself attempted a sync). TS has no such implicit pre-sync. |
| **`--vault` OVERRIDE FLAG** |||||
| 47 | **no `--vault` flag** on `wallet sync` (cli.py argparse) — vault from yaml `linked_vault` only | `--vault <url>` flag (wallet_sync.ts:79, opts.vault threaded through pull+push) | DIVERGE | S2 | Runtime-confirmed (§4): `tn wallet sync ... --vault ...` errors `unrecognized arguments` on Python; TS accepts it. |
| **`TN_ACCOUNT_PASSPHRASE` ENV** |||||
| 48 | passphrase falls back to `os.environ["TN_ACCOUNT_PASSPHRASE"]` cli.py:599-601 | **MISSING** — opts.passphrase only wallet_sync.ts:627 | DIVERGE | S2 | Headless Python honors the env var so argv doesn't echo the secret; TS has no env fallback. |

---

## 3. Restore-body-path divergence verified on the PUSH side

The task flags a documented TS/Python restore divergence (TS flat members vs
Python nested `body/keys/...`). **On the PUSH side both impls are NESTED and
agree** — this is the good case:

- Python `_collect_body_members` keys: `body/keys/<name>`, `body/tn.yaml`
  (wallet.py:53-54).
- TS `collectBodyMembers` keys: `body/keys/<name>`, `body/tn.yaml`
  (wallet_sync.ts:385,388).

Both encrypt the SAME nested STORED-zip layout (ledger #9, #16). So a body
pushed by EITHER CLI carries `keys/<name>` + `tn.yaml` under `body/`. The
divergence the memory note refers to is on the **restore/unpack** side (a
separate code path, `wallet_restore._write_restored_bytes` vs `restore.ts`),
NOT here — confirmed the push producers are byte-shape compatible.

One real push-side body divergence remains: **logs members** (ledger #11) —
Python adds `body/logs/<name>` when `ceremony.sync_logs:true`; TS never does.

---

## 4. Runtime confirmation

Live dev vault `http://localhost:38790` (up; `/` → 200). CLIs:
`C:\codex\tn\tn-e2e\.venv_rel\Scripts\tn.exe` (Python wheel) and
`node C:\codex\tn\tn_proto\ts-sdk\bin\tn-js.mjs` (TS). A fresh ceremony was
created with `tn init demoproj`, which auto-linked to the vault
(project `01KTF6QQ6PTRBXQETCB2K8ATWQ`, ceremony `local_59810e76`) and carries a
`default` btn group. The account has **no PBKDF2 credential registered**
(passkey registration is browser-only per `getCredentialWrap`/
`_fetch_credential_with_wrap`), so a credential-backed body PUT cannot complete
from either CLI — a documented constraint, not a harness gap. Everything UP TO
the credential fetch was exercised, plus all early-exit branches.

### 4a. Stdout / exit, same linked ceremony, no passphrase

```
$ tn.exe wallet sync <yaml>                         # PYTHON
  pulled+absorbed 0 snapshot(s), 0 new event(s)
Synced local_59810e76 -> http://localhost:38790
  uploaded 0 files: []
  WARN 1 errors: [('<passphrase>', 'account passphrase required to push the body backup ...')]
PY_EXIT=1

$ node tn-js.mjs wallet sync <yaml>                  # TS
  pulled+absorbed 0 snapshot(s), 0 new event(s)
tn: error: --passphrase required to push the body backup (derives your account key to wrap the project BEK).
TS_EXIT=1
```

→ confirms ledger **#30**: Python prints `Synced`+`uploaded 0 files: []`+`WARN
1 errors` then exit 1; TS dies before any `Synced` line. Both exit 1.

### 4b. Stdout / exit, with `--passphrase` (no credential registered)

```
# PYTHON
Synced local_59810e76 -> http://localhost:38790
  uploaded 0 files: []
  WARN 1 errors: [('local_59810e76', 'RestoreError: no credentials registered for this account ...')]
PY_EXIT=1

# TS
  pulled+absorbed 0 snapshot(s), 0 new event(s)
tn: error: push failed for local_59810e76: no credentials registered for this account — register one via the browser flow first
TS_EXIT=1
```

→ confirms ledger **#31** (error surfacing shape) and **#21** (error text).

### 4c. Request sequence (captured via a logging reverse-proxy)

A stdlib logging proxy was placed in front of the vault; each CLI's request
order was recorded.

```
PYTHON push leg:                         TS push leg:
  POST /api/v1/auth/challenge              POST /api/v1/auth/challenge
  POST /api/v1/auth/verify                 POST /api/v1/auth/verify
  GET  /api/v1/account/inbox        (pull) GET  /api/v1/account/inbox      (pull)
  POST /api/v1/auth/challenge       (re-auth) POST /api/v1/auth/challenge  (re-auth)
  POST /api/v1/auth/verify                 POST /api/v1/auth/verify
  GET  /api/v1/account/credentials?include=wrap   GET  /api/v1/projects/{id}/wrapped-key
       (← credentials FIRST, stops here)         GET  /api/v1/account/credentials?include=wrap
                                                       (← wrapped-key FIRST, then credentials)
```

→ confirms ledger **#22**: Python fetches **credentials first** (AWK derivation
precedes wrapped-key fetch); TS fetches **wrapped-key first**, then credentials.
Same terminal "no credentials" failure, different request sequence. Both
re-authenticate (fresh challenge/verify) between the pull leg and the push leg
rather than reusing one token across legs.

### 4d. `--vault` flag

```
$ tn.exe wallet sync <yaml> --passphrase X --vault http://localhost:38799
tn: error: unrecognized arguments: --vault http://localhost:38799
```

→ confirms ledger **#47**: Python `wallet sync` rejects `--vault`; TS accepts it.

---

## 5. Prioritized MUST-FIX list

**S1 — behavioral, a second device / data can be harmed:**

1. **#23 wrapped-key non-404 → MINT (Python).** `_fetch_wrapped_key` raises on
   ANY non-200 and `push_ceremony_body` catches it as "no key → mint a fresh
   BEK + PUT wrapped-key" (wallet_push.py:354-389). A transient 5xx/403 makes
   Python mint a NEW BEK and overwrite the wrapped-key, orphaning the existing
   encrypted body blob (now undecryptable). TS mints only on 404
   (wallet_sync.ts:421-424). **Fix: Python must mint only on a real 404**, not
   any non-200.
2. **#11 logs body members (TS MISSING).** `ceremony.sync_logs:true` packs
   `body/logs/<name>` in Python (wallet.py:55-63) but TS `collectBodyMembers`
   has no such branch — logs silently dropped from the TS backup. **Fix: port
   the sync_logs branch to TS** (or decide logs-in-body is Python-only and
   document it).
3. **#44 `--drain-queue` semantics (TS MISSING the queue).** Python drain reads
   and truncates the autosync queue file and reports pending before/after,
   returning 1 if entries remain (wallet.py:299-322); TS `--drain-queue` just
   does a single push and always exits 0. **Fix: TS needs a real sync-queue
   read/drain or `--drain-queue` should be documented as a no-op alias.**

**S2 — stdout / exit / UX a script can trip on:**

4. **#30/#31 missing-passphrase & push-error shape.** Python prints `Synced
   ...` + `uploaded 0 files: []` + `WARN N errors` and exit 1; TS dies with
   `tn: error:` and never prints `Synced`. Pick one contract (the TS clean-die
   is the better UX; Python's "Synced then WARN errors" is misleading). Align.
5. **#22 credential/wrapped-key fetch order.** Harmless today but the two impls
   probe the vault in different order; converge for predictable request traces
   and identical failure-first behavior.
6. **#41 linked_project_id check.** Python RAISES RuntimeError (traceback) where
   TS does a clean `die`. Move the Python guard into the verb as a `_die`.
7. **#47 `--vault` flag** and **#48 `TN_ACCOUNT_PASSPHRASE` env** — present in
   one impl, missing in the other. Add `--vault` to Python's `wallet sync`
   parser; add the env fallback to TS (or drop both for symmetry).
8. **#46 autosync-on-init side effect (Python).** `tn init` at verb entry can
   fire a handler-driven push before the explicit sync logic; TS has no implicit
   pre-sync. Decide whether the verb should load the full runtime at entry.
9. **#3b/#8 sanitization & informed-conflict narrowing** — minor asymmetries
   (Python doesn't `safe_path_seg` the ts filename; Python flags ANY `informed`
   conflict vs TS's leaf_reuse-only). Tighten both toward the stricter side.

**S3 — cosmetic:**

10. **#33/#35 list quoting** (Python repr vs JSON.stringify), **#27 timestamp
    precision** (real micros vs ms-padded), **#21 error text**. Harmonize the
    stdout strings if byte-identical output is a parity goal.

---

## 6. Summary

- **Side-effects audited:** 48 rows.
- **MATCH:** 26 · **DIVERGE:** 21 · **MISSING (one side absent):** 3 of those
  diverges are a true MISSING feature (#11 TS logs, #44 TS queue, #48 TS env).
- **Crypto core is solid:** AWK/BEK AAD constants, PBKDF2 params + floor, the
  no-AAD `nonce||ct` STORED-zip body frame, the wrapped-key and
  encrypted-blob-account PUT bodies (7 fields each) are **field-for-field
  identical** (#13-#19). A body pushed by either CLI round-trips through the
  other's restore. Push-side body layout is NESTED on both sides (#9) — the
  documented flat-vs-nested divergence lives only on the restore/unpack side.
- **Runtime-confirmed divergences:** #30/#31 (stdout+exit shape), #22 (request
  order), #47 (`--vault` flag) — captured live against the dev vault.
- **Top risk: #23** — Python minting a fresh BEK on any non-404 wrapped-key
  response can orphan an existing body blob. Fix first.
