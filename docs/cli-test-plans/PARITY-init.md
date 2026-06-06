# Parity ledger: `init` + claim-URL path (Python vs TypeScript)

Audit of the full `tn init` cold-path (no vault account yet → mint a
pending-claim and surface a claim URL). Every row cites exact `file:line`
on both sides. Runtime-confirmed against the live dev vault
(`http://localhost:38790`, `TN_DEV_AUTH_BYPASS=1`) on 2026-06-06.

Repo: `C:\codex\tn\tn_proto`. All paths below are repo-relative unless absolute.

Legend: **MATCH** = same observable effect. **DIVERGE** = effect exists on
both sides but differs. **MISSING** = effect on Python with no TS counterpart.

---

## 1. Call-chain maps

### Python

| Step | Function | File:line |
|------|----------|-----------|
| 1 | `cmd_init(args)` | `python/tn/cli.py:221` |
| 2 | identity load/mint + ceremony mint (`_ensure_ceremony_on_disk`, `_stamp_project_labels`) | `python/tn/cli.py:283-378` |
| 3 | vault-link branch (`if not args.no_link:`) | `python/tn/cli.py:402` |
| 3a | warm-attach probe (`_try_warm_attach`) | `python/tn/cli.py:415-417` |
| 3b | cold path: `_default_client_factory` + `init_upload(cfg, client, vault_base)` | `python/tn/cli.py:419-426` |
| 4 | `init_upload(...)` | `python/tn/handlers/vault_push.py:273` |
| 4a | TTL-reuse short-circuit (`get_pending_claim` + expiry math) | `python/tn/handlers/vault_push.py:316-334` |
| 4b | mint BEK, export encrypted `full_keystore` tnpkg, unlink staged file | `python/tn/handlers/vault_push.py:336-359` |
| 4c | `client.post_pending_claim(body, project_name=...)` | `python/tn/handlers/vault_push.py:364-367` |
| 4d | build claim URL | `python/tn/handlers/vault_push.py:372` |
| 4e | `set_pending_claim(...)` → `state.json` | `python/tn/handlers/vault_push.py:375-381` → `python/tn/sync_state.py:205` |
| 4f | `_write_claim_url_file(...)` → `claim_url.txt` | `python/tn/handlers/vault_push.py:384,257` |
| 4g | `_emit_claim_url_admin_event(...)` → admin outbox JSON | `python/tn/handlers/vault_push.py:385,208` |
| 5 | stdout block (Backed up / CLAIM URL / connect hints) | `python/tn/cli.py:427-441` |
| — | `post_pending_claim` HTTP impl | `python/tn/handlers/vault_push.py:788` |

### TypeScript

| Step | Function | File:line |
|------|----------|-----------|
| 1 | `initCmd()` | `ts-sdk/bin/tn-js.mjs:812` |
| 2 | identity load/mint + ceremony mint (`ensureCeremonyOnDisk`, `wasFresh`) | `ts-sdk/bin/tn-js.mjs:849-873` |
| 3 | vault-attach branch (`if (flipMint && wasFresh && !noLink)`) | `ts-sdk/bin/tn-js.mjs:901` |
| 3a | warm-attach probe (`_tryWarmAttach`) | `ts-sdk/bin/tn-js.mjs:903-906` |
| 3b | cold path: `tn.initUpload({ vaultBase })` | `ts-sdk/bin/tn-js.mjs:910` |
| 4 | `Tn.initUpload` → `initUpload(rt, opts)` | `ts-sdk/src/tn.ts:844` → `ts-sdk/src/handlers/init_upload.ts:57` |
| 4a | TTL-reuse short-circuit | **MISSING** |
| 4b | mint BEK, export encrypted `full_keystore` tnpkg, rm temp | `ts-sdk/src/handlers/init_upload.ts:67-85` |
| 4c | `fetch POST /api/v1/pending-claims` | `ts-sdk/src/handlers/init_upload.ts:90-110` |
| 4d | build claim URL | `ts-sdk/src/handlers/init_upload.ts:130` |
| 4e | `updateSyncState(pending_claim={...})` → `state.json` | `ts-sdk/src/handlers/init_upload.ts:144-155` → `ts-sdk/src/sync_state.ts:102` |
| 4f | write `claim_url.txt` | `ts-sdk/src/handlers/init_upload.ts:156-162` |
| 4g | emit claim-url admin event | **MISSING** |
| 5 | stdout block + final JSON line | `ts-sdk/bin/tn-js.mjs:912-941` |

---

## 2. Side-effect ledger

One row per observable side-effect of the cold init-upload path.

| # | Python effect (file:line) | TS counterpart (file:line or MISSING) | status | sev | detail |
|---|---------------------------|---------------------------------------|--------|-----|--------|
| 1 | Vault URL resolved: `--link` → `identity.linked_vault` → `TN_VAULT_URL` → hosted default — `cli.py:403` (`resolve_vault_url` `vault_client.py:68`) | `resolveVaultUrl(linkUrl)` — `tn-js.mjs:902` | DIVERGE | MED | TS resolution order omits `identity.linkedVault` (row 2). Env/default tiers match. |
| 2 | Persist resolved vault into `identity.linked_vault` + rewrite identity.json when previously null — `cli.py:404-406` | MISSING | MISSING | HIGH | **Runtime-proven:** PY identity.json `linked_vault=http://localhost:38790`; TS `linkedVault=null`. Breaks future warm-attach + resolution tier #2. |
| 3 | Warm-attach gate signal = `TN_API_KEY` or `identity.linked_account_id` — `cli.py:415` | `TN_VAULT_API_KEY` \|\| `TN_API_KEY` \|\| `identity.linkedAccountId` — `tn-js.mjs:903` | DIVERGE | LOW | TS additionally honors `TN_VAULT_API_KEY`. Superset, not a regression. |
| 4 | Cold path entered only when warm-attach not taken — `cli.py:419` | Cold path entered only when `!attached` — `tn-js.mjs:907` | MATCH | — | Both fall through to claim-URL on warm miss. |
| 5 | TTL-reuse: if live `pending_claim` inside TTL, return it `reused=True`, **no** re-upload (C18) — `vault_push.py:316-334` | MISSING | MISSING | MED | TS `initUpload` always mints a fresh BEK + POSTs. CLI-masked (see §4) but the library API diverges. |
| 6 | Mint 32-byte BEK; `password_b64 = base64url(bek)` no padding — `vault_push.py:337-338,202` | `randomBytes(32)` → `Buffer.toString("base64url")` — `init_upload.ts:67-68` | MATCH | — | Same encoding (base64url, no pad). |
| 7 | Stage encrypted `full_keystore` tnpkg at `<yamlDir>/.tn/sync/init_upload_<ts>.tnpkg`, then unlink — `vault_push.py:340-359` | Stage at `mkdtemp()/init_upload.tnpkg`, then `rmSync` temp dir — `init_upload.ts:73-85` | DIVERGE | LOW | Different staging dir (PY under ceremony `.tn/sync/`, TS under OS tmp). Both unlink; no residue either side (runtime tree shows neither). Cosmetic. |
| 8 | export kind=`full_keystore`, `confirm_includes_secrets=True`, `encrypt_body_with=bek` — `vault_push.py:345-352` | `rt.exportFullKeystoreEncrypted(bek, outPath)` — `init_upload.ts:77` | MATCH | — | Both produce a BEK-encrypted full_keystore body. |
| 9 | HTTP `POST {base}/api/v1/pending-claims`, `Content-Type: application/octet-stream`, body=ciphertext, **no auth** — `vault_push.py:811-828` | `fetch POST {base}/api/v1/pending-claims`, same content-type, body, no auth — `init_upload.ts:90-110` | MATCH | — | Runtime-proven: both got HTTP 200 + `vault_id`/`expires_at`. |
| 10 | Header `X-Publisher-Did` = VaultClient identity DID — `vault_push.py:817-825` | `X-Publisher-Did` = `rt.config.device.device_identity` — `init_upload.ts:93-94` | MATCH | — | Both resolve to device DID. |
| 11 | Header `X-Project-Name` when ceremony carries one — `vault_push.py:826-827` (`project_name` from `cfg.project_name` `cli.py`→ `vault_push.py:364`) | `X-Project-Name` from `rt.config.projectName` — `init_upload.ts:95-96` | MATCH | — | Both stamp the project label. |
| 12 | Request timeout: VaultClient httpx default | `AbortController` 30 000 ms — `init_upload.ts:62,98-99` | DIVERGE | LOW | Explicit 30 s on TS; PY relies on client default. Behavior equivalent for happy path. |
| 13 | Non-2xx → raise (caught by `cli.py:442` → WARN, init still exit 0) — `vault_push.py:829` | `!resp.ok` → throw (caught `tn-js.mjs:925` → WARN, exit 0) — `init_upload.ts:112-117` | MATCH | — | Both soft-warn, never fail init. |
| 14 | Missing `vault_id`/`expires_at` in resp → `KeyError` propagates to WARN — `vault_push.py:366-367` | explicit throw on missing fields — `init_upload.ts:122-127` | MATCH | — | TS validates explicitly; both end in the WARN path. |
| 15 | Build claim URL `{base.rstrip('/')}/claim/{vault_id}#k={password_b64}` — `vault_push.py:372` | `{base}/claim/{vaultId}#k={passwordB64}` (base already `replace(/\/+$/,'')`) — `init_upload.ts:63,130` | MATCH | — | Identical URL shape; runtime URLs identical in form. |
| 16 | Write `state.json`: `pending_claim={vault_id,expires_at,claim_url,password_b64}` at `<yamlDir>/.tn/sync/state.json` — `vault_push.py:375-381`, `sync_state.py:205-222` | `updateSyncState(pending_claim={...})` same path — `init_upload.ts:144-155`, `sync_state.ts:102-116` | DIVERGE | MED | Field values match. **But** nested-object key order differs: PY `json.dumps(sort_keys=True)` sorts recursively (claim_url,expires_at,password_b64,vault_id); TS `saveSyncState` sorts **top-level only** (`sync_state.ts:86-88`), nested `pending_claim` stays insertion-order. Runtime-proven (see §3.2). Byte-divergent file; any cross-impl exact-content test fails. |
| 17 | Write `claim_url.txt` = `claim_url + "\n"` at `<yamlDir>/.tn/sync/claim_url.txt` — `vault_push.py:257-270` | `writeFileSync(.../claim_url.txt, url+"\n")` — `init_upload.ts:156-162` | MATCH | — | Runtime-proven: both files present, `url\n`. |
| 18 | Emit admin event `tn.vault.claim_url_issued` as JSON file in `<stem>/admin/outbox/claim_url_issued_<ts>_<vault_id>.json` (fields: claim_url, did, emitted_at, event_type, expires_at, vault_id; sorted, indent=2) — `vault_push.py:208-254` | MISSING | MISSING | HIGH | **Runtime-proven:** PY tree has the file; TS tree has no `admin/outbox/` at all. Auditor inspecting the outbox sees no issuance trail on TS. |
| 19 | `set_pending_claim` returns; `reused` flag in return dict — `vault_push.py:392-398` | return `{vaultId,expiresAt,claimUrl,passwordB64}` — no `reused` — `init_upload.ts:164` | DIVERGE | LOW | TS result has no `reused`; CLI never prints "(reusing…)" line (row 23). Consequence of row 5. |
| 20 | stdout `\n[tn init] Backed up to {vault_url}` + `vault_id:` + `expires:` (local-tz fmt) — `cli.py:427-430` | same three lines — `tn-js.mjs:912-914` | MATCH | — | Runtime-proven identical wording. |
| 21 | `expires:` rendered via `_format_expires_local` (`%Z` long name, e.g. "Eastern Daylight Time") — `cli.py:146-160` | `_formatExpiresLocal` (Intl `short`, e.g. "EDT") — `tn-js.mjs:986-1008` | DIVERGE | LOW | Same instant; tz-label style differs (long vs short). Cosmetic. |
| 22 | stdout CLAIM URL block + "Already have a vault account…" 3-step hint — `cli.py:434-441` | same block — `tn-js.mjs:915-924` | MATCH | — | Runtime-proven; only `tn`→`tn-js` in the connect-command example. |
| 23 | stdout `(reusing live pending-claim within TTL)` when reused — `cli.py:431-432` | MISSING | MISSING | LOW | Never reachable on TS (row 5/19). Only fires on PY library-level reuse. |
| 24 | Final machine-readable JSON line | MISSING (PY prints no JSON summary) | DIVERGE | LOW | TS prints `{ok,yaml_path,ceremony_id,did,claim_url?}` — `tn-js.mjs:932-941`. TS-only superset; PY is human-only. |
| 25 | CLI-level idempotency: existing ceremony → re-attach, **no** init_upload (early return) — `cli.py:339-349` | `flipMint && wasFresh` gate; `wasFresh=false` on re-run → no upload — `tn-js.mjs:866,901` | MATCH | — | **Runtime-proven:** 2nd run on both sides kept the same `vault_id`, no new POST. |
| 26 | Exit 0 on success and on vault-unreachable WARN — `cli.py:455` | exit 0 (no nonzero throw escapes) — `tn-js.mjs` | MATCH | — | Runtime-proven: both exit 0. |
| 27 | `TN_NO_STDOUT` defaulted to "1" so log envelopes don't pollute claim output — `cli.py:229-230` | n/a (TS CLI has no stdout log-envelope handler) | MATCH | — | Equivalent end state: clean human output both sides. |
| 28 | Admin log row written by ceremony mint (`admin/admin.ndjson`) — side effect of step 2 (not init_upload) | `admin/admin.ndjson` not produced — runtime tree | DIVERGE | MED | Out-of-scope-ish (ceremony mint, not claim path) but **runtime-proven**: PY tree has `admin/admin.ndjson` (+`.emit.lock`); TS tree has no `admin/` dir. Flag for a separate mint-path audit. |

---

## 3. Runtime confirmation

Both CLIs run in isolated dirs against the live dev vault. Commands:

```
# Python
TN_VAULT_URL=http://localhost:38790 TN_DEV_AUTH_BYPASS=1 \
TN_IDENTITY_DIR=C:\tmp_parity\py\id  C:\codex\tn\tn-e2e\.venv_rel\Scripts\tn.exe init demoproj
# (cwd C:\tmp_parity\py\work)

# TypeScript
TN_VAULT_URL=http://localhost:38790 TN_DEV_AUTH_BYPASS=1 \
TN_IDENTITY_DIR=C:\tmp_parity\ts\id  node C:\codex\tn\tn_proto\ts-sdk\bin\tn-js.mjs init demoproj
# (cwd C:\tmp_parity\ts\work)
```

Both exited 0 and minted a real `vault_id` from the vault.

### 3.1 Filesystem tree diff (`find .tn -type f`)

```
  PYTHON                                                        TS
  .tn/demoproj/.tn/sync/claim_url.txt                          .tn/demoproj/.tn/sync/claim_url.txt
  .tn/demoproj/.tn/sync/state.json                             .tn/demoproj/.tn/sync/state.json
- .tn/demoproj/.tn/tn/admin/outbox/claim_url_issued_*.json     (absent)            <-- row 18 MISSING
- .tn/demoproj/admin/admin.ndjson                              (absent)            <-- row 28 DIVERGE
- .tn/demoproj/admin/admin.ndjson.emit.lock                    (absent)
  .tn/demoproj/keys/default.btn.mykit                          .tn/demoproj/keys/default.btn.mykit
  .tn/demoproj/keys/default.btn.state                          .tn/demoproj/keys/default.btn.state
- .tn/demoproj/keys/default.btn.state.lock                     (absent)
  .tn/demoproj/keys/index_master.key                           .tn/demoproj/keys/index_master.key
  .tn/demoproj/keys/local.private                              .tn/demoproj/keys/local.private
  .tn/demoproj/keys/local.public                               .tn/demoproj/keys/local.public
  .tn/demoproj/keys/tn.agents.btn.mykit                        .tn/demoproj/keys/tn.agents.btn.mykit
  .tn/demoproj/keys/tn.agents.btn.state                        .tn/demoproj/keys/tn.agents.btn.state
- .tn/demoproj/keys/tn.agents.btn.state.lock                   (absent)
  .tn/demoproj/tn.yaml                                         .tn/demoproj/tn.yaml
```

TS-side files missing vs Python: the `claim_url_issued` admin event (row 18),
`admin/admin.ndjson` + its emit lock (row 28), and the per-keystore `.state.lock`
files (lock-file strategy difference, not a claim-path concern).

### 3.2 `state.json` content diff (note key ordering)

Python (recursively sorted — `sort_keys=True`):
```json
{ "pending_claim": {
    "claim_url": "...#k=...", "expires_at": "2026-06-07T19:30:28.496497+00:00",
    "password_b64": "...", "vault_id": "01KTF6MMGGSQS5RFFYSSEMBSVM" } }
```
TS (top-level sorted only; nested insertion-order):
```json
{ "pending_claim": {
    "vault_id": "01KTF6MVVFHTJW2TRC1R25F363", "expires_at": "...",
    "claim_url": "...#k=...", "password_b64": "..." } }
```
Same field set + values; **nested key order differs** (row 16).

### 3.3 `claim_url.txt`

Both: `http://localhost:38790/claim/<vault_id>#k=<password_b64>\n`. MATCH (row 17).

### 3.4 stdout diff

Human block is line-for-line identical except (a) `expires:` tz label
("Eastern Daylight Time" vs "EDT", row 21), (b) connect example `tn` vs
`tn-js` (row 22), (c) TS appends a machine-readable JSON summary line (row 24).
PY prints no such JSON. No "(reusing…)" line either side (fresh mint).

### 3.5 Idempotency re-run

Second `init demoproj` in the same dir on both sides: vault_id unchanged
(`01KTF6MMGG…` PY / `01KTF6MVVF…` TS), no new POST — both hit the
"existing ceremony → re-attach" guard (row 25). The Python library-level
TTL-reuse (row 5) is **not** exercised by a second CLI call because the
CLI returns early before reaching `init_upload`; it is reachable only by
calling `init_upload` twice directly on a persisted ceremony.

---

## 4. Prioritized MUST-FIX list

### HIGH

1. **Row 18 — claim-url admin event MISSING on TS.** Python drops a
   `tn.vault.claim_url_issued` JSON envelope into `<stem>/admin/outbox/`
   (`vault_push.py:208-254`); TS emits nothing and has no `admin/outbox/`
   dir. An auditor inspecting the outbox (live-consistency invariant C17)
   sees no issuance trail on TS. **Fix:** port `_emit_claim_url_admin_event`
   into `ts-sdk/src/handlers/init_upload.ts` writing the same filename
   shape + sorted JSON fields.

2. **Row 2 — `identity.linked_vault` not persisted on TS.** Python writes
   the resolved vault back into identity.json (`cli.py:404-406`); TS never
   does. Runtime-proven (PY `linked_vault` set, TS null). Breaks the
   resolution tier #2 (`identity.linkedVault`, row 1) and silently weakens
   future warm-attach. **Fix:** in `initCmd` after `resolveVaultUrl`, set
   `identity.linkedVault` and re-persist when previously null.

### MED

3. **Row 16 — `state.json` nested key order divergence.** TS sorts only
   top-level keys (`sync_state.ts:86-88`); Python sorts recursively. The
   `pending_claim` block is byte-divergent. **Fix:** deep-sort in
   `saveSyncState` (or `JSON.stringify` with a recursive key-sorted
   replacer) to match Python's `sort_keys=True`.

4. **Row 5 — TTL-reuse / C18 idempotency MISSING in TS `initUpload`.**
   Python short-circuits a live pending-claim within TTL and returns
   `reused=True` without re-uploading (`vault_push.py:316-334`); TS always
   mints a fresh BEK + POSTs. CLI-masked today (the CLI re-attach guard
   fires first) but the library entry point diverges and any direct caller
   gets double-uploads + a stomped `vault_id`. **Fix:** add the
   `reuse_pending_window` read-then-validate-TTL branch to
   `init_upload.ts`, plus a `reused` flag on `InitUploadResult` (row 19)
   and the `(reusing…)` stdout line (row 23).

5. **Row 28 — `admin/admin.ndjson` not produced on TS.** Strictly a
   ceremony-mint side effect (upstream of the claim path), but the TS init
   leaves no admin log on disk at all. Flag for a separate mint-path audit;
   it widens the auditability gap that row 18 also reflects.

### LOW (cosmetic / superset — note, optional)

- Row 1/3: TS vault-URL resolution omits the `linkedVault` tier (downstream
  of fix #2) and adds `TN_VAULT_API_KEY` (harmless superset).
- Row 7/12: staging dir + explicit timeout differ; behavior-equivalent.
- Row 21: tz-label long vs short. Row 22: `tn` vs `tn-js`. Row 24: TS-only
  JSON summary line.

---

## 5. Summary counts

- **Total effects audited:** 28
- **MATCH (15):** rows 4, 6, 8, 9, 10, 11, 13, 14, 15, 17, 20, 22, 25, 26, 27
- **DIVERGE (8):** rows 1, 7, 12, 16, 19, 21, 24, 28
- **MISSING (4):** rows 2, 5, 18, 23

(Reconciles: 15 + 8 + 4 = 27 across rows 1–28, with row 3 also a LOW
DIVERGE — 9 DIVERGE if counted; listed under DIVERGE-low in §4. The 28th
row is row 3.)

**Must-fix (HIGH):** rows 18 (claim-url admin event) and 2 (linked_vault
persistence). **Must-fix (MED):** rows 16 (state.json deep-sort), 5
(TTL-reuse), 28 (admin.ndjson).
