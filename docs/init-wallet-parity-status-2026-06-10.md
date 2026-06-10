# Init + Wallet: status & remaining work (2026-06-10)

Init "sync-if-exists / push-if-new" on a logged-in account, backed by a
cached-AWK credential model (the gh/claude pattern: cache the derived key,
never the master secret, OS keychain + 0600-file fallback).

## DONE — Python, proven against the live vault (tne2e, :38790)

- `credential_store.py` (NEW): `CredentialStore` (keychain + 0600-file fallback), `awk_key_name`. File round-trip proven.
- `wallet_restore_passphrase.derive_account_awk` (NEW, extracted; no dup): proven live — real credential → AWK; wrong passphrase rejected.
- `wallet_push.push_ceremony_body` + `wallet.sync_ceremony`: added `awk=` (cached) intake alongside `passphrase=`; cached AWK wins; gate = `awk is None and not passphrase`. Backward-compatible.
- `_init_attach.py` (NEW): `attach_or_sync` (CLAIM_URL / WARM_CREATE / WARM_SYNC), `cache_account_awk`. Never raises (containment law). Reloads cfg after `link_ceremony` to capture the assigned project_id.
- `link_ceremony` guard FIXED (wallet.py:139): keys on `linked_project_id`, not mode/vault — a fresh `mode:linked` ceremony with no project now creates it (was a real latent bug; mocked test hid it).
- WIRING: `cli._try_warm_attach` → `attach_or_sync`; `cli.cmd_account_connect --passphrase` → `cache_account_awk`; `__init__._auto_link_after_init` → warm path. Library warm-sync is PUSH-ONLY (no pull leg yet).
- Tests: `test_init_attach_live.py` (engine + fully-wired connect→cache→init), rewrote `test_cli_warm_attach.py`. Full suite: 1154 pass, 0 regressions (1 unrelated pytest-playwright plugin failure).

## project_id sweep (the vault-side project identity = `cfg.linked_project_id`)

- FIXED: restore interactive-pick read `project_id` from untyped JSON → could reach `_derive_bek_via_passphrase` as `None` (builds `/projects/None/wrapped-key`). Now guarded + coerced (cli.py:1316).
- SAFE: `sync_ceremony` raises if `linked_project_id is None` (wallet.py:370) before any push.
- SAFE: push/pull/restore URL builders type `project_id: str` (required) — risk is only at callers passing `linked_project_id`.
- TO VERIFY: `handlers/vault_sync.py:185` builds `/projects/{self._project_id}/events` — confirm `self._project_id` can't be None at handler construction.
- NOTE: the dead top-level `project_id` yaml key (never read) is a DIFFERENT thing — not this.

## TS PARITY — the remaining must-do (ts-sdk). Survey + my verification:

EXISTS in TS (good): AWK derivation `vault/awk_bek.ts deriveAwkFromMaterial`; body push deriving AWK from passphrase `cli/wallet_sync.ts`; warm-attach orchestration `bin/tn-js.mjs _tryWarmAttach` → `wallet/index.ts WalletNamespace.link`; `account/index.ts connect`; broad tests.

MISSING / BUGGY (the parity work):
1. **`linkCeremony` guard BUG — same as Python** (`wallet/index.ts:134` + `:142`): returns early with `projectId: state.linkedProjectId` (null on a fresh ceremony) and throws "already linked" on a no-project mode:linked ceremony. FIX: key both guards on `state.linkedProjectId`.
2. **Credential store MISSING**: no AWK cache. Mirror `credential_store.py` (keychain + file fallback). Note: TS crypto is Web Crypto (portable, headless-friendly).
3. **Push cached-AWK intake MISSING**: `wallet_sync.ts` derives the AWK from a passphrase only. Add a cached-AWK path (mirror the `awk=` intake).
4. **`account connect` caches nothing**: add a passphrase option → derive AWK → cache (mirror `cache_account_awk` + the `--passphrase` flag on the tn-js connect verb).
5. **Warm-attach must READ the cached AWK** so `tn-js init` pushes the body unattended after connect (today it needs the passphrase at sync).
6. TS tests for the above (unit + a live wired test mirroring `test_wired_connect_cache_then_init`).

## Other follow-ups (not blocking)

- COMMIT the Python work (all uncommitted on `feat/wallet-sync-two-way-equivocation`).
- Move `_pull_absorb_step` to a shared module so the library/notebook path gets a pull leg (currently CLI-only → library warm-sync is push-only).
- The autolink worktree (`fix/autolink-output-parity`) + verify worktree (`fix/verify-semantics`) are separate uncommitted branches with their own work; reconcile during the D4 topology merge.
- See [[project-init-attach-credential-cache]] and the beta sprint memory for the broader context.
