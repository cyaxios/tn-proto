# Env vars

Runtime configuration knobs. **Python honors all of them; TS honors a
documented subset; Rust honors only `TN_RUN_ID` and `TN_FORCE_PYTHON`.**

Truthiness conventions are inconsistent across the Python codebase —
see [discrepancies.md#env-truthiness](./discrepancies.md#env-truthiness).
This page calls out the convention each variable uses.

## Identity / bootstrap

### TN_API_KEY

Cold-start bearer for fetching a sealed `project_seed` from the
vault. Shape: `tn_apikey_<43-char-b64url-seed>_<22-char-b64url-keyid>`.
When set on a fresh node with `vault.sync` declared in yaml, the
client redeems the bearer via
[vault-http.md](./vault-http.md#get-apiv1api-keyskey_id_b64sealed-bundle)
and installs the keystore.

Reference: `python/tn/handlers/registry.py:476`,
`ts-sdk/src/runtime/bootstrap_api_key.ts`.

Truthy: presence (non-empty string).

### TN_IDENTITY_DIR

Override for the XDG identity directory (`identity.json` location).
Default: `$XDG_DATA_HOME/tn` (POSIX) or `%APPDATA%\tn` (Windows).

Python only. TS hasn't ported the `Identity` class.

### TN_IDENTITY_DID, TN_IDENTITY_PASSPHRASE, TN_CEREMONY_ID

Identity scoping for CLI commands. Python only.

### TN_CLAIM_ON_MISSING_IDENTITY

When `=1`, auto-claim a pending vault claim on missing identity.
Python only.

Truthy: exact `"1"`.

## Layout

### TN_YAML

Explicit yaml path. Overrides discovery chain.

Honored: Python, TS.

### TN_HOME

Fallback yaml discovery directory. Default: `~/.tn`. The discovery
chain checks `$TN_HOME/tn.yaml`.

Honored: Python, TS.

### TN_ROOT_DIRNAME

Override the `.tn/` subdirectory name. Default: `".tn"`.

Python only.

### TN_DIR_NAME

Override the per-ceremony stem subdirectory name. Default: derived
from yaml basename without extension.

Python only.

### TN_STATE_DIR

Override for the wallet-daemon sync queue location. Default:
`$XDG_STATE_HOME/tn` (POSIX) or `%APPDATA%\tn` (Windows).

Python only. TS hasn't ported the wallet daemon.

### TN_CACHE_DIR, TN_KEYS_DIR, TN_OUTBOX_DIR, TN_LOG_PATH, TN_ADMIN_LOG_PATH

Per-component path overrides. Python only.

## Vault

### TN_VAULT_URL

Vault base URL. Default: `https://vault.tn-proto.org`. Read by
`resolveVaultUrl(baseUrl)` after the explicit argument.

Honored: Python, TS.

### TN_VAULT_DEFAULT_BASE

Default base URL for `did:key:` vault DID resolution. Default:
`https://vault.tn-proto.org`. Read by `resolveDidEndpoint(did)` when
the DID is `did:key:`.

Honored: Python, TS.

### TN_VAULT_PROJECT_ID, TN_VAULT_JWT, TN_VAULT_TIMEOUT

Project scope, pre-minted JWT, HTTP timeout. Python only.

## Runtime

### TN_STRICT

When truthy, `tn.init()` with no yaml path THROWS instead of
silently minting a fresh ceremony.

Truthy: lowercased value in `{"1", "true", "yes", "on"}`. Python and
TS use the same set. Programmatic `Tn.setStrict(true)` wins over env
in TS.

Honored: Python, TS.

Reference: `python/tn/_autoinit.py:71`, `ts-sdk/src/tn.ts::_envStrict`.

### TN_RUN_ID

Process-singleton run identifier. Auto-injected into every emit's
`run_id` field. Python and Rust wasm read this at runtime init;
they MUST stamp matching values so the `tn.read()` "this run only"
filter works.

If set in the environment by a parent shell, child processes
OVERWRITE it on first `tn.init()` — inheriting the parent's run-id
silently is a bug.

Honored: Python (writes), Rust wasm (reads at init), TS Node (writes
via `src/_run_id.ts::ensureProcessRunId`).

Reference: `python/tn/__init__.py:264-277`,
`crypto/tn-core/src/runtime.rs:860`,
`ts-sdk/src/_run_id.ts`.

### TN_AUTOINIT_QUIET

When `=1`, silences the "auto-mint banner" Python prints on a fresh
ceremony.

Honored: Python, TS.

Truthy: exact `"1"`.

### TN_FORCE_PYTHON

When set, Python skips the Rust wasm runtime and uses the pure-Python
emit/read path. Used for debugging.

Python only. TS IS the wasm path — no fallback exists.

### TN_NO_STDOUT

When `=1`, silences the default stdout handler.

Honored: Python, TS.

Truthy: exact `"1"`.

### TN_NO_LINK

When `=1`, skip auto-link to the vault on `tn.init()`.

Honored: Python. TS exposes the predicate (`isAutoLinkDisabled`)
but has no auto-link path to gate yet.

Truthy: exact `"1"`.

### TN_STDOUT_FORMAT

`"pretty"` (default) or `"json"`. Controls the stdout handler's per-
envelope rendering.

Honored: Python, TS.

### TN_STDOUT_INCLUDE_ADMIN

When `=1`, allows `tn.*`-prefixed admin events to appear in stdout
(suppressed by default).

Honored: Python, TS.

Truthy: exact `"1"`.

### TN_SURFACE_LOG

When set to a path, every public-surface ENTER/EXIT is appended to
that file for debugging.

Python only.

### TN_LOG_LEVEL, TN_DEBUG

Convenience env vars for the process-wide level threshold and a
debug toggle. Python only (Python's autoinit reads them; TS uses
explicit `Tn.setLevel` calls).

### TN_READER_LEGACY

When truthy, Python's reader emits the legacy flat shape instead of
the current grouped shape. Compat knob — Python only.

Truthy: value in `{"1", "true", "True"}`.

### TN_WALLET_AUTOSYNC

When `=1`, the wallet daemon syncs queued events automatically.

Python only. TS hasn't ported the wallet daemon.

Truthy: exact `"1"` (note: checked as `!= "1"` for the negation
gate).

## Integrations

### TN_KAFKA_BOOTSTRAP, TN_KAFKA_USERNAME, TN_KAFKA_PASSWORD

Kafka exporter creds. Python only.

### TN_DELTA_TOKEN, TN_DELTA_HOST

Delta Lake exporter creds. Python only.

### TN_S3_*

S3 exporter creds (bucket, region, key, secret). Python only.

## Truthiness conventions — summary

The Python codebase has FOUR different truthiness checks across the
TN_* set:

| Pattern | Used by |
|---|---|
| Exact `"1"` | `TN_NO_STDOUT`, `TN_NO_LINK`, `TN_AUTOINIT_QUIET`, `TN_STDOUT_INCLUDE_ADMIN`, `TN_CLAIM_ON_MISSING_IDENTITY`, `TN_WALLET_AUTOSYNC` |
| Lowercase in `{"1","true","yes","on"}` | `TN_STRICT` |
| In `{"1","true","True"}` | `TN_READER_LEGACY` |
| Presence (non-empty) | `TN_API_KEY`, `TN_VAULT_URL`, all path/identity overrides |

New env vars SHOULD use the strict-mode convention
(`{"1","true","yes","on"}` lowercased). Existing variables are kept
on their original conventions for back-compat.

See [discrepancies.md#env-truthiness](./discrepancies.md#env-truthiness).

## Source pointers

| Implementation | File |
|---|---|
| Python (catalog) | `python/tn/cli.py:1584-1946` |
| TS (parity audit) | `ts-sdk/src/tn.ts` + `ts-sdk/src/vault/url.ts` + `ts-sdk/src/runtime/bootstrap_api_key.ts` |
| Rust | `crypto/tn-core/src/runtime.rs:860` (`TN_RUN_ID` only) |
