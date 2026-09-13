# `tn.auth` namespace — design record (Python + TypeScript)

This record preserves the proposed Python and TypeScript contract, design
decisions, and implementation order. Status labels describe the design stage;
the parity checklist defines the shared requirements. For supported usage, see
[Authentication & accounts](auth.md).

## Principles

1. **Library-first.** The logic lives in a real, importable namespace
   (`tn.auth` in Python, `tn.auth` in TS) that *any* code can call. The CLI
   is a thin printer over it. No `cli_*` implementation modules.
2. **No printing in the library.** Every verb returns an `AuthState` (or
   raises a typed `AuthError`). All human I/O happens in the CLI layer.
3. **Error containment.** Read verbs (`status`, `whoami`) and
   local-mutation verbs (`use`, `logout`) NEVER raise. Action verbs
   (`login`, `connect`) raise `AuthError` ONLY for the failures the caller
   explicitly asked about (bad code, headless-without-credentials) — never a
   stray stack trace.
4. **Parity.** Python and TypeScript signatures must match in shape and
   pass the shared parity checks.

## Single source of truth: the three layers

Every verb is a read of, or a transition between, three booleans:

| Layer | Question | Source |
|---|---|---|
| `linked` | does the local file claim an account? | `identity.linked_account_id is not None` |
| `enrolled` | does the vault agree this device belongs to that account? | DID challenge / `GET /account/me` (None when unchecked) |
| `key_cached` | is the backup key (AWK) cached locally? | `CredentialStore.get(awk:<account_id>)` |

State machine (the resting state is "backed up"):

| linked | enrolled | key_cached | verdict |
|---|---|---|---|
| no | – | no | `not_logged_in` |
| yes | no | – | `one_sided_link` |
| yes | yes | no | `linked_no_key` |
| yes | yes | yes | `backed_up` |

---

## `AuthState` (the return type)

Python (`tn/auth.py`):
```python
@dataclass(frozen=True)
class AuthState:
    device_did: str | None
    account_id: str | None
    vault_url: str
    linked: bool
    enrolled: bool | None      # None = not checked this call
    key_cached: bool
    @property
    def verdict(self) -> Verdict: ...        # enum: NOT_LOGGED_IN | ONE_SIDED_LINK | LINKED_NO_KEY | BACKED_UP
    @property
    def message(self) -> str: ...            # one-line human label (CLI prints this)
```

TypeScript (`ts-sdk/src/auth/state.ts`):
```typescript
export interface AuthState {
  deviceDid: string | null;
  accountId: string | null;
  vaultUrl: string;
  linked: boolean;
  enrolled: boolean | null;
  keyCached: boolean;
  readonly verdict: Verdict;     // "not_logged_in" | "one_sided_link" | "linked_no_key" | "backed_up"
  readonly message: string;
}
```

`verdict` values are the SAME strings/enum names in both impls (wire-contract
discipline). `message` text is derived from `verdict` by a shared table — keep
the two tables byte-identical (a cross-impl golden test asserts this).

---

## Cross-cutting design decisions (3 gaps)

### G1 — `TN_API_KEY` cold-start stays in the init/runtime layer (REVISED)
Original plan was to wire cold-start into `login`. Implementing it revealed
`bootstrap_from_api_key(yaml_path, keystore_path, vault_did, api_key)` is
**ceremony-scoped** (it populates a *project keystore* and needs a yaml +
keystore dir + the vault's DID). Account-level `auth.login()` has no ceremony
context. Cold-start therefore remains in init / handler-builder, where those
inputs are available. `auth.login()` covers
`TN_VAULT_SESSION_TOKEN` > `code` > `account_passphrase`. Browser sign-in is
interactive I/O and lives in the CLI, not the library. This split is documented
in `tn/auth.py`'s module docstring and mirrored in TS.

### G2 — `TN_VAULT_SESSION_TOKEN` passthrough
The session token lets a non-interactive caller skip the DID challenge. The vault client accepts it; every auth verb reads
it from the env once and passes it through.
- Python: add `session_token: str | None = None` to
  `VaultClient.for_identity(...)`; when set (arg or `TN_VAULT_SESSION_TOKEN`),
  seed `self.token` and skip `authenticate()`.
- TS: `VaultClient.forIdentity(...)` already accepts `token?` on the private
  constructor — surface it on `forIdentity` opts and read the env in the auth
  layer.

### G3 — `TN_IDENTITY_PASSPHRASE` is removed from the catalog
It has **no consumer in either impl** (device key is plaintext-at-rest;
`device_priv_enc_method: "none"` in both). The design removes this unused
variable from the [Python environment catalog](../../python/tn/cli_show.py) and
[environment-variable reference](environment-variables.md). Encrypting the
device identity at rest requires a separate design.
The `device_priv_enc_method` field already anticipates it, so no schema change
is needed for that field.

---

## Per-verb designs

Notation: each verb lists the Python signature, the TS signature, the env it
honors, the behavior steps, what it returns, what it raises, and the state
transition. CLI mapping is one line. Every verb reuses the shared core helpers
(next section) — no duplicated identity-load / vault-resolve / key-check.

### `status`
- **Py:** `def status(*, vault: str | None = None, verify: bool = True) -> AuthState`
- **TS:** `status(opts?: { vault?: string; verify?: boolean }): Promise<AuthState>`
- **Env:** `TN_IDENTITY_DIR`, `TN_IDENTITY_DID`, `TN_VAULT_URL`, `TN_VAULT_DEFAULT_BASE`, `TN_VAULT_SESSION_TOKEN`.
- **Steps:** load identity (or return a not-logged-in state if none) → resolve vault → read `key_cached` → if `verify`, best-effort vault check sets `enrolled` (else `None`).
- **Returns:** `AuthState`. **Raises:** never. **Transition:** none.
- **CLI:** `tn auth status` → print the state block + `message`.

### `whoami`
- **Py:** `def whoami() -> AuthState` (≡ `status(verify=False)`).
- **TS:** `whoami(): Promise<AuthState>`.
- **Env:** identity + vault resolution only (no network).
- **Returns:** `AuthState`. **Raises:** never. **Transition:** none.
- **CLI:** `tn auth whoami` → one-line `did -> account @ vault`.

### `login`
- **Py:** `def login(*, vault: str | None = None, code: str | None = None, account_passphrase: str | None = None, interactive: bool | None = None) -> AuthState`
- **TS:** `login(opts?: { vault?: string; code?: string; accountPassphrase?: string; interactive?: boolean }): Promise<AuthState>`
- **Env:** `TN_VAULT_URL`, `TN_VAULT_SESSION_TOKEN` (G2), `TN_ACCOUNT_PASSPHRASE`, `TN_IDENTITY_DIR`. API-key cold-start stays in init/runtime (G1); `TN_DEV_AUTH_BYPASS` belongs to the CLI's dev browser path.
- **Credential separation (G1):** the account-level inputs are `TN_VAULT_SESSION_TOKEN`, `code` (connect code), and `account_passphrase` (arg or env). The passphrase caches the backup key when an account is established. API-key cold-start remains in init/runtime; browser sign-in remains in the CLI.
- **Steps:** load-or-mint identity → resolve vault → establish/confirm enrollment by the highest-precedence credential available → if an account results and a passphrase is available, cache the AWK → return state.
- **Interactivity:** `interactive` defaults to "is this a TTY". Non-interactive + no usable credential → **raise** `AuthError("no credential and no browser")`. Never opens a browser or blocks in non-interactive mode.
- **Returns:** `AuthState` (ideally `backed_up`). **Raises:** `AuthError` only for headless-without-credential or a rejected `code`. Vault-unreachable is contained (returns a state whose `message` says so).
- **Transition:** → `backed_up` (or `linked_no_key` if no passphrase). **CLI:** `tn auth login`.

### `connect`
- **Py:** `def connect(code: str, *, account_passphrase: str | None = None, vault: str | None = None) -> AuthState`
- **TS:** `connect(code: string, opts?: { accountPassphrase?: string; vault?: string }): Promise<AuthState>`
- **Env:** `TN_VAULT_URL`, `TN_ACCOUNT_PASSPHRASE`.
- **Steps:** load identity → resolve vault → `redeem_connect_code` (Py) / `AccountNamespace.connect` (TS) → persist `linked_account_id` only after the vault returns `account_id` (never a one-sided link) → if passphrase available, cache AWK → return state.
- **Returns:** `AuthState`. **Raises:** `AuthError` on bad/expired/consumed code. **Transition:** → `enrolled` (+`backed_up` if passphrase). **CLI:** `tn auth connect <code>` (and the legacy `tn account connect`, which calls this same function).

### `use`
- **Py:** `def use(vault: str) -> AuthState`
- **TS:** `use(vault: string): Promise<AuthState>`
- **Env:** `TN_IDENTITY_DIR`.
- **Steps:** load-or-mint identity → set `linked_vault = vault` → if the vault changed and an account was linked, clear `linked_account_id` (the account belonged to the old vault — prevents a one-sided link) → save → return state.
- **Returns:** `AuthState`. **Raises:** never (disk error is contained into the message). **Transition:** switch vault, clear stale account. **CLI:** `tn auth use <vault>`.

### `logout`
- **Py:** `def logout() -> AuthState`
- **TS:** `logout(): Promise<AuthState>`
- **Env:** `TN_IDENTITY_DIR`.
- **Steps:** load identity (if none → already-logged-out state) → delete cached AWK for the account → clear `linked_account_id` + `linked_vault` → keep the device keypair → save → return state.
- **Returns:** `AuthState` (`not_logged_in`). **Raises:** never. **Transition:** → `not_logged_in`. **CLI:** `tn auth logout`.

---

## Shared core helpers (where the dedup lives)

One implementation each, called by every verb above AND by `tn init`'s warm
path and the legacy `tn account connect`:

| Helper | Python | TypeScript |
|---|---|---|
| load or mint device identity | `_load_or_mint_identity(path=None)` | `Identity.loadOrMint(path?)` (exists) |
| resolve vault URL | `_resolve_vault(identity, override)` | `resolveVault(identity, override)` |
| is backup key cached | `_backup_key_cached(account_id)` | `loadCachedAwk(accountId) != null` (exists) |
| best-effort enrolled check | `_vault_enrolled(identity, vault, session_token)` | `vaultEnrolled(identity, vault, token)` |
| redeem connect code | `redeem_connect_code(...)` (exists) | `AccountNamespace.connect(...)` (exists) |
| cache backup key (AWK) | `cache_account_awk(...)` (exists) | `cacheAccountAwk(...)` (exists) |
| cold-start from API key | `bootstrap_from_api_key(...)` (exists) | `bootstrapFromApiKey(...)` (exists) |
| compute `AuthState` | `_auth_state(identity, vault, verify)` | `authState(identity, vault, verify)` |

---

## Error model

| Verb | Never raises | Raises `AuthError` when |
|---|---|---|
| `status`, `whoami` | ✅ | — |
| `use`, `logout` | ✅ | — |
| `login` | vault unreachable (contained) | headless + no credential; rejected `code` |
| `connect` | — | bad / expired / consumed code |

`AuthError` is a single typed exception in both impls (`tn.auth.AuthError` /
`AuthError` exported from `@cyaxios/tn-proto`). It is the only exception these
verbs raise, for the explicit action failures listed above.

---

## Parity checklist (acceptance gate)

| Capability | Python symbol | TS symbol | Status |
|---|---|---|---|
| `tn.auth` namespace | `tn.auth` | `tn.auth` | new — both |
| `AuthState` + `verdict` enum | `tn/auth.py` | `src/auth/state.ts` | new — both, golden-tested equal |
| `status` / `whoami` | new | new | both |
| `login` (incl. G1 + G2) | new | new | both |
| `connect` | wraps `redeem_connect_code` | wraps `AccountNamespace.connect` | both |
| `use` / `logout` | new | new | both |
| session-token env passthrough (G2) | add to `for_identity` | add to `forIdentity` opts | both |
| `TN_API_KEY` cold-start in init/runtime (G1) | retain `bootstrap_from_api_key` in init/handler-builder | retain `bootstrapFromApiKey` in init/runtime | both |
| drop `TN_IDENTITY_PASSPHRASE` (G3) | remove from [environment catalog](../../python/tn/cli_show.py) + doc | (TS never had it) | both |
| CLI verbs call the namespace | `cmd_auth_*` thin | `bin/tn-js.mjs` thin | both |
| legacy `tn account connect` → `auth.connect` | delegate | delegate | both |

## Proposed implementation order

1. `AuthState` + `verdict` enum + `message` table — Py and TS, with a cross-impl golden test asserting equal verdict→message mapping.
2. Shared core helpers (table above) — Py and TS.
3. G2: session-token passthrough in both vault clients.
4. G1: retain `bootstrap_from_api_key` / `bootstrapFromApiKey` in init/runtime, where ceremony context is available.
5. The six verbs — Py `tn/auth.py`, TS `src/auth/index.ts`, exposed as `tn.auth`.
6. Thin CLI: `cmd_auth_*` (Py) and `bin/tn-js.mjs` (TS) call the namespace; legacy `account connect` delegates to `auth.connect`.
7. G3: remove `TN_IDENTITY_PASSPHRASE` from the catalog + env doc.
8. Parity test: a table-driven test that runs the same scenario list against both SDKs and asserts identical `verdict`s.
