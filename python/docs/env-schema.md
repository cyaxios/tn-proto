# TN environment-variable schema (Python SDK)

> Environment settings read by the Python SDK.
> Source paths below are relative to the repository's `python/` directory.
>
> `tn show env` reads `_ENV_SCHEMA` in [cli_show.py](../tn/cli_show.py).
> Keep that table and this inventory in sync when adding an environment setting.
> For deployment examples, see the [environment-variable guide](../../docs/guide/environment-variables.md).
>

## Conventions

- All canonical names are **`TN_*`**. Vendor / OS-platform vars (`XDG_*`,
  `APPDATA`) are listed for completeness because TN code reads them as
  fallbacks, but they are **not** TN-owned.
- `read_today = yes` means there is a live `os.environ` / `os.getenv` /
  `os.environ.get` site in `tn/`. The `file:line` reference points at the
  authoritative read.

- `secret = yes` rows render in `tn show env` human form as
  `TN_SECRET_FOO=*** (length: N)`, and only fully expand under
  `--format=env` (the deploy-paste form).
- `precedence` is the documented resolution order. Missing entries default
  to `env > default` (no competing source).

## Identity

| name | purpose | read_today | default | secret | precedence |
|---|---|---|---|---|---|
| `TN_IDENTITY_DIR` | Override the directory holding `identity.json`. | yes — `tn/identity.py:97` | OS-specific data dir (XDG_DATA_HOME/tn or %APPDATA%/tn) | no | env > XDG_DATA_HOME > APPDATA > home fallback |
| `XDG_DATA_HOME` | POSIX user-data root; TN appends `/tn` for identity storage. | yes — `tn/identity.py:100` | `~/.local/share` | no | TN_IDENTITY_DIR > env > home fallback |
| `APPDATA` | Windows roaming profile root; TN appends `\tn` when XDG isn't set. | yes — `tn/identity.py:104` | `~/AppData/Roaming` | no | TN_IDENTITY_DIR > XDG_DATA_HOME > env > home fallback |

## Vault

| name | purpose | read_today | default | secret | precedence |
|---|---|---|---|---|---|
| `TN_VAULT_URL` | Base URL for the TN cloud vault (auth, project CRUD, sealed blobs). | yes — `tn/vault_client.py:49` | `https://vault.tn-proto.org` | no | explicit arg > env > default |
| `TN_VAULT_DEFAULT_BASE` | Base for did:web identity vault discovery (separate from CRUD vault). | yes — `tn/identity.py:410` | `https://vault.tn-proto.org` | no | env > default |
| `TN_VAULT_SESSION_TOKEN` | Pre-authenticated session token for vault calls; `TN_VAULT_JWT` is a legacy alias. | yes — `tn/vault_client.py:for_identity` | challenge/verify on demand | yes | explicit arg > TN_VAULT_SESSION_TOKEN > TN_VAULT_JWT > challenge |
| `TN_API_KEY` | Bootstrap a fresh node with its keystore from a sealed vault bundle. | yes — `tn/bootstrap.py` | unset | yes | env at cold start |
| `TN_ACCOUNT_PASSPHRASE` | Account recovery passphrase used to derive the key that wraps the keystore backup. | yes — account, wallet, and auth commands | unset (flag or prompt) | yes | --account-passphrase > env |

## Ceremony / Config

| name | purpose | read_today | default | secret | precedence |
|---|---|---|---|---|---|
| `TN_YAML` | Explicit path to `tn.yaml` for autoinit / discovery. | yes — `tn/_autoinit.py:180,211` | discovery chain (./tn.yaml then $TN_HOME/tn.yaml) | no | env > ./tn.yaml > $TN_HOME/tn.yaml > mint-fresh |
| `TN_HOME` | Root for shared TN state; default `~/.tn`. Holds `tn.yaml` when minted fresh. | yes — `tn/_autoinit.py:89` | `~/.tn` | no | env > home fallback |
| `TN_STRICT` | Block ceremony auto-discovery; `tn.init()` must take an explicit yaml path. | yes — `tn/_autoinit.py:66` | unset (autodiscover allowed) | no | python override > env > default |
| `TN_RUN_ID` | Run identifier shared between Python and Rust runtimes — stamped onto every envelope. | yes — `tn/__init__.py:209` (write); read by Rust runtime | freshly minted per `tn.init()` | no | parent-process env > minted |
| `TN_AUTOINIT_QUIET` | Silence the loud autoinit banner (mint / fresh-ceremony). | yes — `tn/_autoinit.py:96` | unset (banner on) | no | env > default |

## Runtime / Dispatch

| name | purpose | read_today | default | secret | precedence |
|---|---|---|---|---|---|
| `TN_FORCE_PYTHON` | Disable the Rust extension; pure-Python `emit`/`read` paths. Useful for debugging parity bugs. | yes — `tn/_dispatch.py:43` | unset (Rust if available) | no | env > available-extension |
| `TN_READER_LEGACY` | Revert `tn.read` to legacy flat-tuple shape. | yes — `tn/reader.py:42,47` | unset (new shape) | no | env > default |
| `TN_CLAIM_ON_MISSING_IDENTITY` | Auto-claim a fresh identity when `tn.init()` runs against a yaml whose DID isn't on disk. | yes — `tn/logger.py:430` | unset (raise IdentityError) | no | explicit arg > env > default |
| `TN_WALLET_AUTOSYNC` | After every emit, push the new envelope to the linked vault. | yes — `tn/admin/__init__.py:537` | unset (manual `tn wallet sync`) | no | env > default |

## Logging / Observability

| name | purpose | read_today | default | secret | precedence |
|---|---|---|---|---|---|
| `TN_NO_STDOUT` | Suppress the default-on stdout handler that mirrors every envelope as JSON. | yes — `tn/logger.py:542`, `tn/cli.py:87`, `tn/__main__.py:56` | unset (stdout handler attached) | no | explicit arg > env > default |
| `TN_SURFACE_LOG` | File path: append every public-API ENTER/EXIT to this file (debug instrumentation). | yes — `tn/__init__.py:88` | unset (no surface log) | no | env > default |

## Deployment / Storage

| name | purpose | read_today | default | secret | precedence |
|---|---|---|---|---|---|
| `TN_STATE_DIR` | Override the per-user state dir (sync-failure queue, etc.). | yes — `tn/admin/__init__.py:570` | XDG_STATE_HOME/tn or %APPDATA%/tn or `~/.local/state/tn` | no | env > XDG_STATE_HOME > APPDATA > home fallback |
| `XDG_STATE_HOME` | POSIX user-state root; TN appends `/tn`. | yes — `tn/admin/__init__.py:574` | `~/.local/state` | no | TN_STATE_DIR > env > home fallback |

## Handlers (referenced via `env:NAME` indirection)

Kafka, S3, and Delta handler YAML accepts `env:NAME` values. Each handler
resolves the named environment variable when it is created. Choose the names
in your deployment and reference them from the corresponding handler fields.

## Updating this file

When you add a new env-var read:
1. Add a row here in the appropriate category.
2. Add a matching entry in `_ENV_SCHEMA` in `tn/cli_show.py` so `tn show env`
   surfaces it.
3. Add or extend a test in `tests/test_cli_show_env.py`.
