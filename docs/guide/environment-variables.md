# Environment variables

The `TN_*` parameters that control identity, the vault, which ceremony you're
in, and headless/CI behaviour. Every value here has a sensible default — you
only set these to override.

> Tip: `tn show env` prints the variables this install reads right now, with
> their current values and where each one resolves from.

---

## Headless / CI credentials

The single most confused area. There are **three** different credentials, at
three different lifetimes — they are not interchangeable:

| Credential | Env var | Lifetime | What it does |
|---|---|---|---|
| API key | `TN_API_KEY` | durable | **Cold-starts a fresh node.** Carries a device seed (`tn_apikey_<seed>_<key_id>`); derives the DID, mints a session, pulls the sealed keystore bundle, and absorbs it. One env var → a fully provisioned machine. **The CI default.** |
| Connect code | *(CLI arg, not an env var)* | one-shot | Enrolls an **already-existing** device's DID into an account: `tn auth connect tn_connect_<code>`. Works once, then it's spent. |
| Session token | `TN_VAULT_SESSION_TOKEN` *(legacy alias `TN_VAULT_JWT`)* | ephemeral | A pre-authenticated session token that **skips the challenge** on vault calls. Carries no seed, bootstraps nothing. An escape hatch. |

The API key mints the session token (`TN_API_KEY → challenge/verify → session
token`). AWS analogy: `TN_API_KEY` ≈ an access key / service principal,
`TN_VAULT_SESSION_TOKEN` ≈ a session token.

**The account passphrase.** `TN_ACCOUNT_PASSPHRASE` is the *account recovery
passphrase*; it derives the account wrap key (AWK) that encrypts your keystore
**backup** in the vault. It is not an identity password — the device key is
stored plaintext-at-rest today (`device_priv_enc_method: "none"`).

```bash
# Cold-start a fresh machine from one durable credential:
export TN_API_KEY="tn_apikey_…"
tn init my-project

# Already enrolled — cache the backup key so backups run unattended:
export TN_ACCOUNT_PASSPHRASE="correct horse battery staple"
tn auth login
```

See [Authentication & accounts](auth.md) for how these flow through `tn init`,
`tn auth`, and `tn account connect`.

---

## Identity — which device key

| Var | Role | Default |
|---|---|---|
| `TN_IDENTITY_DIR` | Directory holding `identity.json` | `%APPDATA%\tn` (Windows) · `~/.local/share/tn` (POSIX) |
| `XDG_DATA_HOME` | POSIX data root; TN appends `/tn` | `~/.local/share` |
| `TN_IDENTITY_DID` | Pin which DID to use when several identities are on disk | the only identity present |

Precedence for the identity directory: `TN_IDENTITY_DIR` > `XDG_DATA_HOME` >
platform default. Isolating tests/CI is as simple as pointing `TN_IDENTITY_DIR`
at a scratch dir so the real machine identity is never touched.

```bash
export TN_IDENTITY_DIR="$PWD/.tn-identity"   # sandbox this run's identity
```

---

## Vault — where it is, how to reach it

| Var | Role | Default | Secret |
|---|---|---|---|
| `TN_VAULT_URL` | Base URL for the cloud vault (auth, sealed blobs, projects) | `https://vault.tn-proto.org` | no |
| `TN_VAULT_DEFAULT_BASE` | Base for `did:web` identity-vault discovery | `https://vault.tn-proto.org` | no |
| `TN_VAULT_PROJECT_ID` | Pin the linked vault project id | from yaml `linked_project_id` | no |
| `TN_VAULT_SESSION_TOKEN` | Pre-auth session token (legacy alias: `TN_VAULT_JWT`) | challenge/verify on demand | **yes** |
| `TN_VAULT_TIMEOUT` | HTTP timeout (seconds) for the vault client | `30.0` | no |
| `TN_API_KEY` | Cold-start bootstrap bearer (see above) | unset | **yes** |
| `TN_VAULT_API_KEY` | Warm-attach signal in the TS SDK (alias of `TN_API_KEY` for the link path) | unset | **yes** |
| `TN_ACCOUNT_PASSPHRASE` | Account recovery passphrase → backup key (AWK) | unset (`--account-passphrase` or prompt) | **yes** |

Vault URL precedence: an explicit `--vault`/`--link` arg > the device's
remembered `linked_vault` > `TN_VAULT_URL` > the hosted default.

---

## Ceremony / config — which project

| Var | Role | Default |
|---|---|---|
| `TN_YAML` | Explicit path to `tn.yaml` for autoinit / discovery | the discovery chain |
| `TN_HOME` | Root for shared TN state | `~/.tn` |
| `TN_RUN_ID` | Group emits from one run together (set automatically per process) | a fresh id per process |
| `TN_STRICT` | Block ceremony auto-discovery; `init()` requires an explicit yaml (CI safety) | unset (auto-discover) |
| `TN_NO_LINK` | Never contact the vault — offline-only ceremonies, and the env form of `link=false` | unset (link where appropriate) |

Discovery chain when `TN_YAML` is unset: `./tn.yaml` → `./.tn/default/tn.yaml` →
a sole `./.tn/<project>/tn.yaml`. CLI verbs error rather than minting; library
emit verbs mint a fresh project ceremony.

### Auto-link in serverless

Calling `tn.init()` from code surfaces a vault claim URL **by default** when it
detects a serverless runtime (Vercel, AWS Lambda, Netlify, Cloud Run, Azure
Functions). `TN_NO_LINK=1` turns that off everywhere:

```bash
export TN_NO_LINK=1     # offline-only; tn.init() never reaches the vault
```

---

## Output & behaviour

| Var | Role | Default |
|---|---|---|
| `TN_NO_STDOUT` | Silence the stdout handler (the per-emit JSON echo) | unset (echo on) |
| `TN_STDOUT_FORMAT` | `json` or `pretty` for the stdout handler | `json` |
| `TN_STDOUT_INCLUDE_ADMIN` | Include `tn.*` admin events in the stdout echo | unset |
| `TN_AUTOINIT_QUIET` | Suppress the "minted a fresh ceremony" notice on auto-init | unset |
| `TN_DEBUG` | Emit internal diagnostics to stderr | unset |

Subsystem-specific variables (firehose `TN_FIREHOSE_*`, Kafka `TN_KAFKA_*`, S3,
Delta exporter, …) live with their own features and are out of scope for this
page; `tn show env` lists them under their own categories.

---

## See also

- [Authentication & accounts](auth.md) — the verbs and flows these credentials drive.
- [yaml reference](yaml-reference.md) — the `tn.yaml` fields several of these override.
