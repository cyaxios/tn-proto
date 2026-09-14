# Environment variables

The `TN_*` variables configure identity storage, vault credentials, ceremony
selection, and output. The tables show each variable's purpose and default.

> Tip: `tn show env` prints the variables this install reads right now, with
> their current values and where each one resolves from.

---

## Headless / CI credentials

TN uses these credentials for bundle installation, account enrollment, and
authenticated vault requests:

| Credential | Env var | Lifetime | What it does |
|---|---|---|---|
| API key | `TN_API_KEY` | durable or single-pickup, as issued | Carries a bootstrap signing seed (`tn_apikey_<seed>_<key_id>`) and bundle identifier. TypeScript's `bootstrapFromApiKey` helper uses it to authenticate and fetch a sealed bundle. |
| Connect code | *(CLI arg, not an env var)* | one-shot | Enrolls an **already-existing** device's DID into an account: `tn auth connect tn_connect_<code>`. Works once, then it's spent. |
| Session token | `TN_VAULT_SESSION_TOKEN` *(legacy alias `TN_VAULT_JWT`)* | ephemeral | A pre-authenticated session token that **skips the challenge** on vault calls. Carries no seed, bootstraps nothing. An escape hatch. |

The bootstrap helper uses the API key's signing seed to complete a
challenge/verify exchange and obtain a session token.

**The account passphrase.** `TN_ACCOUNT_PASSPHRASE` is the *account recovery
passphrase*; it derives the account wrap key (AWK) that encrypts your keystore
**backup** in the vault. It is not an identity password — the device key is
stored plaintext-at-rest today (`device_priv_enc_method: "none"`).

```bash
# Supply a credential to a configured bootstrap integration:
export TN_API_KEY="tn_apikey_…"

# Already enrolled — cache the backup key so backups run unattended:
export TN_ACCOUNT_PASSPHRASE="correct horse battery staple"
tn auth login
```

See [Authentication & accounts](auth.md) for how these flow through `tn init`,
`tn auth`, and `tn account connect`.

The [container guide](deploy-containers.md) shows mounted configuration and
keys, and the explicit TypeScript bootstrap call.

---

## Identity — which device key

| Var | Role | Default |
|---|---|---|
| `TN_IDENTITY_DIR` | Directory holding `identity.json` | `%APPDATA%\tn` (Windows) · `~/.local/share/tn` (POSIX) |
| `XDG_DATA_HOME` | POSIX data root; TN appends `/tn` | `~/.local/share` |

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
| `TN_VAULT_SESSION_TOKEN` | Pre-auth session token (legacy alias: `TN_VAULT_JWT`) | challenge/verify on demand | **yes** |
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
| `TN_NO_LINK` | Disable automatic vault linking during initialization | unset (link where appropriate) |

Discovery chain when `TN_YAML` is unset: `./tn.yaml` → `./.tn/default/tn.yaml` →
a sole `./.tn/<project>/tn.yaml`. CLI verbs error rather than minting; library
emit verbs mint a fresh project ceremony.

### Auto-link in serverless

Calling `tn.init()` from code surfaces a vault claim URL **by default** when it
detects a serverless runtime (Vercel, AWS Lambda, Netlify, Cloud Run, Azure
Functions). `TN_NO_LINK=1` turns that off everywhere:

```bash
export TN_NO_LINK=1     # disable automatic linking during initialization
```

---

## Output & behaviour

| Var | Role | Default |
|---|---|---|
| `TN_NO_STDOUT` | Silence the stdout handler's per-emit console output | unset (echo on) |
| `TN_STDOUT_FORMAT` | `json` or `pretty` for the stdout handler | `pretty` |
| `TN_STDOUT_INCLUDE_ADMIN` | Include `tn.*` admin events in the stdout echo | unset |
| `TN_AUTOINIT_QUIET` | Suppress the "minted a fresh ceremony" notice on auto-init | unset |

Configure Kafka, S3, and Delta connection settings in handler YAML. Their
`env:NAME` values resolve the environment variables you name there; see the
[handler reference](yaml-reference.md#handlers).

---

## See also

- [Authentication & accounts](auth.md) — the verbs and flows these credentials drive.
- [yaml reference](yaml-reference.md) — the `tn.yaml` fields several of these override.
