# Authentication & accounts

How a TN install proves who it is, links to a vault account, and backs itself
up. Three things are in play, and keeping them straight makes everything else
obvious:

- **Device identity** — a machine-global Ed25519 key in `identity.json`
  (a `did:key:…`). It signs every attested event. Created once per machine; it
  is *not* an account.
- **Vault account** — your account on a vault (`vault.tn-proto.org` by default).
  It holds your encrypted backups and the list of devices ("minted DIDs") that
  belong to you.
- **The link** — enrolling your device's DID into an account, so the vault
  trusts events and backups from this machine.

Everything below is available two ways with an identical surface: the `tn` CLI
(Python package) / `tn-js` CLI (npm package), and the `tn.auth` library
namespace in both SDKs.

---

## The fastest path: `tn init`

`tn init <project>` mints (or reuses) your device identity, creates a ceremony,
and — unless you opt out — backs it up to the vault and prints a **claim URL**.
Open the URL in a browser, sign in, and the project attaches to your account.

```bash
tn init my-project
```

```text
[tn init] New identity written to ~/.local/share/tn/identity.json
[tn init]   DID: did:key:z6Mkv…SYN
[tn init] Ceremony local_23a4abea created at ./.tn/my-project/tn.yaml
[tn init]   project: my-project
[tn init]   cipher: btn
[tn init]   keystore: ./.tn/my-project/keys

[tn init] Backed up to https://vault.tn-proto.org
[tn init]   vault_id:   01J…
[tn init]   expires:    2026-06-17 12:00:00 EDT

[tn init] CLAIM URL - open this in your browser to attach the project to your account:
  https://vault.tn-proto.org/claim/01J…#k=…
```

Offline only? Skip the vault entirely:

```bash
tn init my-project --no-link
```

### `tn init` flags

| Flag | Effect |
|---|---|
| `<project>` | Project name → ceremony at `./.tn/<project>/`. Omit to use the current folder's name. |
| `--no-link` | Don't contact the vault; produce an offline-only ceremony. |
| `--link <url>` | Override the vault base URL (default: `TN_VAULT_URL`, then the hosted vault). |
| `--force` | Move an existing ceremony aside (to `.tn/_overwritten_<name>_<UTC>/`) and re-mint. |
| `--words 12\|15\|18\|21\|24` | BIP-39 entropy for a fresh identity (default 12). |
| `--mnemonic-file <path>` | Derive the identity from a recovery phrase in a file (non-interactive). |
| `--keep-mnemonic` | Persist the recovery phrase into `identity.json` (treat that file as a secret). |
| `--skip-confirm` | Don't pause for Enter after showing the phrase. |
| `--version-name <name>` | Per-instance nickname inside the project (e.g. `laptop-dev`, `ci`, `prod`). |
| `--json` | Print a JSON receipt instead of the human summary. |

> On a fresh identity in an interactive terminal, `tn init` prints your BIP-39
> recovery phrase **once** and waits for Enter. In a non-interactive context
> (CI, containers, `--json`), it skips the prompt and persists the phrase into
> `identity.json` so it's recoverable — re-display it later with
> `tn wallet export-mnemonic`.

### From code (serverless-friendly)

Calling `tn.init()` programmatically surfaces the same claim URL **by default**
when it detects a serverless runtime (Vercel, AWS Lambda, Netlify, Cloud Run,
Azure Functions). The URL is printed to logs and returned on the instance:

```ts
import { init } from "tn-proto";

const tn = await init();              // or init("my-project")
if (tn.claimUrl) {
  // surface it to the user — e.g. in a Vercel route response
  return Response.json({ claim: tn.claimUrl });
}
```

```python
import tn

tn.init("my-project")                 # auto-links inside notebooks/serverless
```

Control it explicitly with `link`: `init(undefined, { link: true })` always
links; `{ link: false }` never does. `TN_NO_LINK=1` is a hard opt-out in every
mode.

---

## `tn auth` — the account verbs

A thin printer over the `tn.auth` library namespace. Every verb reports an
**auth state** (see [States](#the-four-states) below); only `login` and
`connect` can fail loudly.

### `tn auth status`

Full state, including a live check against the vault.

```bash
tn auth status
```

```text
device:   did:key:z6MkmG68YDjBfPkeb4wzJrUtn5AhVhKjMn39YFP8MMmSjMKC
account:  (none - not logged in to an account)
vault:    https://vault.tn-proto.org
layers:
  linked (local file):  no
  enrolled (vault):     unknown
  backup key (cached):  no
=> Not logged in - run `tn auth login`.
```

| Flag | Effect |
|---|---|
| `--vault <url>` | Check against this vault instead of the default. |

### `tn auth whoami`

One line, local-only (no vault round-trip).

```bash
tn auth whoami
```

```text
not logged in (no identity on this machine)
```

Once linked, it reads: `did:key:…  ->  account 01ACCT… @ https://vault.tn-proto.org`.

### `tn auth use <vault>`

Point this machine at a vault (remembered in `identity.json`). Switching vaults
clears any stale account link so you never end up "one-sided".

```bash
tn auth use https://vault.tn-proto.org
```

```text
vault set to https://vault.tn-proto.org
  run `tn auth login` to connect this device to an account there.
```

### `tn auth login`

Sign in and connect this device — the browser flow, like `az login` / `gh auth
login`. With no flags it opens your browser to the verification page **and**
prints a short code to type as the fallback (OAuth 2.0 Device Authorization
Grant, RFC 8628), then waits while you sign in:

```bash
tn auth login
```

```text
To connect this device, open:
  https://vault.tn-proto.org/device?code=WDJB-MJHT

If your browser didn't open, go to  https://vault.tn-proto.org/device
and enter the code:                 WDJB-MJHT

Waiting for you to sign in…  ✓ Connected as account 01ACCT…
```

The device key stays the principal — nothing is pasted back, no token is stored;
once the browser enrolls your device, the CLI proves itself with the key it
already holds. `TN_NO_BROWSER=1` skips the auto-open (the printed URL still
works).

For unattended/CI use, pass a headless credential instead of the browser:

```bash
# enroll with a one-shot connect code (same as `tn auth connect`)
tn auth login --code tn_connect_xxxxxxxx

# or cache the backup key for an already-enrolled device
tn auth login --account-passphrase "correct horse battery staple"
```

| Flag | Effect |
|---|---|
| *(none)* | Browser device-flow sign-in (the default). |
| `--code <tn_connect_…>` | Headless: redeem a connect code to enroll this device. |
| `--account-passphrase <p>` | Headless: cache the backup key (AWK). Also `TN_ACCOUNT_PASSPHRASE`. |
| `--vault <url>` | Vault to log in against. |

### `tn auth connect <code>`

The canonical home for connect-code redemption (`tn account connect` is the
legacy alias — see below).

```bash
tn auth connect tn_connect_xxxxxxxx
```

```text
Connected to vault account 01ACCT…
device:   did:key:…
account:  01ACCT…
vault:    https://vault.tn-proto.org
layers:
  linked (local file):  yes
  enrolled (vault):     unknown
  backup key (cached):  no
=> Linked, but no backup key cached - backups will not run. Run `tn auth login --account-passphrase`.
```

| Flag | Effect |
|---|---|
| `--account-passphrase <p>` | Cache the backup key after connecting. |
| `--vault <url>` | Vault to connect against. |

### `tn auth logout`

Forget the account + cached key on this machine. Your device key is kept, and
your account and backups in the vault are untouched.

```bash
tn auth logout
```

```text
Logged out on this machine.
  device key kept: did:key:…
  your account and backups in the vault are untouched.
```

---

## `tn account connect` — legacy connect-code alias

Same redemption as `tn auth connect`, but scoped to a ceremony: it persists the
account binding into the ceremony's sync state so later `tn wallet sync` /
`tn absorb` know which account this DID belongs to. The `--yaml` is discovered
when omitted.

```bash
tn account connect tn_connect_xxxxxxxx --passphrase "…" 
```

```text
Connected to vault account 01ACCT…
  cached account credential (body backup runs unattended)
  project_id:   01PROJ…
  project_name: my-project
  did:          did:key:…
```

| Flag | Effect |
|---|---|
| `<code>` | The `tn_connect_…` code (required). |
| `--yaml <path>` | Ceremony to bind. Discovered if omitted. |
| `--vault <url>` | Vault to redeem against. Falls back to the device's linked vault, then the default. |
| `--identity <path>` | Sign as a specific identity (tier-2 of the signing cascade). |
| `--passphrase <p>` | Cache the backup key after connecting. |
| `--json` | Print a JSON receipt. |

---

## The four states

Every auth verb resolves to one of four states, computed from three layers —
`linked` (the local file claims an account), `enrolled` (the vault agrees), and
`key_cached` (the backup key is on this machine):

| State | Meaning | Fix |
|---|---|---|
| `not_logged_in` | No account link on this machine. | `tn auth login` |
| `one_sided_link` | This device claims an account the vault hasn't enrolled. | `tn auth login` to repair |
| `linked_no_key` | Linked, but no backup key cached — **backups won't run**. | `tn auth login --account-passphrase` |
| `backed_up` | Linked, enrolled, key cached. Ready. | — |

---

## From code: the `tn.auth` namespace

Library-first: the CLI is a thin printer over these. Every verb returns an auth
state; only `login` / `connect` throw (`AuthError`).

```python
import tn

st = tn.auth.status()                 # synchronous
print(st.verdict, st.message)
print(st.device_did, st.account_id, st.vault_url)

tn.auth.use("https://vault.tn-proto.org")
tn.auth.connect("tn_connect_xxxx", account_passphrase="…")
tn.auth.logout()
```

```ts
import { tn } from "tn-proto";

const st = await tn.auth.status();    // async in TS
console.log(st.verdict, st.message);
console.log(st.deviceDid, st.accountId, st.vaultUrl);

await tn.auth.use("https://vault.tn-proto.org");
await tn.auth.connect("tn_connect_xxxx", { accountPassphrase: "…" });
await tn.auth.logout();
```

`status({ verify: false })` (or `tn.auth.whoami()`) skips the vault round-trip
for a fast local read.

---

## Headless / CI

For unattended runs there are **three** distinct credentials — see
[Environment variables](environment-variables.md#headless--ci-credentials) for
the full table. The short version:

```bash
# Cold-start a fresh machine from one durable credential (the CI default):
export TN_API_KEY="tn_apikey_…"
tn init my-project --no-link        # keystore is provisioned from the sealed bundle

# Already enrolled — just cache the backup key non-interactively:
export TN_ACCOUNT_PASSPHRASE="…"
tn auth login
```

| Credential | Env var | Lifetime |
|---|---|---|
| API key (cold-start a node) | `TN_API_KEY` | durable |
| Connect code (enroll a device) | *CLI arg* `tn auth connect <code>` | one-shot |
| Session token (skip the challenge) | `TN_VAULT_SESSION_TOKEN` | ephemeral |

---

## See also

- [Environment variables](environment-variables.md) — every parameter these
  verbs read, with precedence and defaults.
- [Getting started](getting-started.md) — the end-to-end first-project walkthrough.
