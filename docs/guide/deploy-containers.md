# Running TN in containers and CI

On your laptop, `tn init` writes an identity to your home directory and you are done. In a container or a CI job there is no home directory to persist, and you must not bake an identity into the image: anyone who pulls the image would have your keys.

The way TN gets an identity onto a fresh container is the **API key bootstrap**. Set it up once per project and forget about it.

The mental model: `TN_API_KEY` is a single string you paste into your platform's secret store. When your container boots, it trades that string with the vault for its keystore, then runs normally. No keys in the image, no identity files in the repo, no startup script.

---

## 1. Mint an API key

Sign in at <https://vault.tn-proto.org/account>, open the project this deploy will write to, click **API keys -> Generate persistent key**, and copy the result. The key looks like:

```text
tn_apikey_<43-char block>_<22-char block>
```

That single string is everything your container needs. It is reusable across deploys; you do not regenerate it per build.

---

## 2. Hand it to your platform as a secret

Put the key in your platform's secret store. The container reads it from the `TN_API_KEY` environment variable.

| Platform | Where the secret goes |
|---|---|
| Cloudflare Workers / Containers | `wrangler secret put TN_API_KEY`, or the Secrets Store |
| GitHub Actions | Repository or org secret `TN_API_KEY` |
| AWS | Secrets Manager or SSM Parameter, exposed as an env var |
| GCP | Secret Manager, exposed as an env var |
| Azure | Key Vault, exposed as an env var |
| Plain Docker | `-e TN_API_KEY=...` (never commit it) |

---

## 3. Deploy

Your container boots, sees `TN_API_KEY`, fetches its keystore from the vault, and starts serving. The first boot has one extra round trip to the vault; subsequent restarts reuse the local cache and skip it.

That is the entire setup.

---

## Disk wins over env

If a project keystore already exists at `<keystore>/local.private`, TN uses it and ignores `TN_API_KEY` entirely. The bootstrap only runs when there is no local keystore yet. This means:

- On your laptop, after `tn init`, your local keystore takes precedence even if `TN_API_KEY` is set in your shell.
- In a container with persistent storage (a Cloudflare Containers R2-backed volume, a mounted EBS, etc.), the keystore survives across cold starts; only the very first boot does the bootstrap round trip.

To force a re-bootstrap, delete the keystore directory and restart.

---

## Where the identity lives

The on-disk project paths are the same on every OS. The only thing that varies is where the per-user identity file lives:

| OS | Per-user identity file |
|---|---|
| macOS / Linux | `~/.local/share/tn/identity.json` |
| Windows | `%APPDATA%\tn\identity.json` |

Resolution precedence is `TN_IDENTITY_DIR` > `XDG_DATA_HOME` > `APPDATA` > home. Set `TN_IDENTITY_DIR` to put the identity file somewhere non-default. The per-project keystore is always under `.tn/<ceremony>/keys/` relative to wherever your project lives.

---

## Rotating the key

Generate a new key in the vault UI, update the secret in your platform, redeploy. Running containers keep working until they restart; new ones come up with the new key.

---

## Opting out of the vault entirely

The bootstrap is only relevant if you want the vault. To run fully offline:

```bash
tn init myproject --no-link          # never talks to a vault
```

```bash
export TN_NO_LINK=1                   # env-level hard kill switch for auto-link
```

Or point at your own vault with `--link <url>` or the `TN_VAULT_URL` environment variable. See the [package README](https://github.com/cyaxios/tn-proto/blob/main/python/README.md#vault-backup-and-recovery-optional).
