# C7 — Default key custody (load-bearing onboarding path)

## What this silo proves

`tn.init(link=True)` on a fresh machine:

1. Mints the ceremony locally as usual (yaml + keystore).
2. Encrypts the keystore under a single-use BEK and POSTs the
   ciphertext to the vault at `/api/v1/pending-claims` — the vault
   never sees the BEK.
3. Persists the claim URL (`<vault>/claim/<ulid>#k=<bek_b64>`) to
   `<yaml_dir>/.tn/sync/claim_url.txt` and the structured pending
   claim record to `<yaml_dir>/.tn/sync/state.json`.
4. The vault accepts the upload, mints a `vault_id`, and the same
   bytes come back on `GET /api/v1/pending-claims/{vault_id}` with
   a bearer token.

This is the free-tier funnel. Friction here loses users. Restore
(machine B) is C8 — this silo only proves the upload side.

## Why it's load-bearing

If `tn.init(link=True)` ever stops uploading, every user who hits a
broken machine loses their keys silently. The silo's failure modes
are tuned to catch each step in the chain so the named assertion
tells you exactly which hop broke (vault unreachable? URL written?
URL format wrong? bytes mismatch on round-trip? sync state stale?).

## Code paths exercised

- `python/tn/_autoinit.py` — discovery chain (no yaml_path).
- `python/tn/_multi.py:_init_named_ceremony` — yaml + keystore mint.
- `python/tn/__init__.py:_auto_link_after_init` — vault upload
  trigger.
- `python/tn/handlers/vault_push.py:init_upload` — pending-claims
  POST + sync_state stamp + claim_url.txt write.
- `tn_proto_web/src/routes_pending_claims.py` — vault-side handler.

## Tests in this silo

- `test_init_link_mints_claim_url.py` — happy path: POST lands, URL
  surfaces, sync_state stamped, vault returns the same bytes back.
- `test_idempotent_reinit.py` — second `tn.init(link=True)` on the
  same ceremony reuses the existing vault_id within TTL.
- `test_claim_url_format.py` — URL parses cleanly into `(vault_id,
  bek)` and BEK is 32 bytes.
- `test_offline_init_no_abort.py` — vault unreachable does NOT
  abort `tn.init()`; ceremony is still usable and a warning is
  surfaced.

## Auth path

C7 uses **dev-auth** (`/api/v1/dev/login`, gated by
`TN_DEV_AUTH_BYPASS=1` on the vault) for the round-trip-fetch
check. Per the crawl rule, this is the ONE automated
encryption-exercising auth path. The other paths (OAuth /
WebAuthn-PRF / passphrase-PBKDF2 / mnemonic-as-backup-of-backups)
are KEEPERS, but they're covered via Playwright (walk tier) or
documented manual scripts — not here.

## How to run only this silo

```
make c7
# or
pytest regression/crawl/c7_key_custody_default/ -v
```

Requirements:
- A reachable mongo at `$VAULT_MONGO_URI` (defaults to
  `mongodb://localhost:27017`).
- The `tn_proto_web` repo as a sibling of `tn_proto/` so the
  subprocess can `python -m src`. The session-scoped
  `vault_server` fixture handles boot/teardown.

If either is missing the silo `pytest.skip`s with a clear message.

## Failure investigation guide

| symptom | first place to look |
|---|---|
| `vault_server` fixture skipped: mongo unreachable | start mongo (`docker run -d -p 27017:27017 mongo:7`) |
| `vault_server` fixture skipped: tn_proto_web/ not found | check that tn_proto/ and tn_proto_web/ are siblings |
| Claim URL absent from sync_state | `python/tn/handlers/vault_push.py:init_upload` write step |
| Vault returned 4xx on `/pending-claims` POST | `tn_proto_web/src/routes_pending_claims.py:create_pending_claim` |
| `pending_claim` row missing from mongo | mongo TTL index dropped it, or the row insert at line 270 of `routes_pending_claims.py` failed silently |
| Round-trip bytes mismatch | encryption parameter changed; check `tn.export:_encrypt_body_in_place` vs `decrypt_body_blob` |
| Re-init produces fresh vault_id (idempotency broken) | `vault_push.py` reuse-within-TTL gate |
