# C7 — Default key custody (load-bearing onboarding path)

**Status: scaffolded, no tests yet. Implemented in the C7 PR.**

## What this silo proves

The **funnel-critical onboarding flow**:

1. New developer runs `tn init` on a fresh machine.
2. `tn` mints a device key + ceremony keystore + yaml.
3. The keystore is automatically backed up to the vault (default
   behavior).
4. A claim URL is surfaced (printed or shown in IPython).
5. The claim URL is reachable + claimable.
6. The keystore is recoverable from the vault.

This is **the** "Gradyo-clean" path that turns a curious-developer
install into an active user. Friction or breakage here loses users.

## Why it's load-bearing

This is the free-tier funnel. The whole pitch is "pip install tn-
protocol → run it → keys are automatically safe in the cloud." If
this silo's failing, the pitch is broken.

## Code paths exercised

- `python/tn/__init__.py:_auto_link_after_init` — auto-backup trigger
- `python/tn/handlers/vault_push.py:init_upload` — pending-claims POST
- `python/tn/vault_client.py` — vault HTTP client
- `python/tn/__init__.py:_display_claim_url` — URL surface (IPython + stdout paths)
- `tn_proto_web/src/routes_pending_claims.py` — vault-side handler
- `python/tn/identity.py` — device identity mint

## Tests to add (in the C7 PR)

- `test_init_mints_keys.py` — fresh init produces yaml + keystore on disk
- `test_init_uploads_to_vault.py` — claim URL surfaced + reachable
- `test_idempotent_reinit.py` — re-init with same yaml reuses existing vault_id within TTL
- `test_offline_init_no_abort.py` — vault unreachable → init succeeds with warning
- `test_claim_url_format.py` — URL pattern matches `/claim/<ulid>#k=<b64>`

## How to run only this silo

```bash
make -C regression c7
```

This silo requires a **test vault** — `_shared/` (or this silo's own
fixtures) will spin up a FastAPI subprocess backed by mongomock-motor.
See the C7 PR for the test-vault helper module.

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| Claim URL missing from output | `__init__.py:_display_claim_url` + `_auto_link_after_init` trigger conditions |
| Vault returns 4xx on pending-claim POST | `tn_proto_web/src/routes_pending_claims.py` + Mongo TTL index |
| `sync_state.pending_claim` absent on disk | `handlers/vault_push.py:init_upload` write step |
| Re-init produces fresh vault_id (idempotency broken) | `vault_push.py:reuse_pending_window` flag + sync_state read |
| `link=True` not honored from CLI | `cli.py:cmd_init` flag plumbing + `__init__.py:tn.init` kwarg |
