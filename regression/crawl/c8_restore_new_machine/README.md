# C8 — Restore on new machine

## What this silo proves

Two-machine handoff via the vault:

1. **Machine A** runs `tn.init(link=True)`, which uploads an encrypted
   keystore to the vault and surfaces a claim URL.
2. **Machine B** (a separate tmpdir representing a fresh machine):
   * Authenticates with the vault (dev-auth path — the one automated
     encryption-exercising auth flow per the crawl rule).
   * Fetches the encrypted `.tnpkg` ciphertext.
   * Decrypts it with the BEK pulled from the claim URL fragment.
   * Lays out the keystore (`tn.yaml` + `keys/<basename>`) in its own
     tmpdir.
   * Calls `tn.init(yaml_path=<B>/tn.yaml)` and ends up with the SAME
     ceremony DID as machine A.
3. Machine B can then `tn.info(...)` and the entry verifies cleanly —
   proof that the keystore restored end-to-end (not just the public DID).

This is the "I lost my laptop, I get back to work" flow.

## Why it's load-bearing

If C8 is broken, the auto-backup in C7 is hollow theater. The whole
value prop is: keys are safe AND recoverable.

## Restore path scope

Per the crawl-tier auth-path rule:

* **ONE automated encryption-exercising path** — dev-auth bearer JWT,
  which is the same shape rung-5 of the manual ladder used. Exercises
  AES-GCM decrypt of the body, zip unpack, and `tn.init` from the
  laid-out yaml.
* **Other paths are KEEPERS** (passphrase-PBKDF2, mnemonic-as-backup-
  of-backups, OAuth, WebAuthn-PRF), but they're covered:
  - via Playwright in the walk tier (paths that involve a browser
    dance), or
  - via documented manual scripts in the walk tier (paths that are
    inherently human-driven).

C8 explicitly does NOT regress those other paths — adding them would
duplicate the surface without catching more end-to-end bugs in the
encryption pipeline.

## Code paths exercised

- `python/tn/__init__.py:_auto_link_after_init` — A's upload.
- `python/tn/handlers/vault_push.py:init_upload` — POST encrypt + send.
- `python/tn/export.py:decrypt_body_blob` — B's decrypt (round-trip
  inverse of A's encrypt).
- `python/tn/tnpkg.py:_read_manifest` — outer .tnpkg parser.
- `tn_proto_web/src/routes_pending_claims.py:get_pending_claim` —
  vault-side GET handler.
- `tn_proto_web/src/routes_dev_auth.py:dev_login` — bearer-JWT mint.

## Tests in this silo

- `test_restore_recovers_same_ceremony_did.py` — full pipeline: A
  uploads → B fetches → B decrypts → B re-inits → DID matches.
- `test_restore_can_sign_new_entries.py` — after restore, B can
  `tn.info(...)` and the entry verifies (proves the keystore really
  did decrypt — not just the public DID).

## How to run only this silo

```
make c8
# or
pytest regression/crawl/c8_restore_new_machine/ -v
```

Same requirements as C7: live mongo + `tn_proto_web/` repo as a
sibling. Skipped with a clear message if either is missing.

## Failure investigation guide

| symptom | first place to look |
|---|---|
| `vault_server` skipped | mongo or tn_proto_web not reachable; see C7 README |
| `parse_claim_url` raises | claim URL spec drifted; see C7 silo's URL format test |
| `decrypt_body_blob` raises `InvalidTag` | BEK doesn't match the cipher; check `vault_push.py:init_upload` BEK persistence vs URL fragment encoding |
| B's `tn.init(yaml_path)` produces a different DID | keystore wasn't laid out where the runtime looks; check `restore_keystore_to` in `_shared/vault_test_helpers.py` and the yaml's `keystore:` path |
| B's first `tn.info(...)` verifies under A's DID but fails signature check | the laid-out keys are missing private material; one of the `body/*` files didn't make it through the rewrite |
