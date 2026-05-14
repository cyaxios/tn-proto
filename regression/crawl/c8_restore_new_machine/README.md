# C8 — Restore on new machine

**Status: scaffolded, no tests yet. Implemented in the C8 PR.**

## What this silo proves

Two-machine handoff via the vault:

1. Machine A: `tn init` + emit some logs (extends C7's flow).
2. Machine B (simulated as a fresh tempdir): `pip install tn-protocol`
   equivalent + `tn wallet restore`.
3. Machine B receives the keystore from the vault.
4. Machine B can append to the log chain — the next `tn.info(...)`
   produces an envelope whose `prev_hash` references machine A's last
   envelope.

This is the "I lost my laptop, I get back to work in 30 seconds" flow.

## Why it's load-bearing

If restore doesn't work, the auto-backup in C7 is hollow theater.
The whole value prop is: "if your machine dies, your keys are safe
AND recoverable AND your log chain continues."

## Restore-path scope

Per the plan: regression suite covers **only the keeper paths**.
Preference order — try the per-project minted base64 identity if it
works end-to-end; fall back to mnemonic if not. Resolution lives in
the test setup. The five-path matrix (passphrase, mnemonic-alone,
legacy DID-challenge, etc.) is deliberately not regressed — those
paths are deprecation candidates per the plan.

## Code paths exercised

- `python/tn/wallet.py:restore_ceremony` — restore entry point
- `python/tn/wallet_restore.py` — top-level orchestrator
- `python/tn/vault_client.py:download_sealed` — vault-side fetch
- `python/tn/cipher.py` — keystore decryption (sealed-blob unseal)
- `tn_proto_web/src/routes_restore.py` — vault-side manifest endpoint

## Tests to add (in the C8 PR)

- `test_restore_pulls_keystore.py` — machine B's tempdir gets the keystore files
- `test_restore_continues_chain.py` — first envelope on B has `prev_hash` = last on A
- `test_restore_idempotent.py` — restore twice doesn't corrupt state
- `test_restore_missing_project.py` — restoring a non-existent project errors clearly

## How to run only this silo

```bash
make -C regression c8
```

Like C7, this silo needs the test vault helper. The two-machine
simulation uses two distinct tempdirs in one pytest process.

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| `wallet restore` reports "no project found" | `vault_client.py:list_projects` + auth flow |
| Restored keystore corrupts on decrypt | `cipher.py` BEK unwrap + `wallet_restore.py` sealed-blob path |
| `prev_hash` chain breaks after restore | `_dispatch.py:_seed_chain_from_log` (or the Rust equivalent in `runtime.rs`) |
| Restore mints fresh keys instead of pulling | `wallet_restore.py` — verify it's the restore path, not init |
