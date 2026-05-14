# C5 — Local groups + recipients in-process

**Status: scaffolded, no tests yet. Implemented in the C5 PR.**

## What this silo proves

Single-machine end-to-end with a real recipient:

1. Alice (publisher) creates a ceremony with a `default` group.
2. Alice mints a reader kit for Frank.
3. Frank's reader kit is held in-process (no out-of-band transport
   needed — both sides run in the same Python process).
4. Alice writes encrypted-to-group log entries via `tn.info(...)`.
5. Frank decrypts and reads them.
6. Alice revokes Carol mid-stream; Carol's would-be kit cannot
   decrypt entries written after revocation.

This is the smallest test that proves the **crypto round-trip works
end-to-end**, not just the API surface.

## Why it's load-bearing

This is the first silo that exercises:
- BTN group encryption + recipient kit minting
- The recipient-side decrypt path (`tn.read(as_recipient=...)`)
- Revocation semantics (Carol's kit becomes useless after revoke)

If C5 is failing, the protocol's crypto guarantee is broken. Everything
above this in the stack is sand.

## Code paths exercised

- `python/tn/admin/__init__.py:add_recipient` — kit minting
- `python/tn/admin/__init__.py:revoke_recipient` — revocation
- `python/tn/reader.py:read_with_keybag` — multi-kit recipient read
- `python/tn/cipher.py:BtnGroupCipher` — encrypt/decrypt round-trip
- `crypto/tn-btn/src/lib.rs` — BTN cipher implementation

## Tests to add (in the C5 PR)

- `test_publisher_logs_decrypt_for_recipient.py` — Alice writes, Frank's kit reads
- `test_multi_recipient_decrypt.py` — Alice writes once, Frank + Bob both decrypt
- `test_revoke_locks_out_recipient.py` — Carol revoked mid-stream, no decrypt after revoke
- `test_recipient_kit_independence.py` — Frank can decrypt without Bob's kit

## How to run only this silo

```bash
make -C regression c5
# or
pytest regression/crawl/c5_groups_recipients_inproc -v
```

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| `add_recipient` raises | `admin/__init__.py:add_recipient` + Rust `admin_add_recipient` binding |
| Recipient gets `$no_read_key` | `reader.py:read_with_keybag` — keystore discovery + cipher dispatch |
| Decrypt returns garbage | `cipher.py:BtnGroupCipher.decrypt` + Rust `btn_decrypt` parity |
| Revoked kit still decrypts pre-revoke entries | This is CORRECT (revocation is forward-only); silo-test must assert correctly |
| Revoked kit decrypts POST-revoke entries | `admin/__init__.py:revoke_recipient` — keystore state not advanced |
