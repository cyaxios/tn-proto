# C5 — Local groups + recipients in-process

## What this silo proves

Single-machine end-to-end with a real recipient — the smallest test
that proves the **crypto round-trip works end-to-end**, not just the
API surface:

1. Alice (publisher) creates a ceremony with a `default` group.
2. Alice mints a reader kit for Frank via `tn.admin.add_recipient`.
3. Alice bundles the kit into a `.tnpkg` via `tn.pkg.export`.
4. Frank's process (separate tmpdir, separate ceremony) absorbs the
   `.tnpkg` via `tn.pkg.absorb`. The kit lands in Frank's keystore.
5. Alice writes encrypted entries via `tn.info(...)`.
6. Frank reads Alice's log via `tn.read(log=..., as_recipient=...,
   group="default")` and gets plaintext.
7. Revocation test: Alice revokes Carol mid-stream; Carol's kit
   cannot decrypt entries written AFTER the revoke (pre-revoke
   entries remain readable — revocation is forward-only).

## Why it's load-bearing

C5 is the first silo that exercises:

- BTN group encryption + per-recipient kit minting
- The cross-runtime decrypt path (`tn.read(as_recipient=...)`)
- Multi-recipient enrollment (Frank + Bob, both can read)
- Revocation semantics (Carol's post-revoke decrypt fails closed)

If C5 fails, the protocol's crypto guarantee is broken. The runtimes
above this (vault auto-backup in C7/C8) all assume this round-trip
works.

## Code paths exercised

- `python/tn/admin/__init__.py:add_recipient` — kit minting
- `python/tn/admin/__init__.py:revoke_recipient` — revocation
- `python/tn/pkg.py:export` (kind=kit_bundle) — package the kit
- `python/tn/pkg.py:absorb` — recipient-side kit ingestion
- `python/tn/read.py:read` (with `as_recipient=`) — decrypt path
- `python/tn/reader.py` — keystore-driven decrypt loop
- `crypto/tn-btn/src/lib.rs` — BTN cipher

## Tests in this silo

- `test_recipient_decrypts_publisher_log.py` — Alice mints+bundles a
  kit for Frank; Frank absorbs; Alice writes 3 events; Frank's read
  surfaces all 3 with fields intact.
- `test_multi_recipient_decrypt.py` — Alice mints kits for Frank AND
  Bob (same group); both absorb separately; both decrypt the same
  envelopes.
- `test_revoke_locks_out_recipient.py` — Alice adds Carol, writes
  one entry (Carol can decrypt), revokes Carol, writes another entry
  (Carol's `hidden_groups` includes `default` for the post-revoke
  entry but not the pre-revoke one).

## How to run only this silo

```
make c5
# or
pytest regression/crawl/c5_groups_recipients_inproc -v
```

No vault contact — TN_NO_LINK is set by hermetic_machine. The
"separate machine" simulation uses a second tmpdir + chdir within
one pytest process.

## Failure investigation guide

| symptom | first place to look |
|---|---|
| `add_recipient` raises `KeyError: 'default'` | The default group wasn't auto-created on init; check `_multi.py:_init_named_ceremony` group bootstrap |
| Recipient gets `$no_read_key` style placeholder | `read.py` keystore discovery; the kit didn't land where the reader looks |
| Decrypt returns garbage | `cipher.py:BtnGroupCipher.decrypt` + Rust `btn_decrypt` parity break |
| Pre-revoke decrypt fails after revoke | Revocation should be forward-only; if pre-revoke fails too, the keystore state was clobbered |
| Post-revoke decrypt succeeds | `admin/__init__.py:revoke_recipient` — index_epoch didn't advance or keystore mutation didn't land |
