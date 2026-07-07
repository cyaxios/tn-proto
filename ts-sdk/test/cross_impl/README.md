# Cross-language add-recipient proof

Proves that adding a recipient in one language produces a recipient who can read
the sealed log in the other language, for both jwe and hibe, repeated with fresh
keys.

- **jwe** — publisher runs `add_recipient(recipientDid, publicKey)`; the recipient
  reads the publisher's log with its X25519 private key via the foreign-read path.
- **hibe** — the reader mints its own ceremony first and shares its real DID; the
  authority runs `grant_reader` to that DID, which delegates an identity key and
  packages a `.tnpkg` kit **sealed to the reader's device key**; the reader absorbs
  the kit (unsealing it) and reads. The reader-first ordering is required: the kit
  is a sealed box, so the authority must grant to the reader's actual DID — an
  intercepted kit is useless to anyone else.

Each cipher runs every `{publisher, reader}` language pair (py→py, py→ts, ts→py,
ts→ts) three times. A run passes only if the recipient recovers the exact
plaintext **and** the record signature verifies.

## Run

```bash
TN_PY=/path/to/venv/bin/python bash ts-sdk/test/cross_impl/run_proof.sh both
# or: ... run_proof.sh jwe   |   ... run_proof.sh hibe
```

`TN_PY` must point at a Python interpreter with the `tn` package installed; the
TS side runs from the ts-sdk root through `tsx`.
