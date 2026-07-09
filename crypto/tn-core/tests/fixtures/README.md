# tn-core golden fixtures

Each JSON file in this directory is the oracle output of the Python TN
pipeline for a set of deterministic inputs. Rust implementations of the
corresponding primitive must reproduce the expected output byte-for-byte.

## Files

| File | What it tests |
|------|--------------|
| `canonical_vectors.json` | `canonical_bytes()` — RFC 8785-style deterministic JSON encoding |
| `row_hash_vectors.json` | `compute_row_hash()` — SHA-256 over the full envelope commitment, incl. container public values hashed as Python `str(value)` |
| `index_token_vectors.json` | `derive_group_index_key()` + `index_token()` — HKDF + HMAC-SHA256 |
| `signing_vectors.json` | Ed25519 signing + `did:key` derivation via DeviceKey |
| `envelope_vectors.json` | Full two-entry chained envelope using the identity cipher |
| `btn_vectors.json` | btn broadcast-encryption round-trip (encrypt + mint + decrypt) |
| `sealed_object_vectors.json` | `tn.seal` / `tn.unseal` wire parity — Python-sealed standalone envelopes that Rust must verify and open (VERIFY vectors: wire line + key material + expected plaintext, plus tampered variants with expected failed checks) |

## Regenerating

The original `generate_rust_fixtures.py` that produced the first six
files is gone; those fixtures are stable and stay committed as-is.

`sealed_object_vectors.json` and the container-public cases appended to
`row_hash_vectors.json` come from a dedicated generator. Run from
`tn_proto/python`:

```
python tools/gen_sealed_object_vectors.py
```

The generator self-checks every case (verify + as-recipient open)
before writing. Sealing is randomized (btn/hibe scheme material, AEAD
nonces), so regeneration changes ciphertext bytes; the committed cases
remain valid indefinitely because each is self-consistent. The
row-hash extension is idempotent by case name.

Never hand-edit these files. If an output changes, regenerate and commit
both the script change and the new fixtures in the same commit, with a
commit message that explains why the format changed.
