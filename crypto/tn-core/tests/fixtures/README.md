# tn-core golden fixtures

Each JSON file in this directory is the oracle output of the Python TN
pipeline for a set of deterministic inputs. Rust implementations of the
corresponding primitive must reproduce the expected output byte-for-byte.

## Files

| File | What it tests |
|------|--------------|
| `canonical_vectors.json` | `canonical_bytes()` — RFC 8785-style deterministic JSON encoding |
| `row_hash_vectors.json` | `compute_row_hash()` — SHA-256 over the full envelope commitment |
| `index_token_vectors.json` | `derive_group_index_key()` + `index_token()` — HKDF + HMAC-SHA256 |
| `signing_vectors.json` | Ed25519 signing + `did:key` derivation via DeviceKey |
| `envelope_vectors.json` | Full two-entry chained envelope using the identity cipher |
| `btn_vectors.json` | btn broadcast-encryption round-trip (encrypt + mint + decrypt) |

## Regenerating

Run from the repo root:

```
.venv/Scripts/python.exe tn-protocol/python/tools/generate_rust_fixtures.py
```

Requires the Python venv at `C:\codex\content_platform\.venv` with the `btn`
extension built (`maturin develop` inside `tn-protocol/crypto/btn-py`).

Never hand-edit these files. If an output changes, regenerate and commit
both the script change and the new fixtures in the same commit, with a
commit message that explains why the format changed.
