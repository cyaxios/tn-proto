# tn-btn

Broadcast-transaction encryption: encrypt once for N future decryptors,
hand each one an opaque reader kit, and revoke individual readers later
without redistributing anything to the survivors. No server, no PKI, no
pre-shared secret, no identity, no network.

## What it does

The core algorithm is NNL subset-difference (Naor-Naor-Lotspiech 2001)
over a key-derivation tree, with revocation expressed as a
subset-difference cover. A publisher mints reader kits from its tree;
encryption targets the current cover (all leaves minus the revoked set);
a reader holding any covered leaf can decrypt, a revoked reader cannot.

## Key surface

- `PublisherState`: owns the master seed and the issued/revoked
  bookkeeping. `setup`, `mint`, `revoke`, `encrypt`, plus `rotate` /
  `retire` which produce a `RetiredPublisherState` (kept so historical
  ciphertexts stay decryptable) and a `RotationOutcome`.
- `ReaderKit`: a minted reader's decrypt capability.
- `Config`: tree configuration and validation.
- `encrypt_to_cover` / `decrypt_with_keyset` and the `tree` module
  (`cover`, `kdt`, `subset`) for the lower-level cover machinery.
- `Error` / `Result`: the public error taxonomy.

## Capacity

The tree has height 8 and 256 reader leaves. Each serialized reader kit
occupies 1,881 bytes.

## How it is consumed

A dependency of `tn-core` (the cipher backing btn groups) and bound for
each language: `tn-btn-py` for the Python `tn-proto` wheel, `tn-wasm`
for Node and the browser.

## License

MIT OR Apache-2.0
