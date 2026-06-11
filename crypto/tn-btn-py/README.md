# tn-btn-py

PyO3 bindings for the `tn-btn` broadcast-transaction encryption crate
(NNL subset-difference with O(log n) revocation), surfaced to Python.

## Role in tn-proto

This crate is an internal `rlib`, not a standalone package. Its lib name
is `tn_btn_py` (not `tn_btn`, which would collide with the btn crate's
own lib in a single graph), and it exposes one `populate()` function that
registers its classes and functions into a Python module supplied by the
caller.

The caller is the umbrella crate `tn-py` (package `tn-proto-native`),
which links `tn-core-py` and `tn-btn-py` together and builds the single
`tn._native` extension via maturin. The contents of this crate land at
`tn._native.btn` (the former standalone `tn_btn._core` module).

## Key surface

The API is deliberately narrow: bytes in, bytes out. Kits and
ciphertexts cross as Python `bytes`, so callers never touch a Rust
struct.

- `PublisherState`: `mint`, `revoke_kit` / `revoke_by_leaf`, `encrypt`,
  `to_bytes` / `from_bytes`, and `rotate` / `retire`, which yield a
  `RotationOutcome` and a `RetiredPublisherState`.
- Module functions: `decrypt`, `ciphertext_publisher_id`,
  `kit_publisher_id`, `kit_leaf`, `tree_height`, `max_leaves`, and the
  envelope `pipeline` helper.
- Typed exceptions: `NotEntitled`, `BtnRuntimeError`.

## Not published

There is no `pip install tn-btn`. The only published wheel is
`tn-proto`; this crate exists only to feed the umbrella extension.
