# tn-core-py

PyO3 bindings for the `tn-core` Rust runtime: emit, read, signing, chain
verification, admin verbs, `.tnpkg` read/write, and config loading,
surfaced to Python.

## Role in tn-proto

This crate is an internal `rlib`, not a standalone package. Its lib name
is `tn_core_py` (not `tn_core`, which would collide with the core crate's
own lib in a single graph), and it exposes one `populate()` function that
registers its classes and functions into a Python module supplied by the
caller.

The caller is the umbrella crate `tn-py` (package `tn-proto-native`),
which links `tn-core-py` and `tn-btn-py` together and builds the single
`tn._native` extension via maturin. The contents of this crate land at
`tn._native.core` (the former standalone `tn_core._core` module).

## Key surface

- `PyRuntime`: the bound `tn_core::Runtime` (init, emit, read,
  secure_read, export/absorb, admin verbs, vault link/unlink).
- `PyAdminStateCache`: incremental admin-state replay.
- Module functions: `tnpkg_read` / `tnpkg_write`, the `manifest_*`
  helpers, `config_load_summary`, and `perf_*` counters.
- Typed exceptions: `TnRuntimeError`, `NotEntitled`, `NotAPublisher`.

A `guard()` wrapper converts any Rust panic escaping the core into a
catchable `TnRuntimeError` so a panic never crosses the FFI boundary as
an uncatchable `BaseException`.

## Not published

There is no `pip install tn-core`. The only published wheel is
`tn-proto`; this crate exists only to feed the umbrella extension.
