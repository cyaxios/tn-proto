# tn-py

The umbrella PyO3 crate that produces the single `tn-proto` Python wheel.
Package name `tn-proto-native`, lib name `_native`, crate type `cdylib`.

## What it does

Historically the Python package depended on two separately published
Rust wheels: `tn-core` exposing `tn_core._core`, and `tn-btn` exposing
`tn_btn._core`. They always shipped on the same version, so this crate
folds both into one extension. It links the two binding `rlib`s
(`tn-core-py` and `tn-btn-py`), calls each one's `populate()`, and builds
a single `tn._native` extension via maturin with these submodules:

- `tn._native.core`: the former `tn_core._core` (the tn-core runtime).
- `tn._native.btn`: the former `tn_btn._core` (the tn-btn cipher).
- `tn._native.core.admin`: the nested admin submodule.

It also registers each submodule in `sys.modules` so explicit imports
like `from tn._native.core import Runtime` resolve (PyO3 wires attribute
access but not the dotted import path on its own).

## Why it exists

One `pip install tn-proto` now carries both Rust runtimes in a single
wheel with one `PyInit` symbol. There is no longer a `tn-core` or
`tn-btn` package on PyPI; those binding crates are internal `rlib`s that
exist only to feed this umbrella.

## How it is built

maturin compiles this `cdylib` into `tn/_native`. See the repo's Python
packaging config for the maturin invocation. This crate has no
user-facing API of its own: it is pure wiring.
