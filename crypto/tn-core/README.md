# tn-core

The TN protocol runtime, in Rust. This is the shared substrate every
language SDK wraps: Python via PyO3, Node and the browser via WASM. The
user-facing surface is the `tn.*` verbs and the `tn` CLI, which call
into the types here.

## What it does

tn-core owns the protocol hot path and the wire format:

- Canonical JSON encoding (deterministic bytes for hashing and signing).
- The row-hash chain that links each event to its predecessor.
- The HMAC equality index that lets a reader match a field without
  decrypting it.
- Ed25519 signing and verification over the row hash.
- Envelope assembly: public fields plus per-group ciphertext blocks.
- Cipher dispatch (btn is first class; JWE and BGW are pluggable).
- Log file I/O, ceremony config loading, and `.tnpkg` package read/write.

## Key surface

Reach for `Runtime` first. It opens or creates a ceremony, writes
attested events (the `tn.info()` / `tn log` family), reads them back
(`tn.read()` / `tn read`), and runs admin verbs (`tn.admin.*` /
`tn rotate`). Other top-level exports: `Manifest` / `ManifestKind` for
`.tnpkg` packages, `DeviceKey` for the Ed25519 identity, and
`Error` / `Result` for the error taxonomy. The `cipher`, `handlers`, and
`storage` modules are the extension-point traits. Everything else
(canonical bytes, chain, indexing, envelope) is an internal primitive
that `Runtime` composes.

## Feature flags

- `fs` (default): filesystem-backed modules and the `tn-core-cli` binary.
- without `fs`: pure-compute modules only, for `wasm32-unknown-unknown`
  targets that inject their own storage via the `Storage` trait.
- `fs-locking` (default): cross-process advisory file locks; omitted on
  wasm where there is no other writer.

## How it is consumed

Not consumed directly by users. `tn-core-py` and `tn-btn-py` bind it for
Python (the `tn-proto` wheel), `tn-wasm` binds it for Node and the
browser (the TypeScript SDK).
