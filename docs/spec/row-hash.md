# row_hash

The chain-link hash inside each [envelope](./envelope.md). Commits
to every field in the envelope EXCEPT `sequence` (which is metadata,
not content) and `row_hash` / `signature` themselves (chicken-and-egg).

Implementations: `python/tn/chain.py::_compute_row_hash` is the
reference. `crypto/tn-core/src/chain.rs::compute_row_hash` claims
byte-for-byte match. TS delegates to wasm.

## Algorithm

```text
row_hash = "sha256:" + hex(SHA256(
    device_identity || \x00
    timestamp       || \x00
    event_id        || \x00
    event_type      || \x00
    level           || \x00
    prev_hash       || \x00
    sorted_public_fields(public_fields) || \x00
    sorted_groups(groups)
))
```

Where:

- `||` is byte concatenation.
- `\x00` is a single zero byte (record separator).
- All string-typed scalars are UTF-8 byte-encoded.
- `sorted_public_fields(d)` emits each `(name, value)` pair, sorted
  by name, as `name + "=" + str(value) + "\x00"`. The value is
  Python `str(v)` for non-bytes values; raw bytes verbatim if it
  IS bytes (see [discrepancies.md](./discrepancies.md#row-hash-bytes)).
- `sorted_groups(d)` emits each `(group_name, group_payload)` pair,
  sorted by group name, as:
  - `"group:" + group_name + "\x00"`
  - `"ct:" + ciphertext_bytes + "\x00"` (raw ciphertext bytes, not
    base64-encoded — the hash sees pre-encoding bytes)
  - `sorted_field_hashes(field_hashes)` — each `(field, token)`
    pair, sorted by field name, as `field + "=" + token + "\x00"`

Reference: `python/tn/chain.py:80-110`, `crypto/tn-core/src/chain.rs:50-130`.

## Zero hash

The `prev_hash` for the first row in any (publisher, event_type)
chain is the **zero hash**:

```text
"sha256:" + "0" * 64
```

i.e. `"sha256:0000000000000000000000000000000000000000000000000000000000000000"`.

Reference: `python/tn/chain.py:15`, `crypto/tn-core/src/chain.rs:13`.

Implementations expose this as a constant:

- Python: `tn.chain.ZERO_HASH`
- Rust: `tn_core::chain::ZERO_HASH` / wasm export `zeroHash`
- TS: `ZERO_HASH` exported from `@tnproto/sdk`

## Properties

The hash:

- **Commits to content, not metadata.** `sequence` is excluded
  because it can be inferred from the chain. `signature` is excluded
  because it signs the hash. `row_hash` itself is obviously excluded.
- **Is deterministic across implementations.** Same inputs → same
  64-hex output, byte-identical.
- **Is order-stable for fields.** Public fields and groups are sorted
  alphabetically inside the hash input, so the producer's insertion
  order doesn't affect the hash. (Insertion order DOES affect the
  envelope's JSON wire shape, but the hash strips that.)

## Verification

A reader recomputes `row_hash` from the envelope's other fields and
compares to the wire `row_hash`. Mismatch = tampered record.

The TS SDK exposes this as `tn.readRaw()` returning
`{envelope, plaintext, valid: {row_hash: bool, ...}}` for explicit
inspection.

## Source pointers

| Implementation | File:line |
|---|---|
| Python (reference) | `python/tn/chain.py:63` |
| Rust core | `crypto/tn-core/src/chain.rs:50` |
| Wasm export | `crypto/tn-wasm/src/lib.rs:327` |
| TS SDK | `ts-sdk/src/core/chain.ts:36` |
