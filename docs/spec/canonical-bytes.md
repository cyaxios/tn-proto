# Canonical bytes

The serialization rule that turns a JSON-shaped value into a byte
sequence everything else in the protocol hashes, signs, and compares.

Implementations: `python/tn/canonical.py::_canonical_bytes` is the
reference. `crypto/tn-core/src/canonical.rs::canonical_bytes` claims
byte-for-byte match. The TS SDK delegates to wasm via
`ts-sdk/src/core/canonical.ts`.

Golden vectors at
`crypto/tn-core/tests/fixtures/canonical_vectors.json`.

## Algorithm

For any JSON-shaped value `v`:

1. **Objects** — emit `{`, then key-value pairs in **sorted-key
   order** (lexicographic on the UTF-8 byte representation of the
   key), separated by `,`. Each pair is the canonical-bytes of the
   key (a JSON string) + `:` + the canonical-bytes of the value. End
   with `}`. Sort is **recursive** — every nested object also has
   sorted keys.
2. **Arrays** — emit `[`, then elements in input order separated by
   `,`, then `]`. Arrays MUST NOT be sorted; order is semantic.
3. **Strings** — emit a JSON string. Non-ASCII characters are
   preserved verbatim (no `\uXXXX` escaping for BMP code points).
   Mandatory escapes are `\"`, `\\`, `\n`, `\r`, `\t`, and `\u00XX`
   for control characters below 0x20.
4. **Numbers** — integers emit without leading zeros, no `+` sign,
   no trailing `.0`. Floats use shortest-round-trip decimal
   representation. `NaN`, `+Infinity`, `-Infinity` MUST be rejected
   at encode time — there is no canonical encoding for them.
5. **Booleans** — emit `true` / `false`.
6. **Null** — emit `null`.
7. **No whitespace anywhere.** Between keys, between elements,
   around `:`, around brackets — none. The output is one
   contiguous byte string.
8. **Encoding** — UTF-8. The output is `bytes`, not a `str`.

## Sentinel wrappers

Two TN-specific extensions to plain JSON:

- **Raw bytes** — a `bytes` value MUST be wrapped as
  `{"$b64": "<standard-base64>"}` before canonicalization (standard
  base64 with `=` padding). The receiver recognises the sentinel and
  decodes back to bytes. Reference: `canonical.py:48` / `canonical.rs:93`.
- **Decimal (Python only)** — `decimal.Decimal` MUST emit as a JSON
  string (e.g. `"1.500"` for `Decimal("1.500")`), preserving trailing
  zeros. Rust + TS do not yet support this; consumers SHOULD avoid
  Decimal in cross-language payloads. See
  [`discrepancies.md#decimal`](./discrepancies.md#decimal).

## Forbidden inputs

The canonicalizer MUST reject:

- `NaN`, `+Infinity`, `-Infinity` (Python: `canonical.py:34`; TS:
  `canonical.ts:9` `assertFinite`; Rust: `canonical.rs:32`).
- Object keys that are not strings (Python: `TypeError`).
- Cyclic references.

## Implementation tests

Every implementation MUST pass the vectors at
`crypto/tn-core/tests/fixtures/canonical_vectors.json`. To verify a
new implementation:

```bash
cargo test -p tn-core canonical_golden        # Rust + Python via FFI
python -m pytest python/tests/test_canonical_golden.py
node ts-sdk/scripts/_canonical_golden.mjs     # (TODO — does not exist yet)
```

The TS golden runner is missing. If you're porting to a new language,
extending `canonical_vectors.json` and adding a runner is the price
of entry.

## Why this matters

Every higher-level operation in the protocol depends on this:

- [Row hashes](./row-hash.md) hash canonical bytes.
- [Manifest signatures](./manifest.md#signing) sign canonical bytes.
- [Recipient-wrap AAD](./recipient-wraps.md#aad) is canonical bytes.
- [Envelope signatures](./envelope.md#signature) sign the row_hash
  (which is over canonical bytes).

A one-byte deviation here invalidates every signature downstream.
That's why golden vectors exist.

## Source pointers

| Implementation | File:line |
|---|---|
| Python (reference) | `python/tn/canonical.py:60` |
| Rust core | `crypto/tn-core/src/canonical.rs:19` |
| TS SDK | `ts-sdk/src/core/canonical.ts:24` |
| Golden vectors | `crypto/tn-core/tests/fixtures/canonical_vectors.json` |
| Cross-check | `crypto/tn-wasm/test/py_cross_check.py` |
