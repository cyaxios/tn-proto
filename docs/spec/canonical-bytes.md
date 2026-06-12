# Canonical bytes

The serialization rule that turns a JSON-shaped value into the byte
sequence everything else in the protocol hashes, signs, and compares.
A one-byte deviation here invalidates every signature downstream, so
this is the most conformance-critical surface in the spec.

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Algorithm

For any JSON-shaped value `v`, the canonical bytes are produced as
follows.

1. **Objects.** Emit `{`, then key/value pairs in **sorted-key order**,
   separated by `,`, then `}`. Keys MUST be sorted lexicographically on
   the UTF-8 byte representation of the key. Each pair is the canonical
   bytes of the key (a JSON string) + `:` + the canonical bytes of the
   value. The sort MUST be recursive: every nested object also has
   sorted keys.
2. **Arrays.** Emit `[`, then elements in input order separated by `,`,
   then `]`. Arrays MUST NOT be reordered; element order is semantic.
3. **Strings.** Emit a JSON string. Non-ASCII characters MUST be
   preserved verbatim — implementations MUST NOT `\uXXXX`-escape BMP
   code points. The only mandatory escapes are `\"`, `\\`, `\n`, `\r`,
   `\t`, and `\u00XX` for control characters below `0x20`.
4. **Numbers.** Integers MUST emit with no leading zeros, no `+` sign,
   and no trailing `.0`. Floats MUST use the shortest round-trip
   decimal representation. `NaN`, `+Infinity`, and `-Infinity` MUST be
   rejected at encode time — there is no canonical encoding for them
   (see [Forbidden inputs](#forbidden-inputs)).
5. **Booleans.** Emit `true` / `false`.
6. **Null.** Emit `null`.
7. **Whitespace.** The output MUST contain no whitespace anywhere —
   not between keys, between elements, around `:`, or around brackets.
   The result is one contiguous byte string.
8. **Encoding.** The output MUST be UTF-8 `bytes`, not a decoded
   string.

## Sentinel wrappers

Two TN-specific extensions to plain JSON.

- **Raw bytes.** A `bytes` value MUST be wrapped as
  `{"$b64": "<standard-base64>"}` (standard base64, `=` padding) before
  canonicalization. A verifier MUST recognize the sentinel and decode
  it back to bytes.
- **Decimal.** A decimal value, where supported, MUST emit as a JSON
  string preserving trailing zeros (e.g. `"1.500"` for a decimal
  `1.500`). Decimal support is OPTIONAL; producers SHOULD avoid
  decimals in cross-language payloads.

## Forbidden inputs

The canonicalizer MUST reject, at encode time:

- `NaN`, `+Infinity`, `-Infinity`.
- Object keys that are not strings.
- Cyclic references.

Rejection MUST surface as a contained error to the caller; it MUST NOT
silently coerce the value (e.g. `NaN` → `null`) and MUST NOT crash the
host program.

## Test-vector conformance

Every implementation claiming producer or verifier conformance MUST
pass `canonical_vectors.json`. Extending the vector set and adding a
runner is the price of entry for a new language port.

## Why this matters

Every higher-level operation depends on this surface:

- [Row hashes](./row-hash.md) hash canonical bytes.
- [Manifest signatures](./manifest.md#signing) sign canonical bytes.
- [Recipient-wrap AAD](./recipient-wraps.md#aad) is canonical bytes.
- [Envelope signatures](./envelope.md#signature) sign the `row_hash`,
  which is itself computed over canonical bytes.
