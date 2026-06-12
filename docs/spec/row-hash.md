# row_hash

The chain-link hash inside each [envelope](./envelope.md). It commits
to every field in the envelope **except** `sequence` (metadata, not
content) and `row_hash` / `signature` themselves. The
[signature](./signing.md) signs this hash, so the signature
transitively commits to the whole record.

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Algorithm

```text
row_hash = "sha256:" + hex(SHA256(
    device_identity  || 0x00
    timestamp        || 0x00
    event_id         || 0x00
    event_type       || 0x00
    level            || 0x00
    prev_hash        || 0x00
    render_public_fields(public_fields)
    render_groups(groups)
))
```

Where:

- `||` is byte concatenation and `0x00` is a single zero byte used as a
  record separator.
- `hex(...)` is lower-case hexadecimal; the output is always
  `"sha256:"` followed by exactly 64 hex characters.
- The six leading scalars are UTF-8 byte-encoded, each followed by one
  `0x00` byte, in the exact order shown. This order is normative.

### render_public_fields

Public fields MUST be emitted **sorted by field name** (lexicographic
on the UTF-8 bytes of the name). Each field emits:

```text
name + "=" + render_value(value) + 0x00
```

`render_value` is defined per JSON type:

| Value type | Rendering |
|---|---|
| string | the raw UTF-8 bytes, unquoted |
| boolean | `True` or `False` (capitalized) |
| null | `None` |
| number | its decimal string form |

These four scalar types are the **only** defined public-field value
types in `wire/1`. A producer MUST NOT use an array or object as a
public-field value: its rendering is not defined by this version of the
wire format and is not guaranteed to be identical across
implementations. A producer SHOULD reject composite public-field values
at encode time.

### render_groups

Groups MUST be emitted **sorted by group name**. Each group emits:

```text
"group:" + group_name           + 0x00
"ct:"    + ciphertext_bytes      + 0x00
```

followed by its field hashes, **sorted by field name**, each as:

```text
field_name + "=" + token + 0x00
```

`ciphertext_bytes` are the raw pre-encoding bytes of the group
ciphertext — not the base64 text that appears in the envelope. The
hash sees the bytes before base64 encoding. `token` is the
[index token](./indexing.md) string verbatim.

## Zero hash

The `prev_hash` of the first row in a given (publisher, event_type)
chain MUST be the **zero hash**:

```text
"sha256:" + "0" repeated 64 times
```

## Properties

- **Commits to content, not metadata.** `sequence` is excluded because
  it is recoverable from the chain. `signature` is excluded because it
  signs the hash. `row_hash` excludes itself.
- **Deterministic across implementations.** Identical inputs MUST
  produce the identical 64-hex output, byte for byte.
- **Order-stable.** Public fields, groups, and field hashes are sorted
  inside the hash input, so producer insertion order does not affect
  the hash. (Insertion order does affect the envelope's JSON wire
  shape; the hash strips that.)

## Verification

A verifier MUST recompute `row_hash` from the envelope's other fields
and compare it to the wire `row_hash`. A mismatch MUST be treated as a
tampered record and rejected.
