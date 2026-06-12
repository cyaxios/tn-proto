# Indexing (equality tokens)

A group's `field_hashes` let a reader match a field for **equality**
without decrypting the group. Each token is a keyed HMAC of the field
value; two records carrying the same value under the same group and
epoch produce the same token, while the value itself stays encrypted.

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Per-group index key

The HMAC key for a group is derived with HKDF-SHA256 from a 32-byte
per-ceremony master secret:

```text
info = "tn-index:v1:" + ceremony_id + ":" + group_name + ":" + decimal(epoch)
group_index_key = HKDF-SHA256(
    ikm    = master,          # 32 bytes
    salt   = <none>,          # HKDF default (treated as 32 zero bytes)
    info   = info,
    length = 32,
)
```

- `master` MUST be exactly 32 bytes.
- `decimal(epoch)` is the unsigned epoch integer rendered as its base-10
  string (no padding).
- The `info` string binds the derived key to the
  `(ceremony_id, group_name, epoch)` tuple, so the same field value
  yields different tokens across groups and across epochs.
- The derived key is exactly 32 bytes.

## Index token

For a field name and its JSON value:

```text
token = "hmac-sha256:v1:" + hex(HMAC-SHA256(
    key = group_index_key,
    msg = field_name || 0x00 || canonical_bytes(value),
))
```

- `field_name` is its raw UTF-8 bytes, followed by a single `0x00`
  separator byte.
- `value` is serialized with the [canonical bytes](./canonical-bytes.md)
  rule — **not** the `str()`-style rendering used by
  [row_hash](./row-hash.md#render_public_fields). Indexing and row_hash
  serialize values differently; an implementation MUST use canonical
  bytes here.
- `hex(...)` is lower-case; the HMAC tag is 32 bytes, so the token is
  the literal prefix `hmac-sha256:v1:` followed by exactly 64 hex
  characters.

## Properties

- **Deterministic.** Identical `(master, ceremony_id, group_name,
  epoch, field_name, value)` MUST produce the identical token, byte for
  byte, across implementations.
- **Equality-only.** Tokens reveal that two values are equal under the
  same key; they reveal nothing else about the value. They do not
  support range or substring matching.
- **Scoped by epoch.** Rotating the epoch changes every token, which is
  how a group's index is retired without re-deriving the master secret.

## Conformance

Tokens are produced by a [producer](./conformance.md#producer) at write
time and travel in the envelope's group `field_hashes`. A producer that
emits indexable fields MUST compute tokens exactly as above. A consumer
that matches on tokens MUST derive the `group_index_key` by the same
HKDF construction; it cannot match without the master secret and the
`(ceremony_id, group_name, epoch)` tuple.
