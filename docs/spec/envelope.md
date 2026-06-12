# Envelope

The wire shape of a single attested event. Each envelope is **one line
of compact JSON**, and a log is newline-delimited JSON (ndjson) — one
envelope per line.

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Structure

An envelope has three regions, in this order:

1. Nine mandatory keys, in fixed order.
2. Public fields, in producer insertion order.
3. Group payloads, in producer insertion order.

### Mandatory keys

These nine keys MUST appear, in exactly this order, at the start of
every envelope:

| Key | Type | Format |
|---|---|---|
| `device_identity` | string | `did:key:z…` Ed25519 (see [signing.md](./signing.md)) |
| `timestamp` | string | ISO-8601 UTC, microsecond precision, `Z` suffix (e.g. `"2026-05-22T14:30:00.123456Z"`) |
| `event_id` | string | UUID v4 |
| `event_type` | string | matches `[a-zA-Z0-9._-]{1,64}` |
| `level` | string | one of `"debug"`, `"info"`, `"warning"`, `"error"`, or `""` |
| `sequence` | integer | monotonic per (publisher, event_type) chain, unsigned 64-bit |
| `prev_hash` | string | `"sha256:<64-hex>"` of the previous row in this chain; the zero hash for the first row (see [row-hash.md](./row-hash.md)) |
| `row_hash` | string | `"sha256:<64-hex>"` (see [row-hash.md](./row-hash.md)) |
| `signature` | string | Ed25519 over `ascii(row_hash)`, URL-safe base64, no padding (see [signing.md](./signing.md)) |

The fixed order is normative. The envelope is serialized with
sorted-key serialization **off**; the producer writes these keys in the
order above, and a verifier relies on it.

### Public fields

Top-level keys not in the mandatory set, declared by the publisher.
Values MUST be JSON scalars — string, number, boolean, or null. Array
and object public-field values are not defined by `wire/1` (see
[row-hash.md](./row-hash.md#render_public_fields)) and MUST NOT be used.

A public-field name that collides with a mandatory key MUST be dropped;
the mandatory value wins.

### Group payloads

For each group the publisher writes to:

```json
{
  "<group_name>": {
    "ciphertext": "<standard-base64>",
    "field_hashes": {
      "<field_name>": "<index-token>"
    }
  }
}
```

- `ciphertext` is the standard base64 of the group's encrypted payload.
  The cipher is determined by the group's declared suite.
- `field_hashes` are the per-field [index tokens](./indexing.md) for
  the group's indexable fields.

## Serialization

An envelope is serialized as compact JSON (no inter-token whitespace)
followed by a newline:

```text
line = compact_json(envelope) + "\n"
```

This is **not** [canonical bytes](./canonical-bytes.md): keys are not
re-sorted, because mandatory-key order and insertion order are part of
the contract. Only the `row_hash` input is canonicalized.

## Chaining

`prev_hash` links each envelope to the previous envelope of the **same
`event_type`** published by the **same `device_identity`**. A verifier
walks `row_hash` → `prev_hash` → `row_hash` to check chain integrity
per event type. The first row of a chain MUST use the zero hash as its
`prev_hash`.

## Signing

After computing `row_hash`, the publisher signs the ASCII bytes of the
hash string and stores the URL-safe-no-padding base64 result in
`signature`:

```text
message       = ascii(row_hash)
signature_raw = Ed25519.sign(seed, message)
envelope.signature = url_safe_b64_no_pad(signature_raw)
```

Because `row_hash` commits to every other content field, the signature
transitively commits to the whole record. See [signing.md](./signing.md).
