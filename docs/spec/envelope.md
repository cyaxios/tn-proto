# Envelope

The on-disk shape of a single attested event. Each envelope is **one
line of JSON** — `json.dumps(envelope, separators=(",", ":")) + "\n"`
— and the log file is newline-delimited JSON (ndjson).

Implementations: `python/tn/logger.py::_emit_locked` is the reference.
`crypto/tn-core/src/envelope.rs::build_envelope` mirrors it. TS
delegates to wasm.

## Structure

An envelope has three regions, in this order:

1. **9 mandatory keys** in fixed write order.
2. **Public fields** — declared in yaml `public_fields`. Insertion
   order is preserved.
3. **Group payloads** — encrypted per group. Insertion order
   preserved.

### Mandatory keys (fixed order)

| Key | Type | Format |
|---|---|---|
| `device_identity` | string | `did:key:z…` (Ed25519, see [signing.md](./signing.md)) |
| `timestamp` | string | ISO-8601 UTC, microsecond precision, `Z` suffix. Example: `"2026-05-22T14:30:00.123456Z"` |
| `event_id` | string | UUID v4 |
| `event_type` | string | Matches `[a-zA-Z0-9._-]{1,64}` |
| `level` | string | One of `"debug"`, `"info"`, `"warning"`, `"error"`, or `""` (severity-less `tn.log`) |
| `sequence` | u64 | Monotonic per (publisher, event_type) chain |
| `prev_hash` | string | `"sha256:<64-hex>"` of the previous row in this chain. First row in a chain: `"sha256:" + "0"*64` |
| `row_hash` | string | `"sha256:<64-hex>"` — see [row-hash.md](./row-hash.md) |
| `signature` | string | Ed25519 over `row_hash.encode("ascii")`, URL-safe base64 NO padding |

These nine MUST appear in this exact order on the wire. The
ordering is enforced because the envelope is serialised with
sorted-key-OFF dict iteration but the producer code path inserts
in this order (`logger.py:311-329`, `envelope.rs:69-79`).

### Public fields

Top-level keys NOT in the mandatory set. Comes from yaml
`public_fields` declaration plus runtime context. Values are
JSON-shaped (object, array, string, number, bool, null).

Field-name collisions with mandatory keys are silently dropped —
the mandatory value wins (`logger.py:322-323` `setdefault`;
`envelope.rs:130-132` explicit skip).

### Group payloads

For each group the publisher writes to:

```json
{
  "<group_name>": {
    "ciphertext": "<standard-base64>",
    "field_hashes": {
      "<field_name>": "<hmac-token>"
    }
  }
}
```

- `ciphertext` — standard base64 of the group's encrypted payload.
  Cipher depends on the group's `cipher_suite` (`btn`, `jwe`, etc).
- `field_hashes` — HMAC-SHA256 tokens for each indexable field,
  keyed by `group_index_key` (derived from
  `index_master.key` + ceremony + group + epoch — see Python's
  `_derive_group_index_key`).

The group key is whatever the yaml `groups:` block declared — e.g.
`default`, `tn.agents`, or any custom group name.

## Serialization

```python
# Pseudocode, mirrors logger.py:331.
line = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False) + "\n"
```

This is NOT canonical bytes (no sorted keys; insertion order is the
contract). It's compact JSON for wire efficiency. Only the
`row_hash` input is canonicalized — see [row-hash.md](./row-hash.md).

## Log file layout

The main log is `<keystore_root>/.tn/<stem>/logs/tn.ndjson`, ndjson
encoded. Each line is one envelope. Append-only. Rotated by
`<file>.rotating` handler when configured.

`prev_hash` chains each envelope to the previous one of the same
`event_type` published by the same `device_identity` — so a reader
walks `row_hash` -> `prev_hash` -> `row_hash` to verify chain
integrity per event-type.

## Signing

After computing `row_hash` (see next section), the publisher signs
the ASCII bytes of the hash string:

```python
message = envelope["row_hash"].encode("ascii")    # e.g. b"sha256:abc..."
sig_bytes = device_key.sign(message)              # 64 bytes Ed25519
envelope["signature"] = url_safe_b64_no_pad(sig_bytes)
```

The signature commits to the row hash. Since the row hash commits
to every other field in the envelope, the signature transitively
commits to the whole record.

## Source pointers

| Implementation | File:line |
|---|---|
| Python (reference) | `python/tn/logger.py:311-329` |
| Rust core | `crypto/tn-core/src/envelope.rs:65-152` |
| TS SDK | `ts-sdk/src/core/envelope.ts:11` |
