# Signing

Ed25519 signatures over canonical bytes. Two base64 encodings live
side by side; getting them mixed up causes silent verification
failure.

## Identity

Every TN publisher has an **Ed25519 keypair**. The public half is
encoded as a `did:key:` DID — the publisher's stable identity for
the lifetime of that key.

### DID format

```text
did:key:z{base58btc(0xed 0x01 || pub_bytes_32)}
```

Where:

- `0xed 0x01` is the [multicodec varint prefix](https://github.com/multiformats/multicodec)
  for Ed25519 public keys.
- `pub_bytes_32` is the raw 32-byte Ed25519 public key.
- `base58btc` is bitcoin-style base58 (no `0`, `O`, `I`, `l`).
- The leading `z` is the multibase identifier for base58btc.

Reference: `python/tn/signing.py:131-133`, `crypto/tn-core/src/signing.rs:14`.

### Other DID methods

- **`did:web:<host>`** — used for vault discovery (see
  [vault-http.md](./vault-http.md)). Resolved via
  `https://<host>/.well-known/did.json` looking for a service entry
  with `type === "TnVaultEndpoint"`.
- **`did:plc:`, `did:ion:`, ...** — explicitly unsupported in TN
  contexts. Implementations MUST reject.

### secp256k1 (ATProto interop)

Python `DeviceKey.verify` accepts secp256k1 DIDs (`0xe7 0x01`
multicodec) for ATProto interop (`signing.py:177-191`). Rust + TS
return `false` without throwing. New implementations MAY skip
secp256k1; conformance does not require it.

See [`discrepancies.md#secp256k1-verify`](./discrepancies.md#secp256k1-verify).

## Signature operation

Given a 32-byte Ed25519 seed `seed` and a `message: bytes`:

```text
signature = Ed25519.sign(seed, message)   # 64 bytes
```

The output is always 64 bytes raw.

## Base64 encoding — two conventions

TN uses **different** base64 dialects for envelope vs manifest
signatures. This is intentional but easy to get wrong.

| Where | Encoding | Example field |
|---|---|---|
| Envelope `signature` | URL-safe, NO padding | `"E2_X...-Q"` |
| Manifest `manifest_signature_b64` | Standard, WITH padding | `"E2/X...+Q=="` |
| Recipient-wrap fields (`ephemeral_x25519_pub_b64` etc) | Standard, WITH padding | `"ABCD...=="` |
| Public-key fields in DIDs | base58btc (different alphabet) | `z6Mk...` |

Producers MUST emit the right dialect per field. Consumers SHOULD
tolerate both standard and URL-safe on the read side (TS
`encoding.ts::b64ToBytes` normalises by replacing `-` → `+`,
`_` → `/`, adding padding); but they MUST emit the correct dialect
when producing.

Reference: `python/tn/signing.py:197`, `python/tn/tnpkg.py:181`.

## What gets signed

The protocol has two distinct signing surfaces:

### Envelope signatures

The publisher signs the envelope's `row_hash` field as an ASCII
string:

```text
message = row_hash.encode("ascii")           # e.g. b"sha256:abc123..."
signature = Ed25519.sign(seed, message)
envelope.signature = url_safe_b64_no_pad(signature)
```

Reference: `python/tn/logger.py:308`, [envelope.md](./envelope.md#signing).

### Manifest signatures

The publisher signs the canonical bytes of the manifest **with the
`manifest_signature_b64` field removed**:

```text
m_unsigned = {k: v for k, v in manifest if k != "manifest_signature_b64"}
message = canonical_bytes(m_unsigned)
signature = Ed25519.sign(seed, message)
manifest.manifest_signature_b64 = standard_b64_with_pad(signature)
```

Reference: `python/tn/tnpkg.py:165-181`,
[manifest.md](./manifest.md#signing).

## Verification

Both forms verify symmetrically:

1. Decode the signature from its dialect.
2. Reconstruct the message (envelope: `row_hash.encode("ascii")`;
   manifest: canonical bytes of the manifest minus signature).
3. Resolve the signer's public key from `device_identity` (envelope)
   or `publisher_identity` (manifest) — both are `did:key:z…`.
4. `Ed25519.verify(pub_key, message, signature)`.

A verification failure is a hard reject. Consumers MUST NOT
attempt to "recover" by trying the other base64 dialect — that
masks producer bugs.

## Source pointers

| Implementation | File:line |
|---|---|
| Python (reference) | `python/tn/signing.py` |
| Rust core | `crypto/tn-core/src/signing.rs` |
| TS SDK | `ts-sdk/src/core/signing.ts` |
