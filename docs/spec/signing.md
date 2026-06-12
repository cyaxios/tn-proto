# Signing

Ed25519 signatures over canonical bytes. Two base64 encodings appear in
the wire format; a producer that emits the wrong one causes silent
verification failure at the reader.

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Identity

Every TN publisher has an **Ed25519 keypair**. The public half is
encoded as a `did:key:` DID, which is the publisher's stable identity
for the lifetime of that key.

### did:key format

```text
did:key:z{base58btc(0xed 0x01 || pub_bytes_32)}
```

Where:

- `0xed 0x01` is the [multicodec](https://github.com/multiformats/multicodec)
  varint prefix for an Ed25519 public key.
- `pub_bytes_32` is the raw 32-byte Ed25519 public key.
- `base58btc` is Bitcoin-style base58 (alphabet excludes `0`, `O`,
  `I`, `l`).
- The leading `z` is the multibase identifier for base58btc.

A producer MUST encode publisher identities in exactly this form. A
verifier MUST decode the 32-byte public key from it to check
signatures.

### Other DID methods

- **`did:web:<host>`** is used for vault discovery (see
  [vault-http.md](./vault-http.md)). It MUST be resolved via
  `https://<host>/.well-known/did.json`, selecting the service entry
  whose `type` is `TnVaultEndpoint`.
- **`did:plc:`, `did:ion:`, and other methods** are not used in TN
  signing contexts. A verifier MUST reject them as signer identities.

### secp256k1 (OPTIONAL)

An implementation MAY accept secp256k1 public keys (multicodec
`0xe7 0x01`) as signer identities for ATProto interoperability.
secp256k1 support is OPTIONAL and is not required for conformance.

An implementation that does not support secp256k1 MUST treat such a
signature as unverified and MUST NOT raise an error merely on
encountering a secp256k1 identity.

## Signature operation

Given a 32-byte Ed25519 seed and a `message` byte string:

```text
signature = Ed25519.sign(seed, message)   # 64 bytes, raw
```

The raw signature is always exactly 64 bytes before encoding.

## Base64 encodings

The wire format uses **different** base64 dialects in different fields.
A producer MUST emit the dialect specified for each field:

| Field | Encoding |
|---|---|
| Envelope `signature` | URL-safe, no padding |
| Manifest `manifest_signature_b64` | Standard, with padding |
| Recipient-wrap fields (e.g. `ephemeral_x25519_pub_b64`) | Standard, with padding |
| Public keys inside DIDs | base58btc (a different alphabet) |

A verifier MAY accept either the standard or URL-safe base64 alphabet
when decoding a field, since both decode to identical bytes; doing so
does not weaken verification, because the signature check still runs on
the decoded bytes. A verifier MUST NOT, on a verification failure,
re-decode under a different assumption to force the check to pass.

## What gets signed

There are two distinct signing surfaces.

### Envelope signatures

The publisher signs the envelope's `row_hash` field as an ASCII string:

```text
message   = ascii(row_hash)                  # e.g. b"sha256:abc123..."
signature = Ed25519.sign(seed, message)
envelope.signature = url_safe_b64_no_pad(signature)
```

See [envelope.md](./envelope.md#signing).

### Manifest signatures

The publisher signs the [canonical bytes](./canonical-bytes.md) of the
manifest **with the `manifest_signature_b64` field removed**:

```text
m_unsigned = manifest without the "manifest_signature_b64" key
message    = canonical_bytes(m_unsigned)
signature  = Ed25519.sign(seed, message)
manifest.manifest_signature_b64 = standard_b64_with_pad(signature)
```

See [manifest.md](./manifest.md#signing).

## Verification

Both forms verify symmetrically. A verifier MUST:

1. Decode the signature from its field's base64 dialect.
2. Reconstruct the message: for an envelope, `ascii(row_hash)`; for a
   manifest, the canonical bytes of the manifest with
   `manifest_signature_b64` removed.
3. Resolve the signer's public key from `device_identity` (envelope) or
   `publisher_identity` (manifest); both are `did:key:z…`.
4. Run `Ed25519.verify(pub_key, message, signature)`.

A verification failure MUST be a hard reject. A verifier MUST NOT treat
an artifact whose signature does not verify as authentic.
