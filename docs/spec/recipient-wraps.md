# Recipient wraps

A **recipient wrap** is a sealed copy of a sealed-body
[BEK](./body-encryption.md), addressed to one recipient by DID. The
recipient unseals it using their Ed25519 seed — converted to X25519 via
the birational map — recovers the BEK, and decrypts the body.

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Wire shape

Each entry in `manifest.state.body_encryption.recipient_wraps[]`:

```json
{
  "frame": "tn-sealed-box-v1",
  "recipient_identity": "did:key:z...",
  "ephemeral_x25519_pub_b64": "<standard-base64, 32 bytes>",
  "wrap_nonce_b64": "<standard-base64, 12 bytes>",
  "wrapped_bek_b64": "<standard-base64, BEK ciphertext + 16-byte tag>"
}
```

All base64 fields MUST use **standard base64 with `=` padding** (not
URL-safe). See [signing.md](./signing.md#base64-encodings).

For a single-recipient bundle, a producer SHOULD also write
`state.body_encryption.recipient_wrap` as a singular shadow of the sole
array entry, so a consumer without plural support can still unseal.

## Seal (producer)

For each recipient DID (a `did:key:z…` carrying an Ed25519 public key):

1. Derive the recipient's X25519 public key from their Ed25519 public
   key via the birational map
   (`crypto_sign_ed25519_pk_to_curve25519`).
2. Generate an ephemeral X25519 keypair: `eph_priv = random(32)`,
   `eph_pub = X25519.public(eph_priv)`.
3. ECDH: `shared = X25519.ecdh(eph_priv, recipient_x_pub)`.
4. HKDF-SHA256 derive the wrap key:
   - `salt = eph_pub || recipient_x_pub` (64 bytes)
   - `info = "tn-kit-seal-v1"`
   - `wrap_key = HKDF-SHA256(shared, salt, info, length=32)`
5. Generate a 12-byte nonce.
6. `wrapped = AES-256-GCM.encrypt(wrap_key, nonce, bek, aad)`, where
   `aad` is defined in [AAD](#aad).
7. Emit the wire entry with `frame = "tn-sealed-box-v1"`,
   `recipient_identity = did`, and the base64 of `eph_pub`, `nonce`,
   and `wrapped`.

## Unseal (consumer)

Given a wrap entry, the verifier's 32-byte Ed25519 seed, and the AAD:

1. Verify `frame == "tn-sealed-box-v1"`. A foreign frame MUST be
   rejected for this format.
2. Derive the verifier's X25519 private key from the Ed25519 seed via
   the birational map.
3. Decode `eph_pub` from `ephemeral_x25519_pub_b64`.
4. Derive the recipient X25519 public key from `recipient_identity` —
   **not** from the verifier's own seed. This defends against a wrap
   that names a different DID.
5. ECDH and HKDF exactly as in the seal step.
6. `bek = AES-256-GCM.decrypt(wrap_key, nonce, wrapped, aad)`.
7. Verify `len(bek) == 32`.

If decryption fails (wrong key, tampered ciphertext, or AAD mismatch),
the verifier MUST move to the next wrap. A producer may have addressed
several recipients; only one wrap is expected to match.

## AAD

The AAD binds each wrap to the manifest it came from. The producer and
the consumer MUST compute byte-identical AAD or the AEAD tag will not
verify:

```text
aad = canonical_bytes(manifest without {
  "manifest_signature_b64",
  "state.body_encryption.recipient_wrap",
  "state.body_encryption.recipient_wraps"
})
```

The three removed fields are excluded for a reason:

- `manifest_signature_b64` is computed **after** the wraps, so the
  wraps cannot bind to it.
- `recipient_wrap` / `recipient_wraps` cannot bind to themselves, and
  removing them makes the producer's and consumer's AAD identical even
  when the consumer holds only one wrap.

Everything else stays in the AAD — including
`state.body_encryption.cipher_suite`, `.nonce_bytes`, `.frame`, and
`.ciphertext_sha256` — so swapping any of those breaks the unseal.

## Constants

| Constant | Value |
|---|---|
| Frame identifier | `tn-sealed-box-v1` |
| HKDF info string | `tn-kit-seal-v1` (UTF-8 bytes) |
| Wrap nonce length | 12 bytes |
| Ephemeral X25519 public key length | 32 bytes |
| BEK length | 32 bytes |
| AEAD tag length | 16 bytes |

## Why this construction

- **Ed25519 + X25519 birational map.** TN identities are Ed25519 (the
  `did:key:z…` form). X25519 is the sound choice for ECDH; the map
  lets one identity serve both.
- **Ephemeral X25519 per wrap.** Forward-secret: compromise of an
  ephemeral key does not decrypt past bundles.
- **HKDF salt includes both public keys.** Defends against ephemeral
  reuse.
- **AAD is the manifest minus the wraps.** Binds each wrap to its
  bundle, so a wrap cannot be lifted from one bundle into another.
