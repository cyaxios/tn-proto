# Recipient wraps

A **recipient wrap** is a sealed copy of a sealed-body BEK,
addressed to one specific recipient by DID. The recipient unseals
the wrap using their Ed25519 seed (converted to X25519 via the
birational map), recovers the BEK, and decrypts the body.

Implementations: `python/tn/recipient_seal.py` is the reference.
`ts-sdk/src/core/recipient_seal.ts` mirrors it. **Rust has no
implementation** — Rust-only consumers cannot process sealed
bundles. See [discrepancies.md](./discrepancies.md#rust-no-body-encryption).

## Wire shape

Each entry in `manifest.state.body_encryption.recipient_wraps[]`:

```json
{
  "frame": "tn-sealed-box-v1",
  "recipient_identity": "did:key:z...",
  "ephemeral_x25519_pub_b64": "<standard-base64, 32 bytes>",
  "wrap_nonce_b64":           "<standard-base64, 12 bytes>",
  "wrapped_bek_b64":          "<standard-base64, BEK ciphertext + 16-byte tag>"
}
```

All base64 fields use **standard base64 with `=` padding** (NOT
URL-safe). See [signing.md](./signing.md#base64-encoding---two-conventions).

For one-recipient bundles, producers SHOULD ALSO write
`state.body_encryption.recipient_wrap` as a singular shadow of the
sole array entry — older consumers without plural support can still
unseal.

## Algorithm

### Seal (producer side)

For each recipient DID (each `did:key:z…` with `\xed\x01` Ed25519
prefix):

1. **Derive recipient's X25519 public key** from their Ed25519 public
   key via libsodium's `crypto_sign_ed25519_pk_to_curve25519` (the
   "birational map"). This is the only way to wrap to a DID
   identified solely by its Ed25519 public key.
2. **Generate ephemeral X25519 keypair**: `eph_priv = random(32)`,
   `eph_pub = X25519.public_key(eph_priv)`.
3. **ECDH**: `shared = X25519.ecdh(eph_priv, recipient_x_pub)`.
4. **HKDF-SHA256** derive the wrap key:
   - `salt = eph_pub || recipient_x_pub`  (64 bytes)
   - `info = b"tn-kit-seal-v1"`
   - `wrap_key = HKDF-SHA256(shared, salt=salt, info=info, len=32)`
5. **Generate wrap nonce**: `nonce = random(12)`.
6. **Encrypt the BEK**:
   - `aad = manifest_aad_for_wrap(manifest)` — see below.
   - `wrapped = AES-256-GCM.encrypt(wrap_key, nonce, bek, aad)`.
7. **Emit the wire entry**:
   - `frame: "tn-sealed-box-v1"`
   - `recipient_identity: did`
   - `ephemeral_x25519_pub_b64: b64(eph_pub)`
   - `wrap_nonce_b64: b64(nonce)`
   - `wrapped_bek_b64: b64(wrapped)`

Reference: `python/tn/recipient_seal.py:180-230`,
`ts-sdk/src/core/recipient_seal.ts::sealBekForRecipient`.

### Unseal (consumer side)

Given a wrap entry, our 32-byte Ed25519 seed, and the AAD:

1. Verify `wrap.frame === "tn-sealed-box-v1"`. If not, reject (foreign
   format).
2. Derive our X25519 private key from the Ed25519 seed via the
   birational map: `our_x_priv = ed25519_sk_to_curve25519(seed)`.
3. Decode `eph_pub = b64decode(wrap.ephemeral_x25519_pub_b64)`.
4. Derive the recipient X25519 public key from
   `wrap.recipient_identity` (NOT from our seed — this defends
   against a malicious wrap naming a different DID).
5. ECDH + HKDF: same derivation as the seal step.
6. `bek = AES-256-GCM.decrypt(wrap_key, nonce, wrapped, aad)`.
7. Verify `len(bek) === 32`.

If decryption fails (wrong key, tampered ciphertext, AAD mismatch),
move to the next wrap. The producer may have addressed multiple
recipients; only one matches us.

Reference: `python/tn/recipient_seal.py::unseal_bek_from_wrap`,
`ts-sdk/src/core/recipient_seal.ts::unsealBekFromWrap`.

## AAD

The AAD (Additional Authenticated Data) binds the wrap to the
manifest it came from. Producer and consumer MUST compute byte-
identical AAD or the AEAD tag won't verify.

```text
aad = canonical_bytes(manifest minus {
  "manifest_signature_b64",
  "state.body_encryption.recipient_wrap",
  "state.body_encryption.recipient_wraps"
})
```

Reasoning for the strips:

- `manifest_signature_b64` — the signature is computed AFTER the
  wraps, so the wraps can't be AAD-bound to the signature
  (chicken-and-egg).
- `recipient_wrap` / `recipient_wraps` — the wraps themselves can't
  AAD-bind themselves. Stripping them makes producer and consumer
  AAD compute identical even when the consumer only has one wrap to
  examine.

Everything else stays in the AAD — including `state.body_encryption.cipher_suite`,
`.nonce_bytes`, `.frame`, `.ciphertext_sha256`. If a man-in-the-middle
swaps any of those, the wrap unseal fails because AAD mismatch.

Reference: `python/tn/recipient_seal.py::manifest_aad_for_wrap`,
`ts-sdk/src/core/recipient_seal.ts::manifestAadForWrap`.

## Constants

- **Frame identifier**: `"tn-sealed-box-v1"`. Future format breaks
  bump the version suffix.
- **HKDF info string**: `b"tn-kit-seal-v1"` (15 bytes including the
  null byte? no — just the UTF-8 bytes of the string, length 15).
- **Wrap nonce length**: 12 bytes (AES-GCM standard).
- **Ephemeral X25519 pub length**: 32 bytes.
- **BEK length**: 32 bytes (AES-256 key).
- **AEAD tag length**: 16 bytes.

## Why this construction

- **Ed25519 + X25519 birational map** — TN identities are
  Ed25519 (matches `did:key:z…`, ATProto compatible). X25519 is
  the cryptographically-sound choice for ECDH. The birational map
  lets us reuse one identity material for both.
- **Ephemeral X25519 per wrap** — forward-secret. Compromise of an
  ephemeral key doesn't decrypt past bundles.
- **HKDF salt includes both pubs** — prevents key reuse if someone
  ever recycles an ephemeral.
- **AES-GCM AAD includes the manifest minus the wrap** — binds the
  wrap to the bundle it's part of. Can't lift a wrap from one
  bundle and graft it into another.

## Source pointers

| Implementation | File:line |
|---|---|
| Python (reference) | `python/tn/recipient_seal.py` |
| TS SDK | `ts-sdk/src/core/recipient_seal.ts` |
| Design doc | `docs/superpowers/specs/2026-05-03-encrypted-kit-bundle-design.md` |
| Rust | — (none) |
