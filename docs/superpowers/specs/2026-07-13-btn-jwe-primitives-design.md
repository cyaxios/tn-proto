# BTN and JWE Primitive Surfaces

Date: 2026-07-13

## Purpose

Expose the same small, byte-oriented `encrypt` and `decrypt` vocabulary for BTN and JWE in Rust, Python, TypeScript, and C#. This is a standalone cryptographic surface for local applications. Existing TN `seal`, `unseal`, and `read` behavior does not change.

The implementation must reuse the BTN and RFC 7516 JWE engines already in this repository. It must not introduce another ciphertext format or route JWE through Biscuit.

## Public shape

The languages expose cipher-specific sibling modules:

- Rust: `tn_proto::btn` and `tn_proto::jwe`
- Python: `tn.btn` and `tn.jwe`
- TypeScript: exported `btn` and `jwe` modules
- C#: `Btn` and `Jwe`

Portable inputs and outputs are raw bytes: `Vec<u8>`, `bytes`, `Uint8Array`, or `byte[]`. Typed Rust objects remain available as the advanced lower-level API, but they are not the cross-language contract.

There is deliberately no generic cipher registry in this slice. A future HIBE surface can be another sibling module with the same byte-oriented verbs and its own authority lifecycle.

## BTN contract

The minimal Rust flow is:

```rust
let mut producer = tn_proto::btn::setup()?;
let kit = producer.mint()?;
let ciphertext = producer.encrypt(b"hello")?;
let subscriber = tn_proto::btn::subscribe([kit])?;
let plaintext = subscriber.decrypt(&ciphertext)?;
```

The BTN surface has these semantics:

- `setup` creates a stateful producer.
- `mint` consumes one reader leaf and returns a portable reader kit.
- Producer `encrypt` and `decrypt`, plus subscriber `decrypt`, operate on raw bytes.
- Rust provides explicit `encrypt_with_aad` and `decrypt_with_aad`; the other languages accept optional AAD in their idiomatic form.
- Producer state supports `to_bytes` and `from_bytes`.
- Subscriber construction accepts one or more kits.
- Producer decryption uses the producer's master state directly. It must not mint or consume a reader leaf as a side effect.
- Revocation changes entitlement for ciphertext created after revocation. It does not retroactively invalidate old ciphertext.

PR #4's Python `tn.btn` API is the starting point, with producer decryption corrected to obey the no-hidden-mint rule.

## JWE contract

The minimal Rust flow is:

```rust
let keys = tn_proto::jwe::keygen()?;
let ciphertext = tn_proto::jwe::encrypt(b"hello", [&keys.public_key])?;
let reader = tn_proto::jwe::subscribe([keys.private_key])?;
let plaintext = reader.decrypt(&ciphertext)?;
```

The JWE surface has these semantics:

- `keygen` returns a raw 32-byte X25519 public key and a raw 32-byte private key.
- Encryption is stateless and requires at least one recipient public key.
- One encryption may target multiple recipients.
- A subscriber holds one or more private keys and tries them without skipping malformed recipient entries.
- The ciphertext is UTF-8 RFC 7516 General JSON Serialization carried as raw bytes.
- The existing TN JWE profile remains the wire contract: protected `enc` is `A256GCM`; each recipient block has `alg: ECDH-ES+A256KW`, its own X25519 `epk`, and a wrapped copy of the shared content-encryption key.
- Rust provides explicit `encrypt_with_aad` and `decrypt_with_aad`; the other languages accept optional AAD.
- AAD is authenticated exactly as transmitted by the RFC 7516 representation. Missing or changed AAD fails closed.
- TypeScript methods remain asynchronous because the existing `jose` implementation is asynchronous.

Rust uses the native `tn-core` JWE engine. Python, TypeScript, and C# wrap their existing interoperable JWE engines; they are not forced through Rust FFI.

## Identity and authenticity boundary

These primitives accept cryptographic key material, not asserted DIDs. They do not claim sender authenticity.

Authenticated DID-to-key binding remains mandatory in enrollment and administration:

- JWE enrollment must prove or verify that an X25519 key belongs to the asserted reader DID.
- HIBE writers must pin or verify the authority MPK fingerprint before sealing.
- A caller cannot make an unrelated raw key trustworthy merely by attaching a DID string.

Those ceremonies remain separate from this small local encryption API. Nothing in this surface weakens their checks.

## Errors and limits

Each language maps native failures into the same stable categories:

- `NotEntitled`: supplied reader material cannot open the ciphertext.
- `Malformed`: invalid state, key, kit, ciphertext, or unsupported JWE input.
- `AuthenticationFailed`: JWE key unwrap succeeded but ciphertext or AAD authentication failed.
- `LimitExceeded`: BTN tree capacity or configured JWE input limits were exceeded.

Required fail-closed behavior:

- JWE encryption with zero recipients fails.
- JWE subscription with zero private keys fails.
- X25519 keys must be exactly 32 bytes.
- Malformed or unsupported recipient entries fail the operation; they are not silently skipped.
- Wrong keys never return plaintext.
- Errors and logs never expose private keys, BTN producer state, reader kits, or plaintext.

BTN may classify an AAD or ciphertext authentication failure as `NotEntitled` where its cryptographic engine cannot safely distinguish the cause. The public category remains stable within that suite.

## Cross-language compatibility

Rust defines the reference behavior and portable vectors. Compatibility is hub-and-spoke:

- Rust-generated BTN and JWE ciphertext opens in Python, TypeScript, and C#.
- Rust opens BTN and JWE ciphertext generated by Python, TypeScript, and C#.
- BTN vectors cover producer and subscriber decryption, AAD, state restoration, and post-revocation ciphertext.
- JWE vectors cover one recipient, multiple recipients, AAD, wrong keys, malformed input, and unsupported headers.

All four languages include short quickstarts showing key or kit creation, encryption, and decryption.

## Delivery slices

Work lands in small, independently reviewable slices:

1. Rust BTN/JWE public modules, including direct BTN producer decryption and reference vectors.
2. Python wrappers aligned to the Rust byte contract.
3. TypeScript wrappers aligned to the Rust byte contract.
4. C# wrappers and the minimal BTN native boundary required by C#.
5. Rust-centered interoperability verification and quickstarts.

Each slice must leave existing `seal`, `unseal`, and `read` APIs unchanged and usable.

## Out of scope

- HIBE operational or administrative APIs.
- DID resolution, enrollment, rotation, and package delivery changes.
- Record signing, signature verification, writer authorization, chaining, or index tokens.
- A generic plug-in abstraction shared by every cipher.
- A new TN or JWE wire format.
