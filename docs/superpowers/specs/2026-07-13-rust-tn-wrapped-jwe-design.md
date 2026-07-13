# Rust TN-Wrapped JWE Design

**Status:** Approved in conversation

**Date:** 2026-07-13

**Scope:** Native Rust JWE group encryption and the existing secure read pipeline

## Purpose

Make `cipher: jwe` work natively in Rust without reproducing the old
multi-recipient General JSON construction. There are no production JWE records,
so this is a clean wire replacement: no legacy reader, migration, or dual-write
path is required.

## Selected composition

Each group seal uses two already-understood layers:

1. Generate a fresh random 32-byte content key and encrypt the group plaintext
   with Biscuit compact JWE using `alg=dir` and `enc=A256GCM`.
2. Wrap that content key independently to every configured, complete Ed25519
   `did:key` using TN's existing `tn-sealed-box-v1` X25519/HKDF/AES-GCM wrap.

The result is one small TN frame:

```json
{
  "frame": "tn-jwe-v1",
  "body": "<compact dir/A256GCM JWE>",
  "recipient_wraps": ["<tn-sealed-box-v1 objects>"]
}
```

The JSON above is illustrative: each `recipient_wraps` element is the existing
wrap object, not a string.

This keeps the jobs separate. Biscuit encrypts and authenticates the string;
TN decides which device identities can recover the one-time content key.

## Identity and key model

- A recipient is its real, complete Ed25519 `did:key` from group configuration.
- TN converts that public key to X25519 when wrapping, exactly as package
  recipient sealing already does.
- The reader converts its own `local.private` Ed25519 seed to X25519 when
  unwrapping.
- There is no second JWE identity, `.jwe.mykey`, raw X25519 enrollment key, or
  publisher-generated reader secret.
- The publisher stores and exports only recipient public DIDs. It never exports
  its own `local.private` key as reader material.

The clear `recipient_identity` in each existing TN wrap is the key selector.
Possessing the named DID is insufficient: opening the wrap still requires the
matching private device key.

## AAD and frame binding

The compact JWE protected header carries `tn_frame="tn-jwe-v1"` and the exact
TN AAD bytes as base64url in a private `tn_aad` field. Decryption pins
`alg=dir` and `enc=A256GCM`, then requires both authenticated fields to match
the expected frame and the AAD reconstructed by the read pipeline.

Recipient wraps authenticate canonical frame metadata containing `frame` and
`body`. A wrap therefore cannot be transplanted onto another encrypted body.
The outer TN row hash and optional record signature continue to cover the whole
group ciphertext as before.

## Rust boundary

`cipher/jwe.rs` becomes a normal `GroupCipher` implementation. It receives the
configured recipient DIDs and the runtime device identity/seed at construction.
Its four operations are:

- `encrypt`: fresh content key, Biscuit body, then one TN wrap per recipient;
- `decrypt`: select this device's wrap, recover the key, then open the body;
- `encrypt_with_aad`: the same operation with authenticated TN AAD; and
- `decrypt_with_aad`: the inverse with exact AAD comparison.

`Runtime::init` constructs this cipher for `jwe` groups just as it already does
for BTN and HIBE. `Tn::read` and its secure defaults do not change; the existing
cipher-neutral read pipeline calls the new implementation through
`GroupCipher`.

This first slice covers configured runtimes, including publisher-as-reader when
the runtime DID is among the group recipients. Standalone foreign-log discovery
without a TN configuration is a separate small slice because JWE no longer has
a group-specific key file to discover.

## Errors and limits

- Empty recipient lists and incomplete/non-Ed25519 DIDs fail before sealing.
- A frame with the wrong version, missing fields, duplicate/unknown fields,
  malformed compact JWE, or more than 1,024 wraps fails closed.
- No wrap for the local DID returns `NotEntitled`; malformed or
  authentication-failing data returns a cipher/malformed error.
- Plaintext, content keys, device seeds, and decrypted key material never
  appear in errors.
- Content keys and copied device seeds are zeroized when their owners drop.
- Production Rust files remain at most 609 lines. Changed functions target 50
  lines and may never exceed 200 lines.

## Alternatives rejected

1. Reimplement the old General JSON `ECDH-ES+A256KW` format in Rust. Biscuit
   does not provide the required multi-recipient/X25519 surface, and TN has no
   production records requiring that compatibility.
2. Use raw `aes-gcm` for both layers. This would work cryptographically, but it
   discards the requested, inspectable compact-JWE body and duplicates the JOSE
   boundary Biscuit already provides.
3. Keep separate `.jwe.mykey` enrollment. That creates a second identity/key
   binding ceremony even though TN already has authenticated device DIDs and a
   reviewed recipient-wrap construction.

## Completion criteria

The slice is complete when a Rust runtime configured with a JWE group can emit
and securely read its own row, a second configured recipient runtime can open
the same ciphertext with its device key, a non-recipient cannot, and no read
scanner/policy/projection API changes are required.
