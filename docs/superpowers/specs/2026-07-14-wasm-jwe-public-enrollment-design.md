# WASM JWE and Public-Only Enrollment Design

## Outcome

Rust JWE becomes usable through `tn-wasm` for key generation, encryption,
decryption, seal, unseal, and unchanged secure `read`. A publisher can prepare a
reader for JWE using public material only; `<group>.jwe.mykey` is generated and
retained exclusively by the reader and is never exported in a recipient bundle.

## One Binding, Several Inputs

Every safe enrollment route produces the same `VerifiedJweBinding` before the
publisher registers a recipient:

- accepted signed offer or challenge response;
- portable DID-signed public-key card;
- authenticated DID-document `keyAgreement` resolution;
- explicit administrator fingerprint pinning, recorded with its verification
  method and audit evidence.

Raw DID plus X25519 key remains available only through the existing explicitly
unsafe, warned, and audited path. It never becomes a verified binding silently.

## Public-Only Activation

After registration, the publisher emits the existing signed enrollment-response
package. The response contains DID, ceremony/group scope, public-key digest,
epoch, expiry, and publisher signature, but no private key. Absorb fails closed
unless the reader retains the matching offer/card state and its local
`<group>.jwe.mykey` derives the public key named by the response.

BTN/HIBE kit bundling remains compatible. A mixed request returns its BTN/HIBE
kit bundle plus one JWE activation package per JWE group instead of inventing a
new cryptographic wire format.

## WASM Surface

`tn-wasm` enables the platform-neutral Rust JWE implementation and exposes:

- key generation returning raw X25519 public/private bytes;
- RFC 7516 General JSON encrypt/decrypt with optional AAD and multiple
  recipients;
- runtime seal/unseal bindings and configured JWE emit/read through injected
  storage.

The TN wire format and `read()` defaults do not change. JWE failure remains
fail-closed and ciphertext remains RFC 7516 General JSON end to end.

## Delivery

Implementation lands as small commits: WASM crypto/runtime, verified binding
adapters, public-only activation bundling, TypeScript-facing bindings, then
focused cross-language and secret-leak verification.
