# WASM JWE and Public Enrollment Implementation Plan

## 1. WASM JWE

- Add failing `tn-wasm` tests for keygen, multi-recipient RFC 7516 JSON,
  required AAD, wrong-key failure, and runtime JWE seal/unseal/read.
- Remove the native-target gate from platform-neutral JWE crypto, enable the
  feature in `tn-wasm`, and add narrow JS bindings.
- Keep `read()` defaults and TN envelope layout unchanged.

## 2. Public-Only Recipient Preparation

- Add failing Rust SDK tests for JWE-only and mixed BTN/JWE preparation.
- Partition kit groups from JWE groups. Existing `bundle_for_recipient` remains
  source compatible; a typed `prepare_recipient` result returns the kit bundle
  and per-group JWE activation packages.
- Register only authenticated public bindings, reuse the signed enrollment
  response, and assert no package contains `.jwe.mykey`.

## 3. Binding Inputs

- Treat the existing unchallenged DID-signed proof as the portable key card and
  the challenge-bound proof as challenge/response.
- Add strict X25519 extraction from an authenticated DID document's
  `keyAgreement` relationship (`publicKeyJwk` or `publicKeyMultibase`). The
  caller-provided resolver is the DID-method authentication boundary and its
  evidence digest is retained.
- Add explicit fingerprint pinning with verification method/evidence and an
  audit event. Keep raw DID-plus-key behind `unsafe_unverified=true`.
- Normalize every safe source into one scoped verified-binding record.

## 4. TypeScript/WASM Surface

- Mirror the Rust primitive and runtime methods without a JS crypto fallback.
- Mirror recipient preparation and binding-source types; preserve current BTN
  behavior and fail closed on missing JWE proof/public material.

## 5. Verification and Commits

- Run focused Rust core/SDK/WASM and TypeScript tests, standard-JWE interop,
  mixed BTN/JWE runtime checks, and an archive scan proving no JWE private key
  is exported.
- Review each slice, then commit docs, WASM, enrollment, and TypeScript changes
  separately.
