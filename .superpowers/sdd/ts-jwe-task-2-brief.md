### Task 2: Gate Direct Rust/TypeScript JWE Interoperability

**Files:**
- Modify: `crypto/tn-core/src/cipher/jwe.rs`
- Modify: `rust-sdk/tests/interop_typescript.rs`
- Modify: `ts-sdk/src/core/jwe.ts`
- Modify: `ts-sdk/src/runtime/keystore.ts`

**Interfaces:**
- Consumes: Rust `JweCipher::{encrypt_with_aad,decrypt_with_aad}` and TypeScript `jweSeal`, `jweDecrypt`, `okpPrivateJwk`.
- Produces: strict JOSE-header union parsing for the allowlisted TN profile and one explicit two-way RFC 7516 interoperability test using the same X25519 keypair, plaintext, and AAD.

- [ ] **Step 1: Add the two-way interoperability gate and verify RED**

Add ignored test `rfc7516_jwe_round_trips_between_rust_and_typescript` to `rust-sdk/tests/interop_typescript.rs`. Reuse `typescript_ready()` and `run_node()`. Load a fixed 32-byte X25519 public/private pair from the existing JWE fixture, have Rust seal and TypeScript open, then have TypeScript seal to exactly one recipient and Rust open. Assert plaintext and AAD in both directions and assert the JSON has RFC 7516 General members without legacy `frame`, `body`, or `recipient_wraps` members. Keep each test/helper function at or below 50 lines by separating fixture loading, Rust-to-TypeScript, TypeScript-to-Rust, and wire-shape assertions.

Run:

```powershell
cargo test -p tn-proto --test interop_typescript rfc7516_jwe_round_trips_between_rust_and_typescript -- --ignored --exact --nocapture
```

Expected RED before the parser fix: Rust-to-TypeScript succeeds, then TypeScript-to-Rust fails because `jose` places the sole recipient's `epk` in the protected header while Rust requires `recipients[0].header.epk`.

- [ ] **Step 2: Merge the three JOSE header components without weakening the TN profile**

In `crypto/tn-core/src/cipher/jwe.rs`, model only the allowlisted optional header members `alg`, `enc`, and `epk` in a strict `JoseHeader` with `deny_unknown_fields`. Allow optional top-level shared `unprotected` and optional per-recipient `header`, but reject explicit `null`. Preserve the exact transmitted protected segment for AES-GCM AAD.

Resolve each allowed member across protected, shared-unprotected, and per-recipient headers. Reject a name appearing in more than one component rather than choosing precedence. Require protected `enc == A256GCM`, merged `alg == ECDH-ES+A256KW`, and an X25519 public `epk`. For exactly one recipient, accept `epk` from the protected or per-recipient header. For multiple recipients, require a distinct per-recipient `epk` in every recipient block; do not permit one protected/shared `epk` to stand in for all recipients. Keep Rust emission unchanged: protected `enc`, per-recipient `alg + epk`.

- [ ] **Step 3: Add focused strictness regressions**

Add native Rust unit coverage that rejects duplicate header names across components, missing `alg`/`epk`, `enc` outside or duplicated beyond the protected header, explicit-null optional header objects, unsupported header members, and shared/protected `epk` on a multi-recipient JWE. Retain existing current-layout round trips.

- [ ] **Step 4: Correct stale implementation comments**

Update `ts-sdk/src/core/jwe.ts` to say TypeScript uses `jose` while the native Rust SDK now has its own RFC 7516 implementation; only the wasm path lacks a Rust JOSE surface. Update `ts-sdk/src/runtime/keystore.ts` so it no longer says TypeScript JWE cannot emit/read.

- [ ] **Step 5: Run native JWE tests and the direct gate**

Run:

```powershell
cargo test -p tn-core --lib cipher::jwe
cargo test -p tn-proto --test interop_typescript rfc7516_jwe_round_trips_between_rust_and_typescript -- --ignored --exact --nocapture
```

Expected: exit 0, proving strict native parsing plus both Rust-to-TypeScript and one-recipient TypeScript-to-Rust AAD-bound JWE opening.

- [ ] **Step 6: Run the complete focused TypeScript slice**

Run:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test test/jwe_cipher.test.ts test/jwe_emit_async.test.ts test/jwe_read_async.test.ts test/seal_unseal.test.ts
npm run typecheck
```

Expected: exit 0 with no failures.

- [ ] **Step 7: Commit only Task 2 and plan files**

```powershell
git add crypto/tn-core/src/cipher/jwe.rs rust-sdk/tests/interop_typescript.rs ts-sdk/src/core/jwe.ts ts-sdk/src/runtime/keystore.ts docs/superpowers/plans/2026-07-13-typescript-jwe-btn-fail-closed.md
git commit -m "test(jwe): gate Rust and TypeScript interoperability"
```
