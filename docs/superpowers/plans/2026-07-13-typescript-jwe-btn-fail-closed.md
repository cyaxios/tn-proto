# TypeScript JWE/BTN Fail-Closed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep TypeScript's existing synchronous `read()` API unchanged while making standalone sealing fail closed for BTN and JWE and directly proving RFC 7516 interoperability with Rust.

**Architecture:** `sealObjectCore` is the shared Node/browser sealing boundary, so cipher errors must propagate there instead of being converted into signed objects with missing private groups. Existing async TypeScript JWE APIs remain unchanged: `seal()`, `unseal()`, `emitAsync()`, and `readAsync()`. A focused Rust integration test exchanges raw RFC 7516 General JSON with `ts-sdk/src/core/jwe.ts` in both directions.

**Tech Stack:** TypeScript, Node 20+, `jose`, Node test runner, Rust 1.85, `tn-core` native JWE.

## Global Constraints

- Synchronous TypeScript `read()` must not change; JWE log reading remains `readAsync()`.
- A requested protected field must never be silently omitted from a standalone sealed object.
- BTN and JWE group-seal failures must both reject `Tn.seal()`.
- JWE wire bytes remain RFC 7516 General JSON with `ECDH-ES+A256KW`, `A256GCM`, and optional standard JWE AAD.
- Do not change enrollment, rotation, package export, or the unrelated dirty worktree files.
- Stage and commit only files named by this plan.

---

### Task 1: Fail Closed When Any Protected Group Cannot Seal

**Files:**
- Modify: `ts-sdk/test/seal_unseal.test.ts`
- Modify: `ts-sdk/src/core/sealed_object.ts`
- Modify: `ts-sdk/src/seal.ts`
- Modify: `ts-sdk/src/browser/seal.ts`

**Interfaces:**
- Consumes: `SealContext.sealGroup(gname, cipher, plaintext, aad)`.
- Produces: `sealObjectCore(...)` rejects with the original cipher error; it never signs an object after dropping a protected group.

- [ ] **Step 1: Add the failing BTN and JWE regression tests**

Add two tests to `test/seal_unseal.test.ts`. Each initializes a real ceremony, removes the relevant publisher material, calls `client.seal(..., { receipt: false })`, and asserts the original BTN or JWE error is propagated. For JWE, remove `<keystore>/default.jwe.recipients`. For BTN, clear the loaded `default` group's `stateBytes` through the same private-runtime cast pattern already used by repository tests.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test --test-name-pattern='seal fails closed' test/seal_unseal.test.ts
```

Expected: both tests fail with `Missing expected rejection` because current code warns, skips the protected group, and returns a signed object.

- [ ] **Step 3: Remove the fail-open boundary**

In `sealObjectCore`, replace the `try/catch/warn/continue` block with a direct awaited call:

```ts
const ct = await ctx.sealGroup(gname, gcfg.cipher, plaintextBytes, aadBytes);
```

Remove the now-unused `warn` member from `SealContext` and from both Node and browser context construction. Do not alter normal log-emission behavior in `NodeRuntime`.

- [ ] **Step 4: Run focused tests and typecheck**

Run:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test --test-name-pattern='seal fails closed|seal returns|unseal round-trips' test/seal_unseal.test.ts
npm run typecheck
```

Expected: exit 0; both fail-closed tests and existing round trips pass.

- [ ] **Step 5: Commit only Task 1 files**

```powershell
git add ts-sdk/test/seal_unseal.test.ts ts-sdk/src/core/sealed_object.ts ts-sdk/src/seal.ts ts-sdk/src/browser/seal.ts
git commit -m "fix(ts): fail closed when sealed groups cannot encrypt"
```

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
