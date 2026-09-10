# TypeScript JWE Task 2 Report

## Status

`COMPLETE`

Task 2 is implemented and committed as `3c371ff92c969c3be4795e2cc395c36043e957af` (`test(jwe): gate Rust and TypeScript interoperability`). The commit contains exactly the five paths named by the updated brief.

## Original RED evidence

The original direct gate was run before the parser change:

```powershell
cargo test -p tn-proto --test interop_typescript rfc7516_jwe_round_trips_between_rust_and_typescript -- --ignored --exact --nocapture
```

Result: exit 1; 0 passed, 1 failed, 12 filtered out.

```text
Error: Core(Malformed { kind: "JWE General JSON", reason: "ciphertext is not valid profile JSON: missing field `epk` at line 1 column 209" })
```

Rust-to-TypeScript opening and its plaintext/AAD assertions completed first. The failure occurred when Rust parsed the natural one-recipient TypeScript JWE.

After focused native tests were added and before production code changed, the native RED run produced 12 passes and the three expected failures:

- `single_recipient_accepts_protected_epk`
- `parser_preserves_the_transmitted_protected_segment`
- `shared_unprotected_alg_is_accepted`

## Root cause

`jose@6.2.3` uses its one-recipient encryption path to place the generated ECDH `epk` in the protected header. The Rust wire structs coupled input parsing to Rust's emission layout and required every recipient header to deserialize as `{ alg, epk }`. Rust therefore rejected a valid one-recipient General JSON JWE before key unwrap or content authentication.

The compatibility boundary was Rust JOSE-header parsing, not TypeScript crypto. TypeScript behavior was left unchanged.

## Implementation

- Replaced fixed protected/recipient input headers with one strict `JoseHeader` that allowlists only optional `alg`, `enc`, and `epk` and uses `deny_unknown_fields`.
- Added optional shared `unprotected` and optional recipient `header` objects. A presence-aware deserializer distinguishes omission from explicit `null` and rejects null objects or members.
- Parses the protected header while retaining the exact transmitted base64url segment for AES-GCM AAD.
- Validates a disjoint protected/shared/recipient header union for every recipient and rejects duplicate member names.
- Requires protected `enc == A256GCM` and merged `alg == ECDH-ES+A256KW`.
- Accepts a valid X25519 public `epk` from protected or recipient scope for one recipient, rejects shared `epk`, and requires a local per-recipient `epk` for every multi-recipient block.
- Kept Rust emission unchanged: protected `enc`; per-recipient `alg` and `epk`.
- Added focused native regression coverage for duplicate names, missing `alg`/`epk`, misplaced/duplicated `enc`, explicit null, unsupported members, multi-recipient protected/shared `epk`, protected-segment preservation, and accepted header-union placements.
- Refactored the two-way interop gate into fixture, direction, and wire-shape helpers, all at or below 50 lines.
- Corrected the two stale TypeScript comments without changing TypeScript crypto behavior.

## Verification

### Native Rust JWE unit slice

```powershell
cargo test -p tn-core --lib cipher::jwe
```

Result: exit 0; 15 passed, 0 failed, 88 filtered out.

### Direct Rust/TypeScript interoperability gate

```powershell
cargo test -p tn-proto --test interop_typescript rfc7516_jwe_round_trips_between_rust_and_typescript -- --ignored --exact --nocapture
```

Result: exit 0; 1 passed, 0 failed, 12 filtered out. This proves Rust-to-TypeScript and one-recipient TypeScript-to-Rust opening with the fixed X25519 keypair, plaintext, and authenticated AAD.

### Focused TypeScript slice

Run from `ts-sdk`:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test test/jwe_cipher.test.ts test/jwe_emit_async.test.ts test/jwe_read_async.test.ts test/seal_unseal.test.ts
```

Result: exit 0; 41 passed, 0 failed.

```powershell
npm run typecheck
```

Result: exit 0; `tsc --noEmit -p tsconfig.json` reported no errors.

### Diff and staging checks

`git diff --check` and `git diff --cached --check` both exited 0. The staged name-status inspection showed only:

- `crypto/tn-core/src/cipher/jwe.rs`
- `docs/superpowers/plans/2026-07-13-typescript-jwe-btn-fail-closed.md`
- `rust-sdk/tests/interop_typescript.rs`
- `ts-sdk/src/core/jwe.ts`
- `ts-sdk/src/runtime/keystore.ts`

The ignored plan was force-added intentionally because the updated brief explicitly required it. The index was empty after commit.

## Self-review

- Every newly added Rust production function, test, and helper is at or below 50 lines; the longest new function/helper is 30 lines.
- The direct gate uses exactly one recipient in each direction and asserts RFC 7516 General members, absence of legacy members, recovered plaintext, and AAD-bound opening.
- The parser never decodes and reserializes the protected segment used as AEAD AAD.
- Duplicate names are rejected rather than resolved by precedence.
- Protected/shared `epk` cannot substitute for per-recipient `epk` in multi-recipient input.
- Existing current-layout round trips remain green, and the emission-shape test still proves protected `enc` plus recipient `alg`/`epk`.
- No TypeScript runtime behavior changed; both TypeScript source edits are comments only.
- Unrelated dirty worktree files were neither staged nor reverted.

## Commit

`3c371ff92c969c3be4795e2cc395c36043e957af`

## Concerns

- The direct interoperability test remains intentionally ignored and depends on local Node/tsx/`jose` readiness. It was explicitly executed and passed in this environment, but default Rust test runs will not exercise it.
- The focused TypeScript tests emit their existing explicit-security-weakening warnings for enrollment fixtures; they completed with 41 passes and no failures.
- No known functional concern remains for the scoped parser compatibility fix.

## Review-hardening follow-up

Approved Minor review findings were addressed in follow-up commit `95d40f134128c1f622f96ffc31b4533007e3b942` (`test(jwe): harden header and interop gates`).

- Added explicit malformed regressions for present-but-unsupported `alg: dir` and protected `enc: A128GCM` values.
- Added a two-recipient malformed regression where the first recipient retains its local `epk` and the second recipient lacks `epk`.
- Changed the specifically invoked ignored interoperability gate to fail with a clear assertion when `typescript_ready()` is false, preventing a false-positive explicit run.

Verification commands and results:

```powershell
cargo test -p tn-core --lib cipher::jwe
```

Result: exit 0; 18 passed, 0 failed, 88 filtered out.

```powershell
cargo test -p tn-proto --test interop_typescript rfc7516_jwe_round_trips_between_rust_and_typescript -- --ignored --exact --nocapture
```

Result: exit 0; 1 passed, 0 failed, 12 filtered out.

`git diff --check` and `git diff --cached --check` exited 0. The follow-up commit contains only:

- `crypto/tn-core/src/cipher/jwe.rs`
- `rust-sdk/tests/interop_typescript.rs`
