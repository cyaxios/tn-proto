# Foundation Task 1 Report

## Status

Complete and committed in two Foundation commits. Foundation Task 1 freezes
deterministic trust fixtures, the common unsafe-operation notice contract in
Python/Rust/TypeScript/C#, the Rust admin catalog/reducer/export adapters, and
the shared C# warning event surface. The post-commit findings were remediated
test-first and accepted by two fresh independent reviews. No later task was
started.

## Git

- BASE: `09fd5ba50bf3c23201ca1d9406c73f5e2a9f84a6`
- Foundation commit: `79b887224d89fe06a66b25536365bf12b2965b84`
- Foundation subject: `test: freeze trusted principal vectors and unsafe-event contract`
- Remediation base: `79b887224d89fe06a66b25536365bf12b2965b84`
- HEAD / remediation commit: `a8822095e7bb2ee13e4c11e8597d605e45f2fddb`
- Remediation subject: `fix: harden unsafe-event and trust fixture contracts`

## Files changed

### Follow-up remediation

- `crypto/tn-core/src/admin_catalog.rs`
- `crypto/tn-core/src/unsafe_operation.rs`
- `crypto/tn-core/tests/admin_catalog_tests.rs`
- `crypto/tn-core/tests/admin_reduce_tests.rs`
- `crypto/tn-core/tests/runtime_emit.rs`
- `crypto/tn-core/tests/unsafe_operation_contract.rs`
- `python/tests/test_trust_fixture_generator.py`
- `tests/fixtures/trust/v1/read_policy_matrix.json`
- `tests/fixtures/trust/v1/signed_statements.json`
- `tools/fixtures/build_trust_v1.py`

### Generator and shared fixtures

- `tools/fixtures/build_trust_v1.py`
- `tests/fixtures/trust/v1/did_key_vectors.json`
- `tests/fixtures/trust/v1/signed_statements.json`
- `tests/fixtures/trust/v1/enrollment_lifecycle.json`
- `tests/fixtures/trust/v1/read_policy_matrix.json`
- `tests/fixtures/trust/v1/read_cursor_vectors.json`
- `tests/fixtures/trust/v1/state_transitions.json`
- `tests/fixtures/trust/v1/package_body_index.json`
- `tests/fixtures/trust/v1/unsafe_operation_event.json`

### Python

- `python/tn/security_audit.py`
- `python/tests/test_trust_fixture_generator.py`
- `python/tests/test_security_audit_contract.py`

### Rust core and adapters

- `crypto/tn-core/src/unsafe_operation.rs`
- `crypto/tn-core/src/lib.rs`
- `crypto/tn-core/src/admin_catalog.rs`
- `crypto/tn-core/src/admin_reduce.rs`
- `crypto/tn-core/tests/unsafe_operation_contract.rs`
- `crypto/tn-core/tests/admin_catalog_tests.rs`
- `crypto/tn-core/tests/admin_reduce_tests.rs`
- `crypto/tn-core-py/src/admin.rs`
- `crypto/tn-wasm/src/lib.rs`

### TypeScript

- `ts-sdk/src/core/unsafe_operation.ts`
- `ts-sdk/test/unsafe_operation_contract.test.ts`

### C#

- `csharp-sdk/src/TnProto/UnsafeOperationNotice.cs`
- `csharp-sdk/src/TnProto/TnSecurityWarningEventArgs.cs`
- `csharp-sdk/src/TnProto/Tn.cs`
- `csharp-sdk/tests/TnProto.Tests/UnsafeOperationNoticeTests.cs`

## RED evidence

- Python required command initially exited 1 during collection with
  `ModuleNotFoundError: No module named 'tn.security_audit'`. The generator-only
  run also exited 1 because `tools/fixtures/build_trust_v1.py` and all fixture
  documents were absent (4 failed, 1 passed).
- Rust required command initially exited 1 for the missing
  `tn_core::unsafe_operation` module and missing catalog array field support.
- TypeScript required command initially exited 1 with `ERR_MODULE_NOT_FOUND`
  for `src/core/unsafe_operation.js`.
- C# required command initially exited 1 with compiler errors for the missing
  notice/enums/event args and missing `Tn.SecurityWarning`/raiser.
- TDD remediation runs caught and then fixed: stale canonical bytes for mutated
  statements/manifests; incomplete unsafe enum fixture coverage; missing
  `auto -> raise` resolution; invalid read authorization metadata; signed
  body-index two-fault negatives; missing read-policy branches; non-public
  `"disabled"` input; non-JWE first-decrypt data; stale extra fixture files;
  the legacy `body/offer.json` path; reducer envelope handling; required
  nullable Rust fields; reducer catalog drift; and PyO3/WASM exhaustive
  `StringArray` mappings.
- Post-commit fixture RED:
  `.\.venv\Scripts\python.exe -m pytest python/tests/test_trust_fixture_generator.py -q`
  reported 2 failed / 5 passed: a non-`signature_invalid` statement had an
  invalid Ed25519 signature and the public `verify=True` vector was absent.
- Post-commit Rust RED: the focused runtime/catalog/reducer/notice matrix failed
  because the real runtime-injected `run_id` was rejected, unknown operation
  and relaxation strings plus an empty relaxation array were accepted, and the
  reducer inherited those semantic gaps. A follow-up focused RED also proved
  empty, null, and numeric `run_id` values were accepted before the metadata
  type check was added.

## GREEN evidence

- `.\.venv\Scripts\python.exe tools/fixtures/build_trust_v1.py` — exit 0.
- `.\.venv\Scripts\python.exe tools/fixtures/build_trust_v1.py --check` — exit 0.
- `.\.venv\Scripts\python.exe -m pytest python/tests/test_trust_fixture_generator.py python/tests/test_security_audit_contract.py -q`
  — 12 passed.
- Python Ruff check and format check on all four owned Python files — clean.
- `cargo test -p tn-core --test runtime_emit --test unsafe_operation_contract --test admin_catalog_tests --test admin_reduce_tests`
  — 52 passed (19 catalog + 18 reducer + 7 runtime + 8 notice).
- PyO3 and WASM `string_array_field_type_has_stable_wire_label` tests — 1
  passed in each crate.
- `cargo check -p tn-core-py` and `cargo check -p tn-wasm` — exit 0.
- Scoped `rustfmt --check --config skip_children=true` on all ten owned Rust
  files — exit 0.
- From `ts-sdk/`,
  `node --import tsx --import ./test/_setup_wasm.mjs --test test/unsafe_operation_contract.test.ts`
  — 3 passed; TypeScript typecheck, targeted ESLint, and targeted Prettier
  checks also passed.
- `dotnet test csharp-sdk/TnProto.sln --filter FullyQualifiedName~UnsafeOperationNoticeTests`
  — 4 passed, exit 0.
- `git diff --check` on remediation-owned paths and
  `git diff --cached --check` on the exact ten-path follow-up commit — exit 0.
- Initial independent reviews: Python/fixtures PASS/PASS, Rust PASS/PASS,
  TypeScript PASS/PASS, C# PASS/PASS, and combined Foundation review Ready to
  commit.
- Fresh post-remediation reviews: contract PASS and quality/scope PASS, each
  with zero Critical, Important, or Minor findings. Independent semantic audit
  verified 13 valid statement signatures, exactly one deliberate invalid
  signature, non-empty-string `run_id`, and rejection of a later-sorting
  arbitrary field after `run_id`; the fixture corpus now contains 100 cases.

## Post-commit findings resolved

1. A real `Runtime` regression now emits `tn.security.unsafe_operation`, parses
   and reserializes the NDJSON envelope, and replay-validates it through the
   reducer. Strict validation accepts only the five payload fields, the nine
   established envelope fields, and a non-empty-string `run_id`; arbitrary
   fields remain rejected regardless of key order.
2. Catalog and reducer validation project the exact five payload fields through
   `UnsafeOperationNotice`, rejecting unknown operation strings, unknown
   relaxation strings, and empty relaxations while retaining sorted,
   de-duplicated serialization.
3. Every signed-statement vector except the intentional `signature_invalid`
   case is re-signed after mutation. The contract test verifies canonical bytes
   and real Ed25519 signatures for every case.
4. The read-policy matrix now covers public `verify=True -> raise`, rejects the
   internal-only string `"disabled"` as a parameter error, and retains public
   `verify=False -> disabled`.

## Key implementation notes

- Fixture documents use schema `tn.trust-fixtures/v1`, canonicalization label
  `tn-canonical-json-v1`, compact sorted-key JSON, and one final newline.
- Fixed Ed25519/X25519 material produces real DID keys, signatures, challenge
  bindings, a signed `body/package.json` `.tnpkg`, and a deterministic General
  JSON JWE using `ECDH-ES+A256KW` plus `A256GCM`; TN's existing Python reader
  decrypts the first-decrypt vector.
- The 100 cases cover both JWE and HIBE authority challenges, all three proof
  purposes, enrollment response, package body indexes, replay/epoch behavior,
  secure read policy decisions, canonical source IDs/multi-source cursors, and
  every unsafe operation/relaxation enum.
- Negative enrollment/package inputs change one property and use one approved
  `expected.reason`; read decisions carry ordered `expected.reasons`.
- `--check` renders in memory, reports missing/changed/extra JSON paths, and
  never writes.
- Python uses a `ContextVar` recursion guard: the outer warning always fires,
  writable admin emission is best effort, and nested audit recursion is
  suppressed.
- Rust requires all five serialized notice fields even when nullable, accepts
  only the five payload fields plus established envelope scalars and a
  non-empty-string `run_id`, and reduces `tn.security.unsafe_operation` as an
  explicit no-state event. PyO3/WASM expose the array schema as stable
  `string_array`.
- C# exposes the shared `Tn.SecurityWarning` event and internal raiser for both
  later tracks.

## Deviations and risks

- The controller explicitly expanded ownership to the baseline-clean
  `crypto/tn-core/src/admin_reduce.rs` and
  `crypto/tn-core/tests/admin_reduce_tests.rs` after review proved that adding
  the catalog event otherwise broke exhaustive reducer behavior.
- The controller then explicitly expanded ownership to the baseline-clean
  `crypto/tn-core-py/src/admin.rs` and `crypto/tn-wasm/src/lib.rs` because the
  new public `FieldType::StringArray` required exhaustive language-adapter
  mappings. Both expansions were test-first and independently re-reviewed.
- Scoped rustfmt uses `skip_children=true` because invoking rustfmt on the crate
  root otherwise traverses unrelated pre-existing dirty modules. All owned Rust
  files pass the scoped check.
- The checkout remains dirty only for unrelated pre-existing user changes;
  they were neither staged nor committed. The remediation commit contains only
  the ten independently reviewed approved paths. No known Foundation Task 1
  risk remains.
