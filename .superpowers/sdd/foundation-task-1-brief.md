### Task 1: Freeze canonical statements, stable reasons, and shared vectors

**Files:**
- Create: `tools/fixtures/build_trust_v1.py`
- Create: `tests/fixtures/trust/v1/did_key_vectors.json`
- Create: `tests/fixtures/trust/v1/signed_statements.json`
- Create: `tests/fixtures/trust/v1/enrollment_lifecycle.json`
- Create: `tests/fixtures/trust/v1/read_policy_matrix.json`
- Create: `tests/fixtures/trust/v1/read_cursor_vectors.json`
- Create: `tests/fixtures/trust/v1/state_transitions.json`
- Create: `tests/fixtures/trust/v1/package_body_index.json`
- Create: `tests/fixtures/trust/v1/unsafe_operation_event.json`
- Create: `python/tn/security_audit.py`
- Create: `python/tests/test_trust_fixture_generator.py`
- Create: `python/tests/test_security_audit_contract.py`
- Create: `crypto/tn-core/src/unsafe_operation.rs`
- Modify: `crypto/tn-core/src/lib.rs`
- Modify: `crypto/tn-core/src/admin_catalog.rs`
- Modify (integration fix approved after review): `crypto/tn-core/src/admin_reduce.rs`
- Create: `crypto/tn-core/tests/unsafe_operation_contract.rs`
- Modify: `crypto/tn-core/tests/admin_catalog_tests.rs`
- Modify (integration fix approved after review): `crypto/tn-core/tests/admin_reduce_tests.rs`
- Modify (adapter exhaustiveness fix approved after review): `crypto/tn-core-py/src/admin.rs`
- Modify (adapter exhaustiveness fix approved after review): `crypto/tn-wasm/src/lib.rs`
- Create: `ts-sdk/src/core/unsafe_operation.ts`
- Create: `ts-sdk/test/unsafe_operation_contract.test.ts`
- Create: `csharp-sdk/src/TnProto/UnsafeOperationNotice.cs`
- Create: `csharp-sdk/src/TnProto/TnSecurityWarningEventArgs.cs`
- Modify: `csharp-sdk/src/TnProto/Tn.cs`
- Create: `csharp-sdk/tests/TnProto.Tests/UnsafeOperationNoticeTests.cs`

**Interfaces:**
- Fixture schema: `tn.trust-fixtures/v1`.
- Canonicalization label: `tn-canonical-json-v1`.
- Generator CLI: `python tools/fixtures/build_trust_v1.py [--check]`.
- Each negative case changes exactly one property. Enrollment/package cases carry one approved `expected.reason`; read cases carry an ordered `expected.reasons` array.
- Python common audit interface: `UnsafeOperationNotice`, `TnSecurityWarning`, and `record_unsafe_operation(notice, context)` using the exact event/payload enums in the design. The helper uses a `ContextVar` recursion guard; warnings always fire, writable admin emission is best effort.
- Rust, TypeScript, and C# common notice types use the same five payload fields and exact operation/relaxation enums. This task freezes data types/serialization only; each SDK track wires its language warning and best-effort audit behavior.
- The core catalog accepts `tn.security.unsafe_operation` with only those five fields. `Tn` exposes `SecurityWarning` and an internal raiser in Foundation so both C# tracks consume the same event surface.

- [ ] **Step 1: Write the failing generator contract test**

```python
def test_checked_in_trust_vectors_are_deterministic() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools/fixtures/build_trust_v1.py"), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_every_negative_vector_has_one_approved_reason() -> None:
    approved = {
        "statement_invalid", "statement_expired", "signature_invalid",
        "did_invalid", "did_signer_mismatch", "outer_inner_signer_mismatch",
        "wrong_recipient", "scope_mismatch", "body_digest_mismatch",
        "challenge_missing", "challenge_expired", "challenge_replayed",
        "replay_conflict", "binding_invalid", "untrusted_principal",
        "epoch_rollback", "epoch_conflict", "record_invalid",
        "row_hash_invalid", "chain_invalid", "signature_required",
        "writer_untrusted", "aad_invalid", "not_a_recipient",
    }
    for path in (ROOT / "tests/fixtures/trust/v1").glob("*.json"):
        for case in json.loads(path.read_text())["cases"]:
            expected = case["expected"]
            reasons = expected.get("reasons", [expected.get("reason")])
            assert all(reason is None or reason in approved for reason in reasons)
```

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_trust_fixture_generator.py python/tests/test_security_audit_contract.py -q`

Run: `cargo test -p tn-core --test unsafe_operation_contract --test admin_catalog_tests`

Run: `node --import tsx --import ./test/_setup_wasm.mjs --test test/unsafe_operation_contract.test.ts` from `ts-sdk/`.

Run: `dotnet test csharp-sdk/TnProto.sln --filter FullyQualifiedName~UnsafeOperationNoticeTests`

Expected: fail because the generator and vectors do not exist.

- [ ] **Step 3: Implement deterministic fixtures**

Use fixed Ed25519/X25519 seeds, timestamps, nonces, ceremony IDs, groups, and epochs. Emit sorted-key compact JSON with a final newline. Include challenge, all three proof purposes, `EnrollmentResponseV1`, manifest body-index, unsafe-event, replay, epoch, read-policy, and multi-source read-cursor cases. For signed statements compute canonical bytes with `signature_b64` omitted; for manifests omit only `manifest_signature_b64`. `--check` renders in memory and exits nonzero with the differing paths rather than writing.

Implement the common notice value in all four SDKs from the same fixture. Add
`tn.security.unsafe_operation` to the core catalog and the Foundation-owned C#
`Tn.SecurityWarning` event/internal raiser. The canonical payload is:

```json
{"artifact_digest":null,"group":null,"operation":"read","relaxations":["verification_disabled"],"subject_did":null}
```

- [ ] **Step 4: Run GREEN and inspect drift**

Run: `.\.venv\Scripts\python.exe tools/fixtures/build_trust_v1.py`

Run: `.\.venv\Scripts\python.exe tools/fixtures/build_trust_v1.py --check`

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_trust_fixture_generator.py python/tests/test_security_audit_contract.py -q`

Run the three cross-SDK contract commands from Step 2 again.

Expected: all commands exit 0.

- [ ] **Step 5: Checkpoint**

Stage only new/baseline-clean Foundation paths and commit `test: freeze trusted principal vectors and unsafe-event contract`.

---
