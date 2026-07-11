# Trusted Principal and JWE/HIBE Enrollment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Use superpowers:test-driven-development for every behavior change and superpowers:verification-before-completion before reporting completion. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind JWE and HIBE key material to complete Ed25519 `did:key` principals, complete the JWE reader enrollment lifecycle through first decrypt, and make normal HIBE authority/grant ceremonies fail closed.

**Architecture:** One versioned canonical-statement layer defines strict DID verification, stable reasons, and deterministic fixtures. Python owns ceremony orchestration and receiver-local state. Rust owns the reusable strict verifier and FFI contract; TypeScript and C# expose equivalent typed APIs and independently consume the same vectors. Enrollment mutations occur only after complete package, scope, freshness, replay, and authorization validation.

**Tech Stack:** Python 3.10+, PyNaCl/cryptography, Rust 1.85, serde/ed25519-dalek, TypeScript/Node, C#/.NET, canonical JSON, pytest, cargo test, Node test runner, xUnit.

## Global Constraints

- The approved contract is `docs/superpowers/specs/2026-07-11-trusted-enrollment-secure-read-design.md`; use only its stable reason codes.
- Preserve all unrelated changes. Before each task record `git status --short` and `git diff -- <owned paths>`. Never reset, checkout, stash, or run `git add .`.
- This checkout already contains relevant uncommitted ceremony fixes. Do not use a fresh worktree because it would omit them. One worker owns each path at a time.
- Task 1 owns `tools/fixtures/build_trust_v1.py` and every file under `tests/fixtures/trust/v1/`. Other tasks may consume but not edit those fixtures.
- Reject unknown version-1 fields and unsupported versions. Verify signatures against the Ed25519 key embedded in the asserted DID; an unrelated raw verification key never establishes identity.
- All private X25519 and HIBE reader keys remain with their recipient. All state writes are atomic and occur only after validation.
- HIBE remains evaluation-only: `tn-bbg` and its pairing stack are unaudited and require external cryptographic review before production use.
- Commit checkpoints are conditional in this dirty checkout: commit only newly created files or files proven clean at the captured baseline. For a pre-dirty file, retain and review the scoped diff instead of staging it.
- Task 1 is the short shared Foundation barrier. Once its fixture check passes, JWE/HIBE work and the companion secure-read track run concurrently.
- Foundation Task 1 solely owns the shared admin catalog and warning payload/event surfaces. Task 9 solely owns `crypto/tn-core-ffi/src/lib.rs`, C# `NativeMethods.cs`/`NativeBridge.cs`, and TS `src/index.ts`. Task 11 solely owns common docs/readmes and `python/tests/test_key_ceremony_docs.py`. Track workers do not edit those paths.
- Within enrollment, shared facade paths are serialized: Python JWE Task 5 finishes before HIBE Task 6 edits `admin/__init__.py`/`cipher.py`; package-body Task 3 finishes before TS enrollment Task 8 edits `core/tnpkg.ts`/`node_runtime.ts`. The secure-read workstream still runs concurrently because it owns disjoint track-local paths.

---

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
- Create: `crypto/tn-core/tests/unsafe_operation_contract.rs`
- Modify: `crypto/tn-core/tests/admin_catalog_tests.rs`
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

### Task 2: Add strict Python DID and key-binding primitives

**Files:**
- Create: `python/tn/trust.py`
- Create: `python/tn/key_binding.py`
- Create: `python/tests/test_trusted_principals.py`
- Create: `python/tests/test_key_binding_wire.py`
- Modify: `python/tn/recipient_seal.py`
- Modify: `python/tn/signing.py`

**Interfaces:**

```text
TrustReason is `class TrustReason(str, Enum)` with values:
  statement_invalid, statement_expired, signature_invalid, did_invalid,
  did_signer_mismatch, outer_inner_signer_mismatch, wrong_recipient,
  scope_mismatch, body_digest_mismatch, challenge_missing,
  challenge_expired, challenge_replayed, replay_conflict, binding_invalid,
  untrusted_principal, epoch_rollback, epoch_conflict

TrustError(ValueError): reason: TrustReason; detail: str

VerifiedPrincipal fields:
  did: str
  purpose: Literal["jwe-reader", "hibe-reader", "hibe-authority"]
  audience_did: str
  ceremony_id: str
  group: str
  proof_digest: str
  issued_at: datetime
  expires_at: datetime

VerifiedJweBinding fields:
  principal: VerifiedPrincipal
  public_key: bytes
  public_key_sha256: str
  proof_digest: str
  challenge_digest: str | None

AcceptedOffer fields:
  binding: VerifiedJweBinding
  offer_digest: str
  artifact_digest: str

EnrollmentChallengeV1 fields:
  version: Literal[1]
  kind: Literal["tn-enrollment-challenge"]
  publisher_did: str
  expected_reader_did: str
  ceremony_id: str
  group: str
  nonce_b64: str
  issued_at: datetime
  expires_at: datetime
  challenge_id: str
  signature_b64: str

KeyBindingProofV1 fields:
  version: Literal[1]
  purpose: Literal["jwe-reader", "hibe-reader", "hibe-authority"]
  subject_did: str
  audience_did: str
  ceremony_id: str
  group: str
  issued_at: datetime
  expires_at: datetime
  nonce_b64: str
  binding: Mapping[str, object]
  signature_b64: str

EnrollmentResponseV1 fields:
  version: Literal[1]
  kind: Literal["tn-enrollment-response"]
  publisher_did: str
  reader_did: str
  ceremony_id: str
  group: str
  accepted_offer_digest: str
  x25519_public_key_sha256: str
  group_epoch: int
  issued_at: datetime
  expires_at: datetime
  signature_b64: str

parse_ed25519_did_key(did: str) -> bytes
verify_ed25519_did_signature(did: str, message: bytes, signature: bytes) -> None
EnrollmentChallengeV1.from_dict(value: Mapping[str, object]) -> EnrollmentChallengeV1
EnrollmentChallengeV1.signing_bytes() -> bytes
EnrollmentChallengeV1.sign(key: DeviceKey) -> EnrollmentChallengeV1
verify_enrollment_challenge(
  challenge: EnrollmentChallengeV1,
  expected_publisher_did: str,
  expected_reader_did: str,
  expected_ceremony_id: str,
  expected_group: str,
  now: datetime,
) -> None
KeyBindingProofV1.from_dict(value: Mapping[str, object]) -> KeyBindingProofV1
KeyBindingProofV1.signing_bytes() -> bytes
KeyBindingProofV1.sign(key: DeviceKey) -> KeyBindingProofV1
verify_key_binding_proof(
  proof: KeyBindingProofV1,
  expected_purpose: str,
  expected_audience_did: str,
  expected_ceremony_id: str,
  expected_group: str,
  now: datetime,
  challenge: EnrollmentChallengeV1 | None,
) -> VerifiedPrincipal
verify_jwe_key_binding(
  proof: KeyBindingProofV1,
  expected_audience_did: str,
  expected_ceremony_id: str,
  expected_group: str,
  now: datetime,
  challenge: EnrollmentChallengeV1 | None,
) -> VerifiedJweBinding
EnrollmentResponseV1.from_dict(value: Mapping[str, object]) -> EnrollmentResponseV1
EnrollmentResponseV1.signing_bytes() -> bytes
EnrollmentResponseV1.sign(key: DeviceKey) -> EnrollmentResponseV1
verify_enrollment_response(
  response: EnrollmentResponseV1,
  expected_publisher_did: str,
  expected_reader_did: str,
  expected_ceremony_id: str,
  expected_group: str,
  expected_offer_digest: str,
  expected_public_key_sha256: str,
  now: datetime,
) -> None
```

- [ ] **Step 1: Add fixture-driven failing tests**

Assert exact canonical bytes for challenge, proof, and response; strict Ed25519 multicodec/32-byte parsing; valid signatures; mutated signatures; unknown fields; unsupported versions; wrong audience/scope; expiry; and X25519/MPK binding validation. Verify challenges against the expected publisher before a proof can be signed. Assert `TrustError.reason`, not message text.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_trusted_principals.py python/tests/test_key_binding_wire.py -q`

Expected: import errors for `tn.trust` and `tn.key_binding`.

- [ ] **Step 3: Implement and consolidate**

Move the strict Ed25519 DID decoder now duplicated in `recipient_seal.py` into `trust.py`. Keep `DeviceKey.verify` backward compatible, but ensure all ceremony code calls the strict helper. Parse JSON with exact allowed-field sets; validate time ordering, purpose-specific binding keys, algorithms, and decoded lengths before signature verification.

- [ ] **Step 4: Run GREEN and regress recipient sealing**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_trusted_principals.py python/tests/test_key_binding_wire.py python/tests/test_sealed_tnpkg_package_contract.py -q`

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit only clean/new task paths as `feat: add strict trusted principal proofs`.

---

### Task 3: Bind every package body member into the signed manifest

**Files:**
- Modify: `python/tn/tnpkg.py`
- Modify: `python/tn/export.py`
- Modify: `python/tn/cli_compile.py`
- Modify: `python/tests/test_manifest_contract.py`
- Modify: `python/tests/test_tnpkg_container_contract.py`
- Modify: `crypto/tn-core/src/tnpkg/mod.rs`
- Modify: `crypto/tn-core/src/tnpkg/zip_write.rs`
- Modify: `crypto/tn-core/src/tnpkg/zip_read.rs`
- Modify: `crypto/tn-core/src/tnpkg/sign.rs`
- Modify: `crypto/tn-core/src/runtime_export/mod.rs`
- Modify: `crypto/tn-core/tests/manifest_contract.rs`
- Modify: `crypto/tn-core/tests/tnpkg_container_contract.rs`
- Modify: `ts-sdk/src/core/tnpkg.ts`
- Modify: `ts-sdk/src/tnpkg_io.ts`
- Modify: `ts-sdk/src/compile.ts`
- Modify: `ts-sdk/src/seal_bundle_producer.ts`
- Modify: `ts-sdk/src/cli/export.ts`
- Modify: `ts-sdk/src/runtime/node_runtime.ts`
- Modify: `ts-sdk/test/manifest_contract.test.ts`
- Modify: `ts-sdk/test/tnpkg_container_contract.test.ts`
- Consume: `tests/fixtures/trust/v1/package_body_index.json`

**Interfaces:**

```text
TnpkgManifest.body_sha256: dict[str, str]
compute_body_sha256(body_files: Mapping[str, bytes]) -> dict[str, str]
prepare_manifest_body_index(
  manifest: TnpkgManifest,
  body_files: Mapping[str, bytes],
) -> TnpkgManifest
sign_manifest_with_body(
  manifest: TnpkgManifest,
  body_files: Mapping[str, bytes],
  signing_key: Ed25519PrivateKey,
) -> TnpkgManifest
verify_manifest_body_index(
  manifest: TnpkgManifest,
  body_files: Mapping[str, bytes],
  require_index: bool,
) -> None
```

Rust uses `Manifest.body_sha256: BTreeMap<String, String>`,
`sign_manifest_with_body(manifest, body, key)`, and
`read_tnpkg_verified(source)`. TypeScript uses
`body_sha256: Record<string, string>`, `signManifestWithBody`, and
`readTnpkgVerified` with the same snake-case wire name.

- [ ] **Step 1: Write failing cross-SDK body-index tests**

For the shared fixture, assert exact lowercase `sha256:` values, signing bytes,
and signature. Add one-property failures for a substituted body, missing indexed
member, extra archive member, malformed digest, and missing index. Prove the
manifest signature is checked before body bytes are loaded and the digest index
is checked before any kind-specific body parser or mutation.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_manifest_contract.py python/tests/test_tnpkg_container_contract.py -q`

Run: `cargo test -p tn-core --test manifest_contract --test tnpkg_container_contract`

Run: `node --import tsx --import ./test/_setup_wasm.mjs --test test/manifest_contract.test.ts test/tnpkg_container_contract.test.ts` from `ts-sdk/`.

Expected: manifests do not expose or verify `body_sha256`.

- [ ] **Step 3: Implement the additive v1 field and strict writer/reader checks**

Compute the map from final stored bytes before signing through the central
builder, then migrate every producer listed above to that builder. `_write_tnpkg`,
Rust `write_tnpkg`/`write_tnpkg_bytes`, and TS writers reject an unsigned
manifest or a map that differs from their supplied body. Refactor Rust's current
body-first `read_tnpkg` path: `read_tnpkg_verified` enforces central-directory
limits, reads the bounded manifest alone, verifies its complete-DID signature,
then reads bounded members and checks the exact digest map before returning any
body. Secure absorb uses only that API. Low-level inspection may parse a legacy
manifest only when it does not apply body state; security-sensitive absorb
requires the index unless its caller selects the named unsafe legacy migration
in Task 5.

Representative Python check:

```python
actual = compute_body_sha256(body_files)
if manifest.body_sha256 != actual:
    raise TrustError(TrustReason.BODY_DIGEST_MISMATCH, "body index mismatch")
```

- [ ] **Step 4: Run GREEN and targeted format checks**

Run all three Step 2 commands.

Run: `rustfmt --edition 2021 --check crypto/tn-core/src/tnpkg/mod.rs crypto/tn-core/src/tnpkg/zip_write.rs crypto/tn-core/src/tnpkg/zip_read.rs crypto/tn-core/src/tnpkg/sign.rs crypto/tn-core/src/runtime_export/mod.rs crypto/tn-core/tests/manifest_contract.rs crypto/tn-core/tests/tnpkg_container_contract.rs`

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit only baseline-clean paths as `feat(tnpkg): sign package body digests`.

---

### Task 4: Implement challenge, replay, and complete pending-offer state

**Files:**
- Create: `python/tn/enrollment.py`
- Create: `python/tests/test_enrollment_state.py`
- Modify: `python/tn/conventions.py`
- Modify: `python/tn/_keystore_backend.py`
- Modify: `python/tn/absorb.py`
- Modify: `python/tn/reconcile.py`
- Modify: `python/tn/admin/__init__.py`
- Modify: `python/tests/test_reconcile.py`

**Interfaces:**

```text
@dataclass(frozen=True)
class PendingOffer:
    ceremony_id: str
    group: str
    reader_did: str
    offer_digest: str
    artifact_path: Path
    verified: VerifiedJweBinding

class EnrollmentStore:
  constructor(
    cfg: LoadedConfig,
    publisher_key: DeviceKey,
    state_root: Path | None = None,
  )
  preauthorize(reader_did: str, group: str) -> None
  issue_challenge(reader_did: str, group: str, ttl: timedelta) -> EnrollmentChallengeV1
  stage_offer(
    artifact: bytes,
    expected_publisher_did: str,
    now: datetime,
  ) -> PendingOffer
  reconcile(pending: PendingOffer, *, now: datetime) -> AcceptedOffer
  approve_and_reconcile(offer_digest: str, *, now: datetime) -> AcceptedOffer

admin.reconcile_enrollment(
  offer_digest: str,
  *,
  approve: bool = False,
  cfg: LoadedConfig | None = None,
  now: datetime | None = None,
) -> AcceptedOffer

ReconcileResult.accepted_offers: list[AcceptedOffer]
```

State root layout:

```text
enrollment/v1/enrollment.lock
enrollment/v1/challenges/<challenge_id>.json
enrollment/v1/offers/<ceremony_id>/<group>/<did_sha256>/<offer_digest>.tnpkg
enrollment/v1/approvals/<offer_digest>.json
enrollment/v1/consumed/<challenge_id>.json
```

- [ ] **Step 1: Write failing state-machine tests**

Cover publisher-signed challenge issuance, exact replay as an idempotent no-op, changed body under the same nonce as `replay_conflict`, consumed challenge as `challenge_replayed`, expired challenge, two groups for one DID without collision, unsolicited offer pending until exact-digest approval, crash-safe temporary files, and no state mutation on any failure. Exercise public `admin.reconcile_enrollment`: preauthorized offers pass with `approve=False`; unsolicited offers require `approve=True`. A multiprocess test races two `approve_and_reconcile` calls: exactly one consumes the challenge, the identical contender converges on the same `AcceptedOffer`, and a conflicting contender gets `replay_conflict`. Assert the returned `offer_digest` and `artifact_digest` are derived from the same retained artifact as the binding.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_enrollment_state.py python/tests/test_reconcile.py -q`

Expected: missing `EnrollmentStore` and old DID-only pending behavior failures.

- [ ] **Step 3: Implement receiver-local state**

Key artifacts by `(ceremony_id, group, reader_did, offer_digest)`. Retain the complete signed `.tnpkg`; never reduce it to DID/key JSON. Reuse/export the cross-platform advisory lock from `_keystore_backend.py` and hold `enrollment.lock` across challenge consumption, approval, and promotion. Write through same-directory temporary files, fsync file and parent directory where supported, then replace. Verify again during promotion. Record consumed challenge IDs and accepted digests separately so idempotency does not become replay authorization.

Representative serialized promotion boundary:

```python
with AdvisoryFileLock(store.lock_path):
    binding = store.reverify(pending, expected_publisher_did=cfg.device.device_identity)
    store.assert_challenge_available(binding.challenge_digest)
    accepted = store.write_consumed_and_promoted(pending, binding)
return accepted
```

- [ ] **Step 4: Run GREEN**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_enrollment_state.py python/tests/test_absorb.py python/tests/test_reconcile.py -q`

Expected: pass.

- [ ] **Step 5: Checkpoint**

Review the full pre/post diffs of `absorb.py` and `reconcile.py`; commit only if their baselines were clean.

---

### Task 5: Complete authenticated JWE enrollment through first decrypt

**Files:**
- Modify: `python/tn/offer.py`
- Modify: `python/tn/packaging.py`
- Modify: `python/tn/absorb.py`
- Modify: `python/tn/reconcile.py`
- Modify: `python/tn/admin/__init__.py`
- Modify: `python/tn/cipher.py`
- Modify: `python/tn/compile.py`
- Modify: `python/tn/pkg.py`
- Create: `python/tests/test_jwe_trusted_enrollment_e2e.py`
- Create: `python/tests/test_jwe_rotation_reenrollment.py`
- Create: `python/tests/test_package_identity_binding.py`
- Modify: `python/tests/test_offer.py`
- Modify: `python/tests/test_manifest_contract.py`

**Interfaces:**

```text
offer(
    cfg: LoadedConfig,
    publisher_did: str,
    *,
    challenge: EnrollmentChallengeV1 | None = None,
    group: str = "default",
) -> Package

add_recipient(
    group: str,
    *,
    recipient: Any | None = None,
    recipient_did: str | None = None,
    out_path: Path | str | None = None,
    public_key: bytes | None = None,
    raw: bool = False,
    cfg: LoadedConfig | None = None,
    accepted_offer: AcceptedOffer | None = None,
    unsafe_unverified: bool = False,
) -> AddRecipientResult

compile_enrolment(
    cfg: LoadedConfig,
    group: str,
    peer_did: str,
    *,
    accepted_offer: AcceptedOffer,
    ttl: timedelta = timedelta(minutes=10),
) -> Package

absorb retains all existing call shapes and adds keyword-only:
  unsafe_legacy_signer: bool = False

JWE rotation writes `<keystore>/<group>.jwe.reenrollment.v1.json`:
  version: 1
  group: str
  previous_epoch: int
  rotated_at: RFC3339 str
  readers: [{ reader_did, public_key_sha256, proof_digest }]
```

- [ ] **Step 1: Write the failing lifecycle test**

The test must create independent publisher and reader homes and run: publisher preauthorization/challenge -> reader verifies challenge and creates/reuses its key -> reader offer -> publisher absorb -> reconcile/approve -> signed `EnrollmentResponseV1` -> reader absorb -> publisher seal -> reader decrypt. Assert the reader's `.jwe.mykey` inode/content is unchanged and never copied to the publisher. Add failures for outer/inner signer mismatch, wrong recipient, body digest mutation, response key mismatch, raw enrollment without `unsafe_unverified=True`, and legacy unrelated signing key without `unsafe_legacy_signer=True`. Rotation tests prove active recipients reset to publisher-only, verified bindings become an inactive re-enrollment plan, and no old public key is silently restored.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_jwe_trusted_enrollment_e2e.py python/tests/test_jwe_rotation_reenrollment.py python/tests/test_package_identity_binding.py python/tests/test_offer.py python/tests/test_manifest_contract.py -q`

Expected: the current offer has no signed binding/challenge and raw registration is accepted.

- [ ] **Step 3: Implement fail-closed package verification**

Make `packaging.verify` bind its signature to the claimed DID. In absorb, validate the outer manifest, every body digest, outer/inner signer, recipient, purpose, ceremony, group, challenge, and authorization before calling any state-mutating helper. `offer` preserves its existing return/outbox behavior; without a challenge it emits a signed unsolicited proof whose null challenge digest can only be exact-digest approved. `add_recipient` preserves BTN/HIBE polymorphism; its normal JWE branch requires one `AcceptedOffer` and cross-checks its retained audience/ceremony/group plus any supplied DID/key. Persist `verified`, `proof_digest`, and X25519 key digest with the recipient. Unsafe raw enrollment and legacy import emit the common warning plus `tn.security.unsafe_operation` payload and persist `verified: false`.

- [ ] **Step 4: Bind the publisher response**

Have `compile_enrolment` accept the same `AcceptedOffer` used for registration and embed its offer/key digests in the strict `EnrollmentResponseV1`; it has no independent digest parameter. On the reader, verify publisher DID/signature, exact recipient/scope/offer/key digest and expiry, derive the public key from the existing local private key, and compare it before installing publisher metadata. Persist the authenticated publisher DID/proof source in `<keystore>/trust/verified_publishers.v1.json`, the shared read-trust adapter path. JWE rotation stores prior verified bindings only as an inactive re-enrollment plan.

- [ ] **Step 5: Run GREEN**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_jwe_trusted_enrollment_e2e.py python/tests/test_jwe_rotation_reenrollment.py python/tests/test_package_identity_binding.py python/tests/test_offer.py python/tests/test_absorb.py python/tests/test_reconcile.py python/tests/test_manifest_contract.py -q`

Expected: pass; the first decrypt succeeds without private-key transfer.

- [ ] **Step 6: Checkpoint**

Because several paths are pre-dirty, retain a scoped diff checkpoint unless every changed hunk has been reviewed and staged explicitly.

---

### Task 6: Authenticate HIBE authorities and fail closed on reader grants

**Files:**
- Modify: `python/tn/cipher.py`
- Modify: `python/tn/admin/__init__.py`
- Modify: `python/tn/recipient_seal.py`
- Modify: `python/tn/key_binding.py`
- Create: `python/tests/test_hibe_authority_trust.py`
- Modify: `python/tests/test_hibe_grant_absorb.py`
- Modify: `python/tests/test_hibe_boundary.py`
- Modify: `python/tests/test_hibe_revoke.py`
- Create: `python/tests/test_hibe_external_writer_rotation.py`

**Interfaces:**

```text
HibeAuthorityUpdateResult fields:
  group: str
  id_path: str
  path_epoch: int
  assertion: KeyBindingProofV1

install_authority_assertion(
    group: str,
    *,
    mpk: bytes,
    assertion: KeyBindingProofV1,
    expected_authority_did: str,
    cfg: LoadedConfig | None = None,
    now: datetime | None = None,
) -> None

issue_authority_assertion(
    group: str,
    *,
    ttl: timedelta = timedelta(minutes=10),
    cfg: LoadedConfig | None = None,
) -> KeyBindingProofV1

issue_hibe_reader_challenge(
    group: str,
    reader_did: str,
    *,
    ttl: timedelta = timedelta(minutes=10),
    cfg: LoadedConfig | None = None,
) -> EnrollmentChallengeV1

create_hibe_reader_proof(
    challenge: EnrollmentChallengeV1,
    *,
    cfg: LoadedConfig,
    now: datetime | None = None,
) -> KeyBindingProofV1

rotate_hibe_path(
    group: str,
    new_path: str,
    *,
    cfg: LoadedConfig | None = None,
) -> HibeAuthorityUpdateResult

grant_reader(
    group: str,
    *,
    reader_did: str | None = None,
    id_path: str | None = None,
    out_path: Path | str | None = None,
    cfg: LoadedConfig | None = None,
    proof: KeyBindingProofV1 | VerifiedPrincipal | None = None,
    allow_subauthority: bool = False,
    unsafe_plaintext: bool = False,
) -> AddRecipientResult
```

- [ ] **Step 1: Write failing authority/grant tests**

Cover authority issuance and valid pin/install, wrong DID/signature, MPK substitution, encoded-depth mismatch, configured path too deep, expired assertion on seal, signed higher-epoch path update, same-epoch conflict (`epoch_conflict`), rollback (`epoch_rollback`), scoped reader challenge/proof, exact-path sealed grant, absent/abbreviated DID failure, no implicit plaintext fallback, explicit unsafe warning/audit, and ancestor grant requiring `allow_subauthority=True`. An external writer test proves it cannot seal until it accepts/pins the initial assertion and cannot use the authority's rotated sibling path until it accepts the higher-epoch assertion.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_hibe_authority_trust.py python/tests/test_hibe_grant_absorb.py python/tests/test_hibe_boundary.py python/tests/test_hibe_revoke.py python/tests/test_hibe_external_writer_rotation.py -q`

Expected: missing assertion API and current plaintext fallback/ancestor behavior failures.

- [ ] **Step 3: Implement pinning and sealed delivery**

`issue_authority_assertion` signs the current MPK/depth/path/epoch; `rotate_hibe_path` rotates and returns the new signed assertion as one result. `install_authority_assertion` is the explicit external-writer accept/pin/update API. Atomically persist authority DID, MPK SHA-256, encoded maximum depth, exact path, epoch, and assertion digest. Require the already pinned authority DID for updates. Refuse new seals after assertion expiry. Normal grants require a scope-valid `hibe-reader` proof or retained verified-reader record and always use `recipient-seal-v1`. Preserve the existing `grant_reader` call shape/`AddRecipientResult`; remove only its implicit plaintext fallback. Mark unsafe plaintext packages and ancestor delegation explicitly in their manifests and common audit records.

- [ ] **Step 4: Run GREEN plus walkthrough**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_hibe_authority_trust.py python/tests/test_hibe_grant_absorb.py python/tests/test_hibe_boundary.py python/tests/test_hibe_revoke.py python/tests/test_hibe_external_writer_rotation.py -q`

Run: `.\.venv\Scripts\python.exe python/tests/demo_hibe_walkthrough.py`

Expected: pass; walkthrough uses `max_depth=3` and authenticated assertions.

- [ ] **Step 5: Checkpoint**

Retain scoped diffs for pre-dirty Python files; commit new tests only if independently useful and exact paths are staged.

---

### Task 7: Implement Rust trust and complete public enrollment parity

**Files:**
- Modify: `crypto/tn-core/src/signing.rs`
- Create: `crypto/tn-core/src/trust.rs`
- Modify: `crypto/tn-core/src/lib.rs`
- Modify: `crypto/tn-core/src/tnpkg/sign.rs`
- Modify: `crypto/tn-core/src/recipient_seal.rs`
- Create: `crypto/tn-core/src/trusted_enrollment.rs`
- Create: `crypto/tn-core/tests/trusted_principals.rs`
- Create: `crypto/tn-core/tests/trusted_enrollment.rs`
- Create: `rust-sdk/src/enrollment.rs`
- Modify: `rust-sdk/src/pkg.rs`
- Modify: `rust-sdk/src/admin.rs`
- Modify: `rust-sdk/src/tn.rs`
- Integration owner modifies: `rust-sdk/src/lib.rs`
- Create: `rust-sdk/tests/trusted_enrollment.rs`
- Create: `rust-sdk/tests/jwe_trusted_enrollment.rs`
- Create: `rust-sdk/tests/hibe_trusted_authority.rs`
- Consume joint Task 9: `crypto/tn-core-ffi/src/lib.rs`
- Modify: `crypto/tn-core-py/src/lib.rs`

**Interfaces:**

```rust
pub fn parse_ed25519_did_key(did: &str) -> Result<[u8; 32], TrustError>;
pub fn verify_ed25519_did_signature(
    did: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TrustError>;
pub fn create_hibe_reader_proof(
    challenge: &EnrollmentChallengeV1,
    reader_key: &DeviceKey,
    now: SystemTime,
) -> Result<KeyBindingProofV1>;
pub fn verify_enrollment_challenge(
    challenge: &EnrollmentChallengeV1,
    expected: &ChallengeExpectation,
) -> Result<(), TrustError>;
pub fn verify_enrollment_response(
    response: &EnrollmentResponseV1,
    expected: &ResponseExpectation,
) -> Result<(), TrustError>;

pub enum TrustReason {
    StatementInvalid, StatementExpired, SignatureInvalid, DidInvalid,
    DidSignerMismatch, OuterInnerSignerMismatch, WrongRecipient,
    ScopeMismatch, BodyDigestMismatch, ChallengeMissing, ChallengeExpired,
    ChallengeReplayed, ReplayConflict, BindingInvalid, UntrustedPrincipal,
    EpochRollback, EpochConflict,
}
pub struct EnrollmentChallengeV1 {
    pub version: u8,
    pub kind: String,
    pub publisher_did: String,
    pub expected_reader_did: String,
    pub ceremony_id: String,
    pub group: String,
    pub nonce_b64: String,
    pub issued_at: String,
    pub expires_at: String,
    pub challenge_id: String,
    pub signature_b64: String,
}
pub struct KeyBindingProofV1 {
    pub version: u8,
    pub purpose: String,
    pub subject_did: String,
    pub audience_did: String,
    pub ceremony_id: String,
    pub group: String,
    pub issued_at: String,
    pub expires_at: String,
    pub nonce_b64: String,
    pub binding: serde_json::Value,
    pub signature_b64: String,
}
pub struct EnrollmentResponseV1 {
    pub version: u8,
    pub kind: String,
    pub publisher_did: String,
    pub reader_did: String,
    pub ceremony_id: String,
    pub group: String,
    pub accepted_offer_digest: String,
    pub x25519_public_key_sha256: String,
    pub group_epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub signature_b64: String,
}
pub struct ChallengeExpectation {
    pub publisher_did: String,
    pub reader_did: String,
    pub ceremony_id: String,
    pub group: String,
    pub now: SystemTime,
}
pub struct ResponseExpectation {
    pub publisher_did: String,
    pub reader_did: String,
    pub ceremony_id: String,
    pub group: String,
    pub offer_digest: String,
    pub public_key_sha256: String,
    pub now: SystemTime,
}
pub struct VerifiedPrincipal {
    pub did: String,
    pub purpose: String,
    pub audience_did: String,
    pub ceremony_id: String,
    pub group: String,
    pub proof_digest: String,
    pub issued_at: String,
    pub expires_at: String,
}
pub struct VerifiedJweBinding {
    pub principal: VerifiedPrincipal,
    pub public_key: [u8; 32],
    pub public_key_sha256: String,
    pub proof_digest: String,
    pub challenge_digest: Option<String>,
}
pub struct AcceptedOffer {
    pub binding: VerifiedJweBinding,
    pub offer_digest: String,
    pub artifact_digest: String,
}
pub struct AbsorbOptionsV1 {
    pub unsafe_legacy_signer: bool,
}
pub struct OfferOptionsV1 {
    pub group: String,
    pub publisher_did: String,
    pub out_path: PathBuf,
    pub challenge: Option<EnrollmentChallengeV1>,
}
pub struct CompileEnrolmentOptionsV1 {
    pub group: String,
    pub reader_did: String,
    pub out_path: PathBuf,
    pub accepted_offer: AcceptedOffer,
    pub ttl: Duration,
}
pub struct InstallHibeAssertionOptions {
    pub group: String,
    pub mpk: Vec<u8>,
    pub assertion: KeyBindingProofV1,
    pub expected_authority_did: String,
    pub now: SystemTime,
}
pub struct GrantReaderOptionsV1 {
    pub group: String,
    pub reader_did: String,
    pub out_path: PathBuf,
    pub id_path: Option<String>,
    pub proof: KeyBindingProofV1,
    pub allow_subauthority: bool,
    pub unsafe_plaintext: bool,
}
pub struct HibeAuthorityUpdate {
    pub group: String,
    pub id_path: String,
    pub path_epoch: u64,
    pub assertion: KeyBindingProofV1,
}

impl Package<'_> {
    pub fn issue_enrollment_challenge(&self, reader_did: &str, group: &str, ttl: Duration)
        -> Result<EnrollmentChallengeV1>;
    pub fn reconcile_pending(&self, offer_digest: &str) -> Result<AcceptedOffer>;
    pub fn approve_and_reconcile(&self, offer_digest: &str) -> Result<AcceptedOffer>;
    pub fn offer_v1(&self, options: OfferOptionsV1) -> Result<OfferReceipt>;
    pub fn compile_enrolment_v1(&self, options: CompileEnrolmentOptionsV1)
        -> Result<CompiledPackage>;
    pub fn absorb_with_options(&self, source: AbsorbSource, options: AbsorbOptionsV1)
        -> Result<AbsorbReceipt>;
}
impl Admin<'_> {
    pub fn register_jwe_offer(&self, group: &str, accepted: &AcceptedOffer)
        -> Result<AddRecipientResult>;
    pub fn register_jwe_raw_unsafe(
        &self, group: &str, reader_did: &str, public_key: [u8; 32],
        unsafe_unverified: bool,
    ) -> Result<AddRecipientResult>;
    pub fn issue_hibe_authority_assertion(&self, group: &str, ttl: Duration)
        -> Result<KeyBindingProofV1>;
    pub fn issue_hibe_reader_challenge(
        &self, group: &str, reader_did: &str, ttl: Duration,
    ) -> Result<EnrollmentChallengeV1>;
    pub fn install_hibe_authority_assertion(&self, options: InstallHibeAssertionOptions)
        -> Result<()>;
    pub fn rotate_hibe_path_with_assertion(&self, group: &str, new_path: &str)
        -> Result<HibeAuthorityUpdate>;
    pub fn grant_reader_verified(&self, options: GrantReaderOptionsV1)
        -> Result<GrantReaderResult>;
}
```

- [ ] **Step 1: Add failing shared-vector tests**

Load `../../tests/fixtures/trust/v1/did_key_vectors.json`, `signed_statements.json`, `enrollment_lifecycle.json`, and `state_transitions.json`. Reconstruct canonical bytes independently and assert exact decision/reason for every key binding, challenge, and accepted response. At the Rust SDK surface run challenge, offer, atomic approval/reconcile, accepted response, and artifact absorption/interop; retain the established documented native JWE `NotImplemented` sentinel. Run native HIBE assertion pin/update, fail-closed grant, unsafe warning/audit capture, reader challenge/proof, signed path rotation, and ancestor opt-in. Python, TypeScript, and C# managed JWE tests own first decrypt.

- [ ] **Step 2: Run RED**

Run: `cargo test -p tn-core --test trusted_principals --test trusted_enrollment`

Run: `cargo test -p tn-proto --test trusted_enrollment --test jwe_trusted_enrollment --test hibe_trusted_authority`

Expected: unresolved trust module/types.

- [ ] **Step 3: Implement and consolidate**

Centralize the strict parser currently duplicated by TN package and recipient-seal code. Keep existing public compatibility methods, but route all new trust decisions through the strict API. Implement the same locked enrollment state layout and typed binding/response checks as Python, including `<keystore>/trust/verified_publishers.v1.json`. Extend existing `Package::offer`, `compile_enrolment`, and absorb option structs rather than replacing their public methods. Extend existing `Admin::grant_reader` through `GrantReaderOptionsV1`; no implicit plaintext. Rust SDK emits the one structured log warning; the mutation-owning runtime emits the one best-effort audit event. Prepare versioned JSON DTOs for the integration owner's FFI functions without changing existing symbols.

- [ ] **Step 4: Run GREEN and lint**

Run: `cargo test -p tn-core --test trusted_principals --test trusted_enrollment`

Run: `cargo test -p tn-proto --test trusted_enrollment --test jwe_trusted_enrollment --test hibe_trusted_authority`

Run: `cargo test -p tn-core-py`

Run: `rustfmt --edition 2021 --check crypto/tn-core/src/signing.rs crypto/tn-core/src/trust.rs crypto/tn-core/src/trusted_enrollment.rs crypto/tn-core/src/tnpkg/sign.rs crypto/tn-core/src/recipient_seal.rs crypto/tn-core/tests/trusted_principals.rs crypto/tn-core/tests/trusted_enrollment.rs rust-sdk/src/enrollment.rs rust-sdk/src/pkg.rs rust-sdk/src/admin.rs rust-sdk/src/tn.rs rust-sdk/tests/trusted_enrollment.rs rust-sdk/tests/jwe_trusted_enrollment.rs rust-sdk/tests/hibe_trusted_authority.rs`

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit clean Rust task paths as `feat(core): verify trusted principal statements`.

---

### Task 8: Add TypeScript trust and complete public enrollment parity

**Files:**
- Create: `ts-sdk/src/core/trust.ts`
- Modify: `ts-sdk/src/core/signing.ts`
- Modify: `ts-sdk/src/core/recipient_seal.ts`
- Modify: `ts-sdk/src/core/tnpkg.ts`
- Modify: `ts-sdk/src/core/results.ts`
- Create: `ts-sdk/src/runtime/enrollment.ts`
- Modify: `ts-sdk/src/runtime/reconcile.ts`
- Modify: `ts-sdk/src/runtime/jwe_group.ts`
- Modify: `ts-sdk/src/runtime/hibe_group.ts`
- Modify: `ts-sdk/src/runtime/node_runtime.ts`
- Modify: `ts-sdk/src/pkg/index.ts`
- Modify: `ts-sdk/src/admin/index.ts`
- Consume joint Task 9: `ts-sdk/src/index.ts`
- Create: `ts-sdk/test/trusted_principals.test.ts`
- Create: `ts-sdk/test/trusted_enrollment.test.ts`
- Create: `ts-sdk/test/jwe_trusted_enrollment.test.ts`
- Create: `ts-sdk/test/hibe_trusted_authority.test.ts`

**Interfaces:**

```ts
export type TrustReason =
  | "statement_invalid" | "statement_expired" | "signature_invalid"
  | "did_invalid" | "did_signer_mismatch" | "outer_inner_signer_mismatch"
  | "wrong_recipient" | "scope_mismatch" | "body_digest_mismatch"
  | "challenge_missing" | "challenge_expired" | "challenge_replayed"
  | "replay_conflict" | "binding_invalid" | "untrusted_principal"
  | "epoch_rollback" | "epoch_conflict";
export interface EnrollmentChallengeV1 {
  version: 1; kind: "tn-enrollment-challenge"; publisher_did: string;
  expected_reader_did: string; ceremony_id: string; group: string;
  nonce_b64: string; issued_at: string; expires_at: string;
  challenge_id: string; signature_b64: string;
}
export interface KeyBindingProofV1 {
  version: 1; purpose: "jwe-reader" | "hibe-reader" | "hibe-authority";
  subject_did: string; audience_did: string; ceremony_id: string; group: string;
  issued_at: string; expires_at: string; nonce_b64: string;
  binding: Record<string, unknown>; signature_b64: string;
}
export interface EnrollmentResponseV1 {
  version: 1; kind: "tn-enrollment-response"; publisher_did: string;
  reader_did: string; ceremony_id: string; group: string;
  accepted_offer_digest: string; x25519_public_key_sha256: string;
  group_epoch: number; issued_at: string; expires_at: string;
  signature_b64: string;
}
export interface VerifiedJweBinding {
  principal: VerifiedPrincipal;
  publicKey: Uint8Array;
  publicKeySha256: string;
  proofDigest: string;
  challengeDigest: string | null;
}
export interface VerifiedPrincipal {
  did: string; purpose: "jwe-reader" | "hibe-reader" | "hibe-authority";
  audienceDid: string; ceremonyId: string; group: string;
  proofDigest: string; issuedAt: string; expiresAt: string;
}
export interface AcceptedOffer {
  binding: VerifiedJweBinding;
  offerDigest: string;
  artifactDigest: string;
}
export interface ProofExpectation {
  purpose: "jwe-reader" | "hibe-reader" | "hibe-authority";
  audienceDid: string; ceremonyId: string; group: string;
  now: string; challenge?: EnrollmentChallengeV1;
}
export function parseEd25519DidKey(did: string): Uint8Array;
export function verifyKeyBindingProof(
  proof: KeyBindingProofV1,
  expected: ProofExpectation,
): VerifiedPrincipal;
export function verifyEnrollmentChallenge(
  challenge: EnrollmentChallengeV1,
  expected: {
    publisherDid: string; readerDid: string; ceremonyId: string;
    group: string; now: string;
  },
): void;
export function verifyEnrollmentResponse(
  response: EnrollmentResponseV1,
  expected: {
    publisherDid: string; readerDid: string; ceremonyId: string;
    group: string; offerDigest: string; publicKeySha256: string; now: string;
  },
): void;

PkgNamespace.issueEnrollmentChallenge(
  readerDid: string, group: string, ttlMs: number,
): Promise<EnrollmentChallengeV1>
PkgNamespace.reconcilePending(digest: string): Promise<AcceptedOffer>
PkgNamespace.approveAndReconcile(digest: string): Promise<AcceptedOffer>
PkgNamespace.offer(opts: OfferOptions & { challenge?: EnrollmentChallengeV1 }): Promise<OfferReceipt>
PkgNamespace.compileEnrolment(
  opts: CompileEnrolmentOptions & {
    acceptedOffer: AcceptedOffer; ttlMs: number;
  },
): Promise<CompiledPackage>
PkgNamespace.absorb(
  source: string | Uint8Array,
  opts?: { unsafeLegacySigner?: boolean },
): Promise<AbsorbReceipt>

AdminNamespace.addRecipient options add:
  acceptedOffer?: AcceptedOffer
  unsafeUnverified?: boolean
AdminNamespace.grantReader options add:
  proof?: KeyBindingProofV1
  allowSubauthority?: boolean
  unsafePlaintext?: boolean
AdminNamespace.issueHibeAuthorityAssertion(group: string, ttlMs: number)
  -> Promise<KeyBindingProofV1>
AdminNamespace.issueHibeReaderChallenge(group: string, readerDid: string, ttlMs: number)
  -> Promise<EnrollmentChallengeV1>
createHibeReaderProof(challenge: EnrollmentChallengeV1, reader: DeviceKey)
  -> Promise<KeyBindingProofV1>
AdminNamespace.installHibeAuthorityAssertion(options: {
  group: string; mpk: Uint8Array; assertion: KeyBindingProofV1;
  expectedAuthorityDid: string;
}) -> Promise<void>
AdminNamespace.rotateHibePathWithAssertion(group: string, newPath: string)
  -> Promise<{ group: string; idPath: string; pathEpoch: number;
    assertion: KeyBindingProofV1 }>
```

- [ ] **Step 1: Add failing vector and lifecycle tests**

The tests load the top-level shared fixtures, independently canonicalize them, and assert exact wire bytes/reasons. Until joint Task 9, import new trust types from their track-local modules; Task 9 separately tests root exports. Add a two-home public `PkgNamespace`/`AdminNamespace` JWE lifecycle through first decrypt and HIBE issuance/pin/update/grant tests, including replay, unsafe warning/audit, and ancestor opt-in.

- [ ] **Step 2: Run RED**

Run: `node --import tsx --import ./test/_setup_wasm.mjs --test test/trusted_principals.test.ts test/trusted_enrollment.test.ts test/jwe_trusted_enrollment.test.ts test/hibe_trusted_authority.test.ts` from `ts-sdk/`.

Expected: missing exports and old unbound enrollment behavior.

- [ ] **Step 3: Implement parity**

Use the strict decoder from recipient sealing as the single TS implementation. Reject extra keys before calling WASM signature verification. Implement the same locked state keys, typed binding/response checks, `<keystore>/trust/verified_publishers.v1.json`, proof/key/epoch metadata, rotation plan, and unsafe labels as Python. Preserve the existing `offer`, `absorb`, `addRecipient`, and `grantReader` surfaces by adding option fields/overloads. Unsafe paths emit the common structured warning and best-effort audit event.

- [ ] **Step 4: Run GREEN and static checks**

Run the Step 2 command.

Run: `npm run typecheck` from `ts-sdk/`.

Run: `npm run lint` from `ts-sdk/`.

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit exact clean TS paths as `feat(ts): add trusted enrollment proofs`.

---

### Task 9: Integrate the one shared native and SDK bridge

**Prerequisites:** Enrollment Tasks 7-8 and secure-read-plan Tasks 2, 5, and 6
have passing track-local tests. This is the only task that edits the shared
bridge/export files.

**Files:**
- Modify: `crypto/tn-core-ffi/src/lib.rs`
- Create: `crypto/tn-core-ffi/tests/trust_enrollment_v1.rs`
- Create: `crypto/tn-core-ffi/tests/read_options_v2.rs`
- Modify: `rust-sdk/src/lib.rs`
- Modify: `ts-sdk/src/index.ts`
- Modify: `csharp-sdk/src/TnProto/Native/NativeMethods.cs`
- Modify: `csharp-sdk/src/TnProto/Native/NativeBridge.cs`

**Interfaces:**

Every native function clears/sets the existing last-error channel, accepts
UTF-8 JSON through `*const c_char`, returns an owned `*mut c_char`, rejects
unknown fields/versions, and preserves all legacy symbols:

```rust
pub unsafe extern "C" fn tn_trust_verify_key_binding_v1(
    statement_json: *const c_char,
    expectation_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_trust_verify_enrollment_challenge_v1(
    statement_json: *const c_char,
    expectation_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_trust_verify_enrollment_response_v1(
    statement_json: *const c_char,
    expectation_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_enrollment_issue_challenge_v1(
    handle: *mut TnHandle, request_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_enrollment_reconcile_v1(
    handle: *mut TnHandle, request_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_pkg_offer_v2(
    handle: *mut TnHandle, request_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_pkg_compile_enrolment_v2(
    handle: *mut TnHandle, request_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_pkg_absorb_v2(
    handle: *mut TnHandle, request_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_admin_add_jwe_recipient_v2(
    handle: *mut TnHandle, request_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_admin_hibe_v1(
    handle: *mut TnHandle, operation: *const c_char,
    request_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_read_v2(
    handle: *const TnHandle, options_json: *const c_char,
) -> *mut c_char;
pub unsafe extern "C" fn tn_runtime_read_trust_snapshot_v1(
    handle: *const TnHandle,
) -> *mut c_char;
```

Exact request DTOs, all with `version: 1`:

```text
verify expectation:
  purpose, audience_did, ceremony_id, group, now, challenge|null
challenge expectation:
  publisher_did, reader_did, ceremony_id, group, now
response expectation:
  publisher_did, reader_did, ceremony_id, group, offer_digest,
  public_key_sha256, now
issue challenge:
  reader_did, group, ttl_seconds
reconcile:
  offer_digest, approve: bool, now
offer:
  group, publisher_did, out_path, challenge|null
compile enrolment:
  group, reader_did, out_path, accepted_offer, ttl_seconds
absorb:
  source_path, unsafe_legacy_signer
add JWE recipient accepted mode:
  mode="accepted_offer", group, accepted_offer
add JWE recipient raw mode:
  mode="raw_unsafe", group, reader_did, public_key_b64,
  unsafe_unverified=true
HIBE operation="issue_authority_assertion":
  group, ttl_seconds
HIBE operation="issue_reader_challenge":
  group, reader_did, ttl_seconds
HIBE operation="install_authority_assertion":
  group, mpk_b64, assertion, expected_authority_did, now
HIBE operation="rotate_path":
  group, new_path
HIBE operation="grant_reader":
  group, reader_did, out_path, id_path|null, proof,
  allow_subauthority, unsafe_plaintext
read:
  all_runs, verify="auto|raise|skip|disabled",
  require_signature: bool|null, allow_unauthenticated: bool|null,
  trusted_writers: [string]|null, allow_unknown_writers,
  required_group: string|null, cursor: ReadCursorV1|null
```

All responses are `{ "version": 1, "result": <typed result> }`; trust rejection
uses `{ "version": 1, "result": null, "reason": "<stable code>" }`. The read
result is `{ entries, scanned, yielded, skipped, cursor: ReadCursorV1 }`. The
trust snapshot result is `{ writers: [{ did, source }] }`, where source is one
of the three design values. `ReadCursorV1` uses the exact versioned multi-source
shape in the design/secure-read plan.

- [ ] **Step 1: Write failing bridge and ABI-compatibility tests**

Test every DTO's success, unknown-field/version rejection, stable reason, null
handling, raw-unsafe flag enforcement, and returned typed shape. Link/call every
legacy symbol to prove no ABI removal. Compile the generated C# P/Invokes and
assert TS/Rust root exports resolve.

- [ ] **Step 2: Run RED**

Run: `cargo test -p tn-core-ffi --test trust_enrollment_v1 --test read_options_v2`

Expected: new symbols are absent.

- [ ] **Step 3: Implement both tracks in one bridge edit**

Delegate immediately into the already-tested track-local typed APIs. Do not
duplicate DID parsing, policy evaluation, or enrollment state logic in FFI.
Keep C# JSON serialization centralized in `NativeBridge` and use unmapped-member
rejection on typed responses.

- [ ] **Step 4: Run GREEN and compile every consumer**

Run: `cargo test -p tn-core-ffi --test trust_enrollment_v1 --test read_options_v2`

Run: `cargo test -p tn-proto --lib`

Run: `npm run typecheck` from `ts-sdk/`.

Run: `dotnet build csharp-sdk/TnProto.sln`

Run: `rustfmt --edition 2021 --check crypto/tn-core-ffi/src/lib.rs crypto/tn-core-ffi/tests/trust_enrollment_v1.rs crypto/tn-core-ffi/tests/read_options_v2.rs rust-sdk/src/lib.rs`

Expected: pass.

- [ ] **Step 5: Checkpoint**

The root integration owner reviews/stages only these shared paths.

---

### Task 10: Expose C# trust and complete public enrollment parity

**Files:**
- Create: `csharp-sdk/src/TnProto/Trust/TrustReason.cs`
- Create: `csharp-sdk/src/TnProto/Trust/EnrollmentChallengeV1.cs`
- Create: `csharp-sdk/src/TnProto/Trust/KeyBindingProofV1.cs`
- Create: `csharp-sdk/src/TnProto/Trust/EnrollmentResponseV1.cs`
- Create: `csharp-sdk/src/TnProto/Trust/VerifiedPrincipal.cs`
- Create: `csharp-sdk/src/TnProto/Trust/VerifiedJweBinding.cs`
- Create: `csharp-sdk/src/TnProto/Trust/AcceptedOffer.cs`
- Create: `csharp-sdk/src/TnProto/Trust/ProofExpectation.cs`
- Create: `csharp-sdk/src/TnProto/Trust/ChallengeExpectation.cs`
- Create: `csharp-sdk/src/TnProto/Trust/ResponseExpectation.cs`
- Create: `csharp-sdk/src/TnProto/TnTrust.cs`
- Modify: `csharp-sdk/src/TnProto/Packages/OfferOptions.cs`
- Modify: `csharp-sdk/src/TnProto/Packages/CompileEnrolmentOptions.cs`
- Create: `csharp-sdk/src/TnProto/Packages/PackageAbsorbOptions.cs`
- Modify: `csharp-sdk/src/TnProto/Packages/PackageClient.cs`
- Create: `csharp-sdk/src/TnProto/Admin/GrantReaderOptions.cs`
- Modify: `csharp-sdk/src/TnProto/Admin/AdminClient.cs`
- Consume joint Task 9: `csharp-sdk/src/TnProto/Native/NativeMethods.cs`
- Consume joint Task 9: `csharp-sdk/src/TnProto/Native/NativeBridge.cs`
- Create: `csharp-sdk/tests/TnProto.Tests/TrustedPrincipalTests.cs`
- Create: `csharp-sdk/tests/TnProto.Tests/TrustedEnrollmentTests.cs`
- Create: `csharp-sdk/tests/TnProto.Tests/JweTrustedEnrollmentTests.cs`
- Create: `csharp-sdk/tests/TnProto.Tests/HibeTrustedAuthorityTests.cs`

**Interfaces:**

```csharp
public static class TnTrust
{
    public static VerifiedPrincipal VerifyKeyBinding(
        KeyBindingProofV1 proof,
        ProofExpectation expected,
        DateTimeOffset now);
    public static void VerifyEnrollmentChallenge(
        EnrollmentChallengeV1 challenge,
        ChallengeExpectation expected);
    public static void VerifyEnrollmentResponse(
        EnrollmentResponseV1 response,
        ResponseExpectation expected);
    public static KeyBindingProofV1 CreateHibeReaderProof(
        EnrollmentChallengeV1 challenge,
        DeviceIdentity reader,
        DateTimeOffset now);
}

VerifiedPrincipal fields:
  Did, Purpose, AudienceDid, CeremonyId, Group, ProofDigest, IssuedAt, ExpiresAt
AcceptedOffer fields:
  Binding, OfferDigest, ArtifactDigest

PackageClient additions:
  IssueEnrollmentChallengeAsync(
    string readerDid, string group, TimeSpan ttl, CancellationToken token = default)
    -> Task<EnrollmentChallengeV1>
  ReconcilePendingAsync(string digest, CancellationToken token = default)
    -> Task<AcceptedOffer>
  ApproveAndReconcileAsync(string digest, CancellationToken token = default)
    -> Task<AcceptedOffer>
  OfferAsync accepts OfferOptions.Challenge: EnrollmentChallengeV1?
  CompileEnrolmentAsync requires CompileEnrolmentOptions.AcceptedOffer and Ttl
  AbsorbAsync accepts PackageAbsorbOptions.UnsafeLegacySigner (default false)

AdminClient additions:
  AddJweRecipientAsync(string group, AcceptedOffer accepted,
    CancellationToken token = default)
  AddJweRecipientRawUnsafeAsync(string group, string readerDid,
    byte[] publicKey, bool unsafeUnverified,
    CancellationToken token = default)
  IssueHibeAuthorityAssertionAsync(string group, TimeSpan ttl,
    CancellationToken token = default)
  InstallHibeAuthorityAssertionAsync(string group, byte[] mpk,
    KeyBindingProofV1 assertion, string expectedAuthorityDid,
    CancellationToken token = default)
  IssueHibeReaderChallengeAsync(string group, string readerDid, TimeSpan ttl,
    CancellationToken token = default)
  RotateHibePathWithAssertionAsync(string group, string newPath,
    CancellationToken token = default)
  GrantReaderAsync(string group, string readerDid, string outPath,
    GrantReaderOptions options, CancellationToken token = default)

GrantReaderOptions fields:
  string? IdPath
  KeyBindingProofV1? Proof
  bool AllowSubauthority
  bool UnsafePlaintext
```

- [ ] **Step 1: Add failing tests**

Consume the same top-level fixture files, assert canonical bytes and exact `TrustReason`, and verify C# calls the Rust FFI rather than implementing a second DID decoder. At `PackageClient`/`AdminClient`, create the C# reader key/proof/offer, verify and absorb a publisher response, then open a fixture publisher ciphertext with C#'s managed `JweSealedGroupCipher`. Task 12 replaces that fixture publisher with live Python/TypeScript publishers. Run HIBE assertion issue/pin/update and fail-closed grant tests, including unsafe warning/audit and ancestor opt-in.

- [ ] **Step 2: Run RED**

Run: `dotnet test csharp-sdk/TnProto.sln --filter "FullyQualifiedName~TrustedPrincipalTests|FullyQualifiedName~TrustedEnrollmentTests|FullyQualifiedName~JweTrustedEnrollmentTests|FullyQualifiedName~HibeTrustedAuthorityTests"`

Expected: missing typed C# trust/enrollment wrappers and public lifecycle methods; Task 9 native symbols already link.

- [ ] **Step 3: Implement typed wrappers**

P/Invoke the exact versioned functions installed by the integration owner in Task 9. Deserialize with unmapped-member rejection. Surface stable reason strings through a typed exception/result without translating them. Preserve existing `OfferAsync`, `CompileEnrolmentAsync`, `AbsorbAsync`, and `GrantReaderAsync` signatures through option additions/overloads. Accepted responses install the same `<keystore>/trust/verified_publishers.v1.json` record consumed by native read trust. All unsafe options raise the Foundation-owned `Tn.SecurityWarning` event exactly once; the invoked native mutation owns the single best-effort audit event.

- [ ] **Step 4: Run GREEN**

Run the Step 2 command and `dotnet test csharp-sdk/TnProto.sln`.

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit exact clean C# paths as `feat(csharp): expose trusted principal verification`.

---

### Task 11: Document the complete safe ceremonies and compatibility boundaries

**Prerequisites:** Enrollment Task 10 and secure-read plan Task 7 are GREEN.
This is the one joint documentation owner for both workstreams.

**Files:**
- Integration owner modifies: `docs/guide/jwe-hibe-key-ceremonies.md`
- Integration owner modifies: `docs/guide/jwe-howto.md`
- Integration owner modifies: `docs/guide/hibe-howto.md`
- Integration owner modifies: `docs/guide/groups-readers-rotation.md`
- Integration owner modifies: `docs/guide/protocol.md`
- Integration owner modifies: `docs/guide/getting-started.md`
- Integration owner modifies: `README.md`
- Integration owner modifies: `python/README.md`
- Integration owner modifies: `ts-sdk/README.md`
- Integration owner modifies: `python/tests/test_key_ceremony_docs.py`

**Interfaces:**
- Documents the exact safe APIs from Tasks 2-10 plus the secure-read plan.
- Names `unsafe_unverified=True`, `unsafe_legacy_signer=True`, `unsafe_plaintext=True`, and `allow_subauthority=True` only as explicit migration/compatibility/delegation controls.

- [ ] **Step 1: Extend the failing documentation contract**

Assert the challenge/proof/response/first-decrypt sequence, complete Ed25519 DID examples, MPK assertion/pin/path epoch, fail-closed grants, rotation re-enrollment, and the unaudited warning. Also assert `read()` remains the primary surface and defaults to automatic integrity/authentication/authorization; docs distinguish authentication from authorization, list every tuning parameter, require both unsigned overrides for foreign input, explain the common warning/audit event, and describe `secure_read()` as a strict delegate.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_key_ceremony_docs.py -q`

Expected: new lifecycle/API assertions fail.

- [ ] **Step 3: Update docs with runnable examples**

Use generated full DIDs, reader-owned X25519 keys, publisher challenges, proof absorption, and a first-decrypt check. Never instruct exporting the publisher's `.jwe.mykey`. Explain that HIBE reader keys are bearer capabilities and ancestor keys are delegated subauthorities. Lead read documentation with unchanged `read()` usage, then show `verify="skip"`, explicit `verify=False`, unsigned-profile controls, `trusted_writers`, and `allow_unknown_writers`. State that disabling verification never bypasses parsing/AAD and never authenticates or authorizes the envelope DID.

- [ ] **Step 4: Run GREEN and link checks**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_key_ceremony_docs.py -q`

Run in PowerShell: `$hits = rg -n "did:key:z[.][.][.]|bundle_for_recipient.*JWE|implicit plaintext" docs python/README.md ts-sdk/README.md; if ($LASTEXITCODE -eq 0) { $hits; throw 'unsafe documentation claim found' } elseif ($LASTEXITCODE -ne 1) { throw 'rg failed' }`

Expected: pytest passes; search finds no abbreviated operational DID or false JWE/plaintext claim.

---

### Task 12: Cross-SDK integration, compatibility, and final verification

**Files:**
- Create: `python/tests/test_enrollment_read_trust_integration.py`
- Create: `python/tests/test_trusted_enrollment_ts_interop.py`
- Create: `ts-sdk/test/enrollment_read_trust.test.ts`
- Create: `ts-sdk/test/trusted_enrollment_python_interop.test.ts`
- Create: `csharp-sdk/tests/TnProto.Tests/EnrollmentReadTrustTests.cs`
- Create: `csharp-sdk/tests/TnProto.Tests/TrustedEnrollmentInteropTests.cs`
- Modify only tests needed to fix verified integration defects; production fixes return to their owning task.

- [ ] **Step 1: Regenerate and prove fixture stability**

Run: `.\.venv\Scripts\python.exe tools/fixtures/build_trust_v1.py --check`

Expected: exit 0 with no changed files.

- [ ] **Step 2: Run focused Python security suite**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_trust_fixture_generator.py python/tests/test_security_audit_contract.py python/tests/test_trusted_principals.py python/tests/test_key_binding_wire.py python/tests/test_manifest_contract.py python/tests/test_tnpkg_container_contract.py python/tests/test_enrollment_state.py python/tests/test_jwe_trusted_enrollment_e2e.py python/tests/test_jwe_rotation_reenrollment.py python/tests/test_package_identity_binding.py python/tests/test_hibe_authority_trust.py python/tests/test_hibe_grant_absorb.py python/tests/test_hibe_external_writer_rotation.py python/tests/test_enrollment_read_trust_integration.py python/tests/test_trusted_enrollment_ts_interop.py python/tests/test_key_ceremony_docs.py -q`

Expected: pass.

- [ ] **Step 3: Run Rust, TypeScript, and C# suites**

Run: `cargo test -p tn-core -p tn-core-ffi -p tn-core-py`

Run: `cargo test -p tn-proto --test trusted_enrollment --test jwe_trusted_enrollment --test hibe_trusted_authority`

Run: `npm run typecheck` from `ts-sdk/`.

Run: `npm run lint` from `ts-sdk/`.

Run: `node --import tsx --import ./test/_setup_wasm.mjs --test test/trusted_principals.test.ts test/trusted_enrollment.test.ts test/jwe_trusted_enrollment.test.ts test/hibe_trusted_authority.test.ts test/enrollment_read_trust.test.ts test/trusted_enrollment_python_interop.test.ts` from `ts-sdk/`.

Run: `dotnet test csharp-sdk/TnProto.sln`

Expected: all pass.

The cross-workstream tests install a verified publisher through enrollment,
then prove default `read()` authorizes that publisher; an unverified unsafe raw
recipient/contact record must not enter the trusted-writer set.

The interop tests exchange actual `.tnpkg` artifacts through temporary files:
Python publisher -> TypeScript reader, TypeScript publisher -> Python reader,
and Python plus TypeScript publishers -> C# reader. Each flow covers challenge,
offer, atomic approval, response, seal, and first decrypt while asserting the
reader's private key never appears in a handoff artifact.

- [ ] **Step 4: Verify unsafe-path observability and no secret leakage**

Run targeted tests with log capture and inspect generated packages. Assert unsafe calls emit both a warning and audit event; normal packages contain no X25519 private key, no HIBE master secret, and no plaintext `.hibe.sk`. A normal HIBE grant does contain recipient-encrypted `.hibe.sk` bearer material and only the addressed DID can unseal it. Assert no unrelated verification public key is accepted as identity.

- [ ] **Step 5: Review the dirty worktree safely**

Run: `git diff --check`

Run: `git status --short`

Review each owned path against its recorded baseline. Do not stage or alter unrelated changes. Invoke superpowers:requesting-code-review, address findings, then invoke superpowers:verification-before-completion and rerun every command whose affected files changed.
