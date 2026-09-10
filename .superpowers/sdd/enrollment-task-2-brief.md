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

