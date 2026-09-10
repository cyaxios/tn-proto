# Trusted Principal Enrollment Task 2 Report

## Status

- Status: complete
- BASE: `a8822095e7bb2ee13e4c11e8597d605e45f2fddb`
- HEAD: `47bcea1e67443b5a8d4894beabf132a36f3be2aa`
- Commit: `47bcea1e67443b5a8d4894beabf132a36f3be2aa` (`feat: add strict trusted principal proofs`)
- Independent review: Spec PASS, Quality PASS, Findings None, Ready to commit Yes

## Committed files

Exactly these six paths were staged and committed:

- `python/tn/trust.py`
- `python/tn/key_binding.py`
- `python/tn/recipient_seal.py`
- `python/tn/signing.py`
- `python/tests/test_trusted_principals.py`
- `python/tests/test_key_binding_wire.py`

This report is intentionally uncommitted. No Foundation fixture or read-track path was edited or staged.

## TDD evidence

Focused RED command:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_trusted_principals.py python/tests/test_key_binding_wire.py -q
```

Initial result: exit 1 during collection with two expected errors, both
`ModuleNotFoundError: No module named 'tn.key_binding'`.

Additional review-driven RED/GREEN cycles:

- Immutable binding snapshot test: RED because mutating `proof.binding` did not raise; GREEN after snapshotting into `MappingProxyType`.
- Exact direct-object version test: six RED cases for `True` and `1.0`; six GREEN cases after exact integer guards in challenge, proof, and response validation.
- Backward-compatible malformed-DID test: initially 29 passed / 1 failed because `_b58decode` leaked `ValueError`; GREEN after `DeviceKey.verify` retained its boolean contract.

Final exact GREEN/regression command:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_trusted_principals.py python/tests/test_key_binding_wire.py python/tests/test_sealed_tnpkg_package_contract.py -q
```

Result: `39 passed in 0.37s`.

Additional regressions:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_recipient_wrap_contract.py python/tests/test_awk_pickup.py python/tests/test_kit_bundle_sealed.py python/tests/test_multi_curve_verify.py python/tests/test_verify_roundtrip.py python/tests/test_signing_flag.py -q
```

Result: `37 passed in 2.17s`.

## Fixture and contract coverage

- All six accepted `signed_statements.json` vectors verify: two enrollment challenges, JWE reader proof, HIBE reader proof, HIBE authority proof, and enrollment response.
- Exact canonical signing bytes are asserted for every accepted challenge, proof, and response kind.
- All eight negative signed-statement vectors map to their exact fixture reason: unknown field, unsupported version, expiry, mutated signature, signer mismatch, wrong recipient, scope mismatch, and binding mismatch.
- All Ed25519 DID fixture vectors cover strict base58btc, multicodec, and 32-byte public-key parsing.
- Purpose-specific binding validation covers exact fields, algorithms, X25519 decoded length, HIBE recipient-seal delivery, HIBE path/depth/epoch fields, and MPK digest-to-expected-bytes comparison at the fixture-consumer boundary.
- Reader proof acceptance requires a verified, fresh, audience-signed challenge with an exact full-statement digest binding.
- UTC awareness, canonical `Z` timestamps, time ordering, not-yet-valid rejection, and expiry are covered.
- Returned proof bindings are defensive immutable snapshots, preventing Mapping mutation/TOCTOU after signature verification.
- `DeviceKey.verify` remains boolean and multi-curve; ceremony paths use strict Ed25519 verification.

## Static and deterministic checks

- `tools/fixtures/build_trust_v1.py --check`: exit 0, no fixture changes.
- Scoped `ruff check` on all six paths: all checks passed.
- Scoped `ruff format --check` on all six paths: six files already formatted.
- Scoped `py_compile`: exit 0.
- Cached path allowlist: exactly the six committed paths.
- Cached diff check: clean using Git `core.whitespace=cr-at-eol` because the two legacy source blobs use CRLF.

## Inherited recipient-seal delta

Before Task 2 began, `python/tn/recipient_seal.py` already contained the approved one-line documentation change removing the unsupported word `audited` before
`crypto_sign_ed25519_pk_to_curve25519`. That inherited delta was preserved and is included in the scoped commit. Ruff also applied mechanical line wrapping within this task-owned file; behavior is covered by the recipient-seal regressions above.

## Deviations and residual risks

- No API deviations from the brief.
- The fixed `KeyBindingProofV1.sign(key)` interface has no challenge argument, so challenge verification cannot be encoded as method-local state without hidden global state. The implemented trust boundary enforces challenge verification in `verify_key_binding_proof` before reader-proof acceptance, and the signing workflow test verifies the expected publisher challenge before signing.
- The fixed generic proof verifier has no expected-MPK argument. It authenticates the signed HIBE MPK digest and strict binding shape; fixture-consumer coverage separately hashes the expected 96-byte MPK and compares it to that digest.
- No known outstanding correctness or security findings after independent review.
