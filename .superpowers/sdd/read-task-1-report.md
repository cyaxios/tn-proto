# Secure-Default Read Task 1 Report

## Status

Complete and committed. Task 1 defines the pure Python secure-default read
policy/decision table and receiver-local trust-provider boundary. The accepted
Foundation matrix is consumed without fixture changes, and no existing read
surface, enrollment path, or later secure-read task was started.

## Git

- BASE: `a8822095e7bb2ee13e4c11e8597d605e45f2fddb`
- Shared-checkout parent after Enrollment Task 2 checkpoint:
  `47bcea1e67443b5a8d4894beabf132a36f3be2aa`
- Task 1 HEAD / commit: `87ad1fdb1a977dcaf69ae950a4c739e25e2cca44`
- Subject: `feat(read): define secure default trust policy`
- The commit contains exactly the four authorized implementation/test paths.
  This report remains outside the commit as required.

## Exact files

- `python/tn/read_policy.py`
- `python/tn/read_trust.py`
- `python/tests/test_read_trust_policy.py`
- `python/tests/test_read_trust_provider.py`

Consumed without modification:

- `tests/fixtures/trust/v1/read_policy_matrix.json`

## RED evidence

- Required initial command:
  `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_trust_policy.py -q`
  exited 1 during collection with
  `ModuleNotFoundError: No module named 'tn.read_policy'`.
- Provider integration-boundary regression:
  `test_local_provider_does_not_assume_an_enrollment_owned_schema_label`
  initially failed because the reader rejected an outer schema label not
  defined by the Task 1 brief. The provider now consumes only the exact-DID
  registry boundary and does not couple to enrollment DTO metadata.
- Invalid-signature security regression:
  `test_allow_unauthenticated_never_accepts_a_present_invalid_signature`
  initially failed with `accepted=True` and reason `signature_invalid`.
  `allow_unauthenticated` now permits an unsigned envelope only; a present
  invalid signature remains rejecting unless verification is explicitly
  disabled with `verify=False`.
- Detached-chain security regression:
  `test_detached_read_does_not_inherit_local_unchained_profile` initially
  returned `accepted=True`, no reasons, and `writer_authorized=True` for an
  invalid chain. `profile_chain=False` is now honored only for an active,
  attached local log.

## GREEN and quality evidence

- Required focused command:
  `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_trust_policy.py python/tests/test_read_trust_provider.py -q`
  — 79 passed.
- Foundation generator:
  `.\.venv\Scripts\python.exe tools/fixtures/build_trust_v1.py --check`
  — exit 0 with no fixture drift.
- `ruff 0.15.12 check --config python/pyproject.toml` on all four exact Python
  paths — all checks passed.
- `ruff 0.15.12 format --check --config python/pyproject.toml` on all four
  exact Python paths — four files already formatted.
- `.\.venv\Scripts\python.exe -m compileall -q` on both implementation modules
  — exit 0.
- Pre-checkpoint no-index whitespace checks on each new file and
  `git diff --cached --check` on the four-path staged checkpoint — exit 0.
- Independent read-only review against the full Task 1 brief returned spec
  PASS, quality PASS, no findings, and `Ready to commit: Yes`.

## Fixture and contract coverage

- All 33 accepted `read_policy_matrix.json` cases execute through the public
  `ReadTrustPolicy.resolve(...).evaluate(...)` contract with exact resolved
  mode, acceptance, ordered reasons, authentication, and authorization.
- Public verification coverage includes `auto`, `raise`, `skip`, `True`, and
  `False`; `auto` freezes to `raise`, `False` freezes to internal `disabled`,
  and public string `"disabled"` is rejected.
- Matrix coverage includes local signed and profile-unsigned logs, trusted and
  unknown foreign writers, context-free unsigned input, row-hash/chain/
  signature failures, malformed records, AAD failure, required-recipient
  failure, explicit trust overrides, skip mode, ordered multiple reasons, and
  disabled-mode hard versus bypassable failures.
- Additional policy regressions cover invalid runtime verify values (including
  integer `0`/`1`), empty explicit writer overrides with `verify=False`, frozen
  policy/provider snapshots, first-reason ordering, invalid signed input under
  unsigned permission, optional hidden groups, and detached sign/chain profile
  isolation.
- Provider coverage proves canonical Ed25519-only DIDs for local, explicit
  config, private verified-package, and injected in-memory sources; exact
  source labels and precedence; exact-key lookup with no normalization; the
  precise `<keystore>/trust/verified_publishers.v1.json` path; construction-time
  caching; and malformed configuration/private-record rejection.

## Implementation notes

- `ReadTrustPolicy` is frozen and contains only resolved values. It performs no
  global configuration reads; all source state enters through `ReadContext` and
  its injected `ReadTrustProvider`.
- Reasons are stable `ReadRejectReason` values, appended in frozen order and
  de-duplicated. `ReadDecision.first_reason` exposes the callback/exception
  reason without recomputation.
- Authentication, authorization, and acceptance remain independent. Unsigned
  input is never authenticated; unsigned or active integrity-failed input is
  never authorized; AAD/recipient failures can preserve the separately proven
  writer authorization metadata while still rejecting the record.
- Disabled mode reports underlying integrity/authentication/authorization
  reasons but zeroes both trust claims. It can never accept `record_invalid`,
  `aad_invalid`, or an explicitly required `not_a_recipient` result.
- Local trust is snapshotted into a read-only exact-DID map. Source precedence
  is local device, then verified package, then explicit configuration.

## Deviations and risks

- No owned-scope deviation occurred, and no fixture or existing read/enrollment
  file was edited.
- The brief freezes the verified-publisher path and exact-DID lookup contract,
  but not an enrollment persistence DTO or outer schema label. The provider
  therefore accepts an exact-DID mapping either under `publishers` or directly
  at the document root and deliberately ignores unrelated outer metadata.
  Later enrollment persistence must preserve that exact-key registry boundary.
- Ruff is not installed in the repository virtualenv, so the scoped checks used
  the available `ruff 0.15.12` executable with the repository's exact
  `python/pyproject.toml` configuration.
- The shared checkout advanced through the separately owned Enrollment Task 2
  commit before this checkpoint. Shared-index coordination was observed; the
  Task 1 commit itself contains only its four explicit paths, and unrelated
  dirty work remains unstaged and untouched.
- No known Task 1 implementation risk remains. Task 2 of the secure-default
  read plan was not started.
