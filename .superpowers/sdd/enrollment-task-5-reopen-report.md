# Trusted Principal Enrollment Task 5 Reopen Report

## Status

- Status: collision-free Python JWE phases implemented and adversarial-review
  findings remediated; awaiting independent re-review before the shared
  `admin/__init__.py`, `cipher.py`, `export.py`, and `recipient_seal.py`
  integration boundary is released.
- Shared HEAD observed during this checkpoint:
  `a90b2d280115c00a4d0c3ba83bbf67aa5a070579`.
- This agent ran no staging or commit command. The shared index is empty.
- No HIBE-owned file was edited by this agent.

## Collision-free implementation

- `packaging.verify` now requires the raw Ed25519 package signer to match the
  claimed complete `did:key`. Identity-unbound signature checking is private
  and used only by the explicit legacy-import compatibility path.
- `offer` verifies a publisher challenge before reader-key or enrollment-state
  mutation, scopes the offer to the publisher ceremony/group, signs a JWE
  `KeyBindingProofV1`, reuses one reader X25519 key unless rotation is explicit,
  and durably prepares exact offer state/artifact before outbox publication.
- `PendingOffer`, `AbsorbReceipt`, and legacy `AbsorbResult` carry exact offer,
  artifact, and reader identifiers needed by public approval/reconcile flows.
- `compile_enrolment` requires one durably reverified `AcceptedOffer` and signs
  an `EnrollmentResponseV1` binding publisher, reader, ceremony, group, offer
  digest, reader-key digest, and group epoch.
- Reader response absorption cross-checks the outer manifest, inner package,
  response signer/recipient/scope/epoch, retained outbound offer, and the public
  key derived from the existing local `.jwe.mykey` before any mutation.
- Authenticated publisher installation uses a durable prepare record followed
  by atomic idempotent YAML, sender-public-key, and
  `trust/verified_publishers.v1.json` writes; the accepted marker is last.
  Exact replay is a no-op, interrupted writes recover on retry, and corrupt or
  conflicting prepared state fails closed. No reader private key is retained in
  response state.
- `absorb(..., unsafe_legacy_signer=True)` is the only compatibility path for a
  legacy package signed by a key unrelated to its claimed DID. It verifies the
  raw signature first, emits the shared warning/audit payload, and records the
  legacy offer as `verified: false`. A malformed signature cannot downgrade.
- Enrollment consumed-marker paths now accept the frozen portable challenge-ID
  grammar `[A-Za-z0-9._-]{1,128}` instead of UUID-only IDs. When both a retained
  challenge and its proof have lapsed, the state machine reports
  `challenge_expired` before proof `statement_expired`, while consumed/replay
  precedence remains intact.

## Adversarial review remediation

The first independent review returned **Not Ready** with four concrete
boundary failures and one recovery-usability gap. Each received a focused RED
test before the production change:

- Response-less legacy enrollment is rejected by default for both wrapped and
  flat packages. The compatibility path is separately named
  `unsafe_legacy_enrollment=True`; it is not implied by
  `unsafe_legacy_signer=True`. Before its warning or mutation it still requires
  a complete DID-bound signature, exact local recipient, matching outer/inner
  signer, recipient, ceremony, and group when an outer manifest exists, a
  portable group, nonnegative epoch, and canonical 32-byte sender key. The
  installed group is explicitly `verified: false`, and the warning/audit uses
  `legacy_package_import` plus `unverified_key_binding`. Foreign or malformed
  packages never reach the unsafe mutation.
- Every JWE enrollment group that can reach filesystem or configuration state
  now passes one shared portable-component validator. It accepts 1-128 ASCII
  letters/digits plus interior dot, underscore, and hyphen, and rejects path
  separators, absolute/drive syntax, whitespace, dot components, trailing dot,
  and Windows device names. `offer`, outbound state, publisher state,
  `EnrollmentStore`, response installation, and the unsafe legacy importer all
  use the same validator before mutation.
- Exact durable response prepares can recover after response expiry. Recovery
  first requires every response/sender/state field except `verified_at` to
  equal the retained prepare, then re-verifies the signed response at the
  canonical original `verified_at` instant. A new expired response still gets
  `statement_expired`; a conflict still gets `replay_conflict`.
- Flat legacy file and bytes inputs use the same 1 MiB bounded enrollment read
  before UTF-8/JSON decoding. Wrapped offers and enrollments are likewise
  subjected to compact enrollment archive quotas before body inflation. The
  bounded bytes are the exact snapshot subsequently verified, dispatched, and
  hashed for audit, so a path replacement cannot apply one package under
  another package's digest.
- Outbound publication now writes a durable exact-digest publication marker.
  A repeated public `offer(...)` call first looks for a matching
  prepared-but-unpublished artifact, re-verifies its manifest, package,
  challenge/proof, scope, DID, and current reader public key, publishes those
  exact bytes, and returns the retained package. Exact prepared recovery remains
  available after challenge expiry because the retained proof is reverified at
  its original valid instant; an expired challenge without a matching prepare
  still rejects before key mutation. This also prevents a failed
  `rotate_reader_key=True` call from rotating the key again on retry. A fully
  published marker leaves later explicit calls free to create a new offer.

## TDD evidence

The response/legacy RED set initially produced five expected failures:

```text
reader trust record missing
response key mismatch incorrectly applied
outer/inner signer mismatch incorrectly applied
exact response replay incorrectly re-applied
unsafe legacy signer produced no warning
```

After the first implementation, a corruption test proved a modified durable
prepare record could redirect recovery; it failed because the retry returned
`enrolment_applied`. The implementation now compares every authenticated field
except the original verification timestamp before recovery.

The frozen carry-forward RED set produced:

```text
2 failed, 9 passed
- expired challenge + expired proof returned statement_expired
- fixture challenge-... ID was rejected as a non-UUID
```

Both are green after the narrow state-machine changes.

The adversarial remediation RED gate produced:

```text
31 failed, 79 passed
- response-less enrollment changed reader state without a response proof
- signed group strings escaped the reader keystore / reached Windows paths
- exact prepared response recovery failed after statement expiry
- oversized flat packages bypassed the 1 MiB enrollment quota
- public offer retry minted a different artifact and rotated twice
```

After the five narrow fixes, that focused set was `110 passed`. A follow-up
recovery test then proved current-time challenge expiry still preempted exact
prepared publication (`1 failed`); moving only exact retained recovery behind a
historical signature/scope check made the focused set `111 passed`.
One final TOCTOU RED swapped the source after the bounded read and demonstrated
that the old dispatcher could apply the replacement bytes under the first
artifact's audit digest. Dispatch now consumes the exact retained snapshot, and
the focused set is `112 passed`.

## Current verification

- Fresh expanded collision-free gate: `182 passed, 1 deselected in 29.46s`.
  The one deliberate deselection is the known shared-admin collision
  `test_absorb_enrolment_makes_recipient_read`, whose historical raw recipient
  path calls strict `compile_enrolment` without an `AcceptedOffer`.
- Frozen fixture generator: `tools/fixtures/build_trust_v1.py --check` passed.
- Security-audit and deterministic-fixture contract gate: `12 passed`.
- Scoped Ruff: `All checks passed!`.
- Scoped `compileall`: passed.
- Scoped `git diff --check`: no whitespace errors (Git printed only existing
  LF/CRLF working-copy warnings).

## Remaining shared-file work

After HIBE releases the shared paths, Task 5 still needs:

1. make normal JWE `add_recipient` consume only the exact durable
   `AcceptedOffer`, atomically persist verified recipient metadata, and compile
   the response from that same value;
2. retain raw DID/public-key registration only behind
   `unsafe_unverified=True`, with the common warning/audit event and
   `verified: false` state;
3. update the historical raw enrolment test to the authenticated flow and prove
   publisher seal -> reader first decrypt without private-key transfer; and
4. implement JWE rotation's inactive
   `<group>.jwe.reenrollment.v1.json` plan while resetting active recipients to
   publisher-only and never silently restoring old reader keys.
