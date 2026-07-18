# Trusted Principal Enrollment Task 6 Reopen Report

## Status

- Status: Python HIBE authority authentication, reader admission, and honest
  rotation/revocation semantics are implemented; both independent-review
  remediation rounds are complete and ready for final re-review.
- Task-start base: `b3dd68058ee7bc284e4608d274e7a416a80f592f`.
- Shared HEAD at final report time:
  `53638f0a89ed1b812dd5c53c4a38b1cb41111dd5`. Other agents advanced the
  shared branch while this review continued. This subagent ran no staging or
  commit command; the index is empty.
- At task start, every Task 6 HIBE-owned production/test path was clean. The
  checkout was already dirty in Task 4/read/JWE paths; those edits were
  preserved and not reverted.
- HIBE remains explicitly evaluation-only: neither this scheme nor its pairing
  implementation should be represented as audited or production-approved.

The earlier checkpoint `a84c135` was titled as though this task were complete,
but its changes were predominantly Rust/runtime compatibility work plus the
legacy Python grant/walkthrough surface. The approved Python APIs for signed
authority assertions, external-writer pinning, scoped reader proof, and
epoch-bearing rotation were absent. The prescribed suite initially confirmed
that gap with 14 failures and 12 passes.

## Exact owned paths

Production:

- Modified `python/tn/admin/__init__.py`.
- Modified `python/tn/cipher.py`.
- Modified `python/tn/export.py` under controller-approved scope solely to add
  typed internal manifest-state augmentation.
- Modified `python/tn/recipient_seal.py` documentation to remove the implication
  that an unresolvable DID permits automatic plaintext fallback.
- `python/tn/key_binding.py` required no Task 6 diff because the shared trust
  wire types and verifiers already supported the necessary signed statements.

Tests and executable walkthrough:

- Created `python/tests/test_hibe_authority_trust.py`.
- Created `python/tests/test_hibe_external_writer_rotation.py`.
- Modified `python/tests/test_hibe_grant_absorb.py`.
- Modified `python/tests/test_hibe_boundary.py`.
- Modified `python/tests/test_hibe_revoke.py`.
- Modified `python/tests/test_cipher_hibe.py`.
- Modified `python/tests/test_hibe_aad.py`.
- Modified `python/tests/test_hibe_lifecycle.py`.
- Modified `python/tests/test_hibe_rotation.py`.
- Modified `python/tests/test_keybag_multi_cipher.py`.
- Modified `python/tests/test_rotation_reload_failure.py`.
- Modified `python/tests/demo_hibe_walkthrough.py`.
- Created this report.

No fixture, Rust, TypeScript, JWE enrollment, read-policy, absorb, packaging, or
offer path was changed by this subagent.

## Implemented authority and external-writer contract

- `issue_authority_assertion` signs the authority DID, exact writer audience,
  ceremony/group, MPK SHA-256, MPK-encoded maximum depth, exact identity path,
  path epoch, and freshness window. `audience_did` is additive and defaults only
  to the self-authority convenience case.
- `install_authority_assertion` requires an explicit real
  `expected_authority_did`, verifies signature/freshness and exact scope, checks
  the raw MPK against its signed digest and encoded depth, and persists the
  authenticated writer pin under a lock with durable atomic writes.
- External HIBE writers cannot seal merely because raw MPK/path files exist.
  Every seal checks the committed pin, material/path/epoch equality, and
  assertion expiry. Same-epoch identical-material renewal is accepted; its
  expiry error correctly asks for a fresh assertion/update rather than falsely
  demanding a higher epoch.
- Exact assertion replay is idempotent and repairs drifted public files.
  Same-epoch material changes are `epoch_conflict`; lower epochs are
  `epoch_rollback`.
- A fresh external staging operation removes stale MSK, reader SK, delegated
  prior SKs, and path history from an earlier local-authority incarnation of
  the same group. This closes a reload bypass where a stale `.hibe.msk` could
  have made an unpinned external writer look like an authority.
- The HIBE path epoch is durable, starts at zero, and increments on authority
  path rotation. `max_depth()`, `path_epoch()`, and `is_authority()` expose the
  state needed by the administrative boundary.
- External raw creation validates the requested path against the depth encoded
  in the MPK. The walkthrough's three-label `org/fraud/case-17` authority is
  explicitly created with `max_depth=3`.

Authority assertions are writer-specific. A signed update authenticates what a
writer has received; it cannot give an offline writer knowledge of an unseen
rotation. Operational fencing remains required until every external writer has
accepted the new sibling path.

## Implemented reader grant contract

- `issue_hibe_reader_challenge` retains a one-time authority-signed challenge
  for one complete reader DID, ceremony, and group.
- `create_hibe_reader_proof` requires the caller's independently trusted
  `expected_authority_did`; it never treats a challenge's own publisher field as
  a trust root. The resulting `hibe-reader` proof is signed by the reader's real
  Ed25519 `did:key`.
- Normal `grant_reader` requires a fresh, exact-scope signed proof or an exact
  receiver-local retained verified-principal record. A caller-constructed
  `VerifiedPrincipal` dataclass is not authority. Invalid, absent, abbreviated,
  expired, mismatched, or wrong-scope reader identity is a hard failure before
  package delivery.
- Normal HIBE grants are always `recipient-seal-v1`; the HIBE secret key remains
  a bearer capability inside that sealed package and is not cryptographically
  bound to the DID after delivery.
- Plaintext bearer delivery exists only through `unsafe_plaintext=True`. It
  emits one common `TnSecurityWarning`, one best-effort
  `tn.security.unsafe_operation`, and a manifest marker identifying unsafe
  plaintext bearer delivery. There is no implicit fallback.
- Exact-path grants are the default. An ancestor key is explicitly marked as a
  delegated subauthority and requires `allow_subauthority=True`.
- Grant manifests bind delivery mode, exact granted path, unsafe state, and
  delegated-subauthority state. The narrow internal `export(...,
  _manifest_state=...)` hook rejects top-level state collisions and preserves
  the historical `state=None` wire/signature domain when unused.
- The one-time challenge commit is recoverable: package bytes are retained
  durably, the verified registry is written, and the consumed marker commits
  last. Exact replay re-delivers byte-identical retained bytes, including after
  proof expiry; a different proof/grant is `replay_conflict`. Injected registry
  and final-delivery failures are retry-safe.
- `add_recipient` forwards HIBE proofs and explicit unsafe/delegation switches
  into the same fail-closed grant path. Its result exposes `unsafe` and
  `delegated_subauthority`.

## Honest rotation and revocation

- `rotate_hibe_path` validates audience, TTL, and clock inputs before mutating
  the path and returns one `HibeAuthorityUpdateResult` containing the new path,
  epoch, and writer-scoped signed assertion.
- `revoke_reader` preflights survivor records before rotation, rotates to a
  sibling, and reissues authenticated sealed survivor kits. An external writer
  remains on its old path until it receives and pins the returned signed update.
- A holder of an ancestor HIBE key can derive into the new descendant/sibling
  namespace. Such a holder is honestly reported as `revoked=False`; no path or
  registry mutation occurs and no misleading assertion is returned.
- `RevokeRecipientResult` forwards `revoked`, new path, survivor kits, path
  epoch, and authority assertion.
- Unified `revoke_recipient(..., audience_did=writer_did)` now forwards the real
  external-writer audience. Its regression installs the returned epoch-2
  assertion in a separate writer configuration and successfully seals on the
  new path. BTN and JWE reject this HIBE-only parameter if explicitly supplied;
  their existing behavior is unchanged when it is omitted.
- Revocation remains forward/local and is not overclaimed: prior ciphertext
  stays readable, a stale external writer can still produce old-path output,
  and an ancestor capability cannot be cut off by sibling rotation. BTN remains
  the appropriate choice for routine per-recipient forward cutoff.

## Adjacent dispatch correction

Mixed-cipher receiver keybags can contain BTN and HIBE material for the same
group. A wrong-path HIBE open correctly returned `NotARecipientError`, but BTN
then attempted to parse the HIBE frame and converted the row into
`$decrypt_error`. BTN frames have an unambiguous `0xB7` magic, so a non-BTN
frame is now classified as another candidate (`NotARecipientError`) while a
malformed real BTN frame remains a decrypt error. Boundary/revocation tests now
retain the expected `$no_read_key` sentinel.

## TDD evidence

Initial prescribed RED:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_hibe_authority_trust.py python/tests/test_hibe_grant_absorb.py python/tests/test_hibe_boundary.py python/tests/test_hibe_revoke.py python/tests/test_hibe_external_writer_rotation.py -q
14 failed, 12 passed
```

Additional test-first RED cases covered:

- an attacker-signed, self-asserted authority challenge;
- path mutation before invalid audience/TTL/time validation;
- a caller-forged `VerifiedPrincipal`;
- exact replay versus conflicting proof and crash recovery after expiry;
- an unverified legacy survivor mutating rotation state;
- internal manifest augmentation changing ordinary package signatures;
- mixed BTN/HIBE wrong-path classification;
- stale local MSK surviving external restaging;
- the inaccurate higher-epoch-only expiry message; and
- unified revoke rejecting the newly required external writer audience.

Each focused RED was observed before its implementation change and is green in
the final gates.

## Final verification evidence

Fresh prescribed Task 6 gate:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_hibe_authority_trust.py python/tests/test_hibe_grant_absorb.py python/tests/test_hibe_boundary.py python/tests/test_hibe_revoke.py python/tests/test_hibe_external_writer_rotation.py -q
36 passed in 12.31s
```

Fresh complete HIBE-named suite plus low-level HIBE cipher contract:

```text
$tests = @(rg --files python/tests | rg '(^|[\\/])test_hibe.*\.py$')
.\.venv\Scripts\python.exe -m pytest @tests python/tests/test_cipher_hibe.py -q
50 passed in 28.53s
```

Legacy cipher/BTN/keybag/read/reload regression slice:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_cipher_hibe.py python/tests/test_btn_wire_contract.py python/tests/test_btn_keystore.py python/tests/test_keybag_multi_cipher.py python/tests/test_read_parse_resilience.py python/tests/test_rotation_reload_failure.py -q
61 passed in 7.85s
```

Executable walkthrough:

```text
.\.venv\Scripts\python.exe python/tests/demo_hibe_walkthrough.py
exit 0; all walkthrough sections passed
```

An adjacent 220-test package/admin/absorb/read gate produced `218 passed, 1
skipped, 1 failed`. The sole failure is explicitly outside this task:
`test_export_absorb.py::test_export_offer_round_trip` still supplies the fake
`did:key:z6MkAlice` to the now fail-closed JWE offer surface. The JWE owner
acknowledged and owns that fixture update; this subagent left the dirty file
untouched.

Scoped Ruff across every Task 6 production/test path: `All checks passed!`.
Scoped `git diff --check` exited zero (only Git's existing LF-to-CRLF notices).
Workspace-root `*.tnpkg` artifact count is zero. The Git index is empty.

## Review notes and boundaries

- This is the Python lifecycle. Rust/TypeScript/C# parity and native-runtime
  enforcement belong to the subsequent parity task; do not infer cross-SDK
  production readiness from these Python gates.
- Assertion receipt is authentication, not update discovery. External writer
  fencing/acknowledgement remains an operational requirement.
- HIBE provides confidentiality to path capabilities and admission through
  controlled capability delivery. It does not itself authenticate the sender:
  anyone with the public MPK and target path can form HIBE ciphertext. TN record
  signing, signature verification, and writer authorization remain separate
  controls.
- No stage, commit, reset, checkout, or unrelated-file cleanup was performed.

## Independent-review remediation (2026-07-12)

The three Important findings from the first independent review were reproduced
before production changes and remediated as follows.

1. `install_authority_assertion` now applies the cipher boundary's complete,
   non-lossy HIBE path canonicalization to the signed `id_path` before it
   acquires a lock or writes any file. Invalid signed paths are mapped to stable
   `TrustError(BINDING_INVALID)`. Parameterized regressions snapshot the entire
   external-writer keystore and prove leading, component, and line-ending
   whitespace cause zero mutation, including no lock file.
2. `grant_reader` now requires and parses a complete Ed25519 `did:key` before
   entering the `unsafe_plaintext` branch. Unsafe mode waives proof and
   recipient sealing only; it no longer waives identity syntax. `None` and an
   abbreviated DID fail before warning, audit emission, registry mutation, or
   package output. The positive unsafe test and all adjacent HIBE fixtures now
   use generated real DIDs while retaining the exact plaintext-delivery warning
   and audit payload.
3. Grant, revoke, `rotate_hibe_path`, and `rotate_reader_path` now share one
   per-group lifecycle lock. Lock order is consistently lifecycle, then
   EnrollmentStore for challenged grants, then the grant-registry lock. The
   revoke implementation never re-enters the public grant/rotate wrappers, so
   this ordering has no self-deadlock edge.

Revocation is now a durable, retryable transaction rather than a
rotate/replace/deliver sequence:

- Before live mutation, it durably retains an operation-keyed intent, the exact
  signed external-writer update, start and target identity keys/history, exact
  recipient-sealed survivor packages, registry start/target digests, and exact
  output metadata.
- Live rotation is an idempotent install from retained bytes. Recovery accepts
  every intended partial combination at the prior archive, history, current
  SK, identity-path, and path-epoch writes, while validating every live file
  against the retained start/target byte sets. Foreign bytes are an
  `EPOCH_CONFLICT`, never silently overwritten.
- Registry replacement is permitted only when its canonical digest is exactly
  the retained start or target digest. A racing grant therefore cannot be
  overwritten. Public grant/rotate calls also refuse an incomplete active
  intent until the caller retries that exact revocation.
- Survivor registry records bind the new path and exact package digest. Their
  `grant_digest` is recomputed over the retained proof digest, reader,
  ceremony/group, and new survivor path instead of incorrectly retaining the
  old-path digest.
- Output failure leaves the active intent recoverable. Exact retry converges on
  the same path epoch and redelivers byte-identical survivor packages. A
  completed receipt supports idempotent redelivery. If its writer-scoped
  assertion has expired, retry signs a fresh same-epoch, identical-material,
  same-audience assertion while preserving exact survivor bytes.
- The honest ancestor-capability no-op and audience-specific external-writer
  assertion remain unchanged.

Additional RED/GREEN coverage includes registry failure, survivor-output
failure, grant/revoke concurrency in the snapshot/replace window, public rotate
fencing, process-restart recovery at every live rotation write, foreign live
key rejection, same-epoch assertion renewal after expiry, exact package
redelivery, and canonical new-path grant metadata.

Fresh post-remediation verification:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_hibe_authority_trust.py python/tests/test_hibe_grant_absorb.py python/tests/test_hibe_boundary.py python/tests/test_hibe_revoke.py python/tests/test_hibe_external_writer_rotation.py -q
50 passed in 22.33s

$tests = @(rg --files python/tests | rg '(^|[\\/])test_hibe.*\.py$')
.\.venv\Scripts\python.exe -m pytest @tests python/tests/test_cipher_hibe.py -q
64 passed in 27.06s

.\.venv\Scripts\python.exe -m pytest python/tests/test_cipher_hibe.py python/tests/test_btn_wire_contract.py python/tests/test_btn_keystore.py python/tests/test_keybag_multi_cipher.py python/tests/test_read_parse_resilience.py python/tests/test_rotation_reload_failure.py -q
62 passed in 7.63s

.\.venv\Scripts\python.exe python/tests/demo_hibe_walkthrough.py
exit 0; all walkthrough sections passed
```

Scoped Ruff and `git diff --check` pass. No workspace-root `.tnpkg` artifact
exists. This subagent still performed no staging or commit operation.

## Second independent-review remediation (2026-07-12)

Four additional Important findings were reproduced and fixed in focused
RED/GREEN checkpoints.

### Durable survivor admission

Proof freshness remains mandatory for an initial grant or explicit re-grant,
but routine survivor reissue no longer mistakes an expired enrollment proof
for expired admission. A successful fresh grant now persists an
authority-signed `accepted_admission` statement binding the authority and
reader DIDs, audience, ceremony/group, proof digest and timestamps, and the
acceptance time. Revoke verifies that durable authority signature and exact
registry binding without reapplying proof expiry. Missing, unsafe,
scope-tampered, registry-divergent, and attacker-signed statements fail before
rotation or output. A +1-day proof-expiry test restarts the process and still
reissues the legitimately admitted survivor.

### Safe group and lifecycle paths

HIBE administrative entry points now centrally require the portable enrollment
group grammar, exact ceremony membership, HIBE cipher, and authority role
before deriving a lifecycle path. They repeat those checks under the lock.
Lifecycle locks use only a SHA-256 group component beneath a resolved
`.hibe-lifecycle` directory and enforce containment. Zero-mutation tests cover
`../`, `..\\`, absolute workspace paths, drive paths, UNC paths,
slash-absolute paths, and safe-but-unknown groups across grant, rotate, and
revoke; none constructs or acquires a lock.

### Monotonic reader-admission cutoff

Each HIBE challenge has durable receiver-local generation metadata. Challenge
issuance, grant, and revoke serialize in the single order lifecycle lock then
EnrollmentStore lock (then registry lock where needed). A real revocation
atomically increments the group admission generation before intent staging,
and the revocation intent pins that exact generation. Every pre-cutoff proof,
including a grant that loses a race with revoke, is `CHALLENGE_REPLAYED`.
Post-cutoff challenge issuance succeeds. The fence survives an injected crash
after the generation write but before intent creation and a complete process
restart. A challenge-issuance/revoke race proves issuance waits and records the
new generation.

### Retained assertion signer and writer cutoff

Active and completed recovery now require the retained authority assertion's
`subject_did` to equal both the intent authority and loaded configuration
authority before signature verification or mutation. Same-binding statements
signed by an attacker are rejected with `DID_SIGNER_MISMATCH`; active and
completed substitution tests prove no live-state or output mutation.

External-writer cutoff is explicitly codified as a fleet invariant. Writers
must be quiesced before revoke and may resume only after each writer has
successfully persisted the exact returned epoch through
`install_authority_assertion`. A successful install is the writer's durable
local ACK and its seal-time pin is enforced locally. The authority process
cannot remotely stop an offline stale writer, so orchestration must collect all
ACKs before resuming writes.

Fresh second-round verification:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_hibe_authority_trust.py python/tests/test_hibe_grant_absorb.py python/tests/test_hibe_boundary.py python/tests/test_hibe_revoke.py python/tests/test_hibe_external_writer_rotation.py -q
61 passed in 34.69s

$tests = @(rg --files python/tests | rg '(^|[\\/])test_hibe.*\.py$')
.\.venv\Scripts\python.exe -m pytest @tests python/tests/test_cipher_hibe.py -q
75 passed in 40.46s

.\.venv\Scripts\python.exe -m pytest python/tests/test_cipher_hibe.py python/tests/test_btn_wire_contract.py python/tests/test_btn_keystore.py python/tests/test_keybag_multi_cipher.py python/tests/test_read_parse_resilience.py python/tests/test_rotation_reload_failure.py -q
62 passed in 7.28s

.\.venv\Scripts\python.exe python/tests/demo_hibe_walkthrough.py
exit 0; all walkthrough sections passed
```
