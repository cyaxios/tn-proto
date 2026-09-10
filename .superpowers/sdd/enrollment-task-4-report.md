# Trusted Principal Enrollment Task 4 Report

## Status

- Status: implementation and adversarial remediation complete; ready for final
  controller handoff.
- Task-start base: `8fb829a6f6d85095c2d9d42c3b99604dd09daa14`.
- Current shared HEAD: `b3dd68058ee7bc284e4608d274e7a416a80f592f`.
  The controller advanced and committed shared Task 4 work while this subagent
  continued review remediation. This subagent ran no staging or commit command.
- The complete signed `.tnpkg` bytes are retained. Pending state is never
  reduced to DID/key JSON.
- No known Critical or Important correctness/security finding remains.

## Scope and exact paths

Original Task 4 paths:

- Created `python/tn/enrollment.py`.
- Created `python/tests/test_enrollment_state.py`.
- Modified `python/tn/conventions.py`.
- Modified `python/tn/_keystore_backend.py`.
- Modified `python/tn/absorb.py`.
- Modified `python/tn/reconcile.py`.
- Modified `python/tn/admin/__init__.py`.
- Modified `python/tests/test_reconcile.py`.
- Created this report.

Controller-approved wire-contract expansion:

- Modified `python/tn/key_binding.py`.
- Modified `python/tests/test_key_binding_wire.py`.

Controller-approved adversarial container/durability expansion:

- Modified `python/tn/tnpkg.py`.
- Modified `python/tests/test_absorb.py`.
- Modified `python/tests/test_atomic_write.py`.
- Modified `python/tests/test_keystore_backend.py`.

No fixture was changed. Shared unrelated files and changes were neither edited
nor reverted.

## Implemented enrollment contract

- Added frozen `PendingOffer` and `EnrollmentStore` with preauthorization,
  signed one-time challenges, exact artifact staging, re-verification,
  reconciliation, and exact-digest approval.
- Added `admin.reconcile_enrollment(..., now: datetime | None) -> AcceptedOffer`
  with the frozen public signature.
- Added `ReconcileResult.accepted_offers`. Automatic reconciliation applies
  only to challenged/preauthorized offers; unsolicited offers remain pending
  until exact administrator approval.
- State paths hash signed ceremony/group text and the complete reader DID.
  This prevents traversal, separators, Windows reserved-device names,
  trailing-dot/space aliases, and case-folding collisions without changing
  canonical signed values.
- Challenge consumption, exact approval, and accepted-offer history are
  separate durable records. Exact retained-byte replay converges even after
  proof/challenge expiry. A consumed mismatch is classified before freshness
  as `replay_conflict`; a legacy partial consumed marker is
  `challenge_replayed`.
- Exact approval is durable before promotion. If writing accepted history fails,
  a retry can recover after expiry only for the same offer and artifact digest;
  different retained bytes remain unauthorized.
- Promotion re-reads and cryptographically verifies the retained artifact under
  the lock. `offer_digest` covers the canonical signed proof and
  `artifact_digest` covers the exact retained `.tnpkg` bytes.
- JWE reader bindings permit `challenge_digest: null` only when no challenge is
  supplied. Non-null without a challenge is `challenge_missing`; null with a
  supplied challenge is `binding_invalid`.
- Invalid input and clean reconciliation do not create enrollment state.

## Availability and conflict isolation

- Raw enrollment artifacts are bounded to 1 MiB using a stat check plus a
  TOCTOU-safe `MAX+1` read. Absorb uses the same bounded reread.
- Unsolicited pending capacity is separate and bounded to 256 KiB per artifact,
  128 unaccepted artifacts, and 8 MiB aggregate.
- Publisher-challenged capacity is reserved separately but bounded to four
  distinct variants per challenge, 256 unaccepted artifacts, and 32 MiB
  aggregate. Exact replay bypasses quota checks; a different challenge retains
  its reserved capacity. Accepted artifacts remain retained but stop consuming
  pending quota.
- `pending_offers()` deliberately remains fail-closed if any retained artifact
  is corrupt/conflicting. Internal reconciliation uses a per-artifact scan
  result: each bad path is explicitly added to `ReconcileResult.conflicts`,
  while unrelated valid offers continue and can be accepted. Nothing is
  silently discarded.

## Container boundary hardening

- Every `.tnpkg` member must be `ZIP_STORED`, have
  `compress_size == file_size`, and avoid encryption, compressed-patch, and
  strong-encryption flag bits. These checks occur before any member read.
- Before constructing `zipfile.ZipFile`, a bounded EOCD tail preflight caps the
  entry count and central directory (2 MiB), rejects ZIP64 sentinels/locator and
  multi-disk input, requires an EOCD whose declared comment ends at EOF, and
  validates central-directory placement. Path inputs use the same open handle
  for preflight and construction, avoiding a path-replacement race.
- The EOCD search walks backward past false signatures embedded at the end of a
  ZIP comment. Tests use an exploding ZipFile constructor to prove hostile
  count/central-size/ZIP64 metadata is rejected before constructor allocation
  for both bytes and Path inputs.
- Enrollment adds tighter metadata limits: eight entries, 256 KiB per member,
  and 512 KiB total uncompressed content, all checked before member reads.
- CRC failures, truncated ZIP reads, ZIP-layer `NotImplementedError`, and
  recognized encrypted/unsupported RuntimeError cases become `PackageError`.
  Direct enrollment maps them to `TrustError(statement_invalid)`; public absorb
  returns a rejected receipt. Unrelated programmer RuntimeError remains visible.
- Excessive manifest or inner `body/package.json` nesting is normalized rather
  than leaking `RecursionError`.

## Locking and durability

- `AdvisoryFileLock` tracks process-lock, descriptor, and actual OS-lock state.
  Failed open or OS-lock acquisition releases every acquired layer and never
  attempts an unlock for a lock that was not obtained.
- Atomic writes use unique same-directory `O_EXCL` temporary files created
  `0600`, file fsync, atomic replace, and directory fsync. Real directory I/O
  failures propagate; only explicit unsupported platform/filesystem errors are
  ignored. A post-replace directory-fsync error is reported with the correct
  semantics: the new target may exist but crash durability is unconfirmed.
- Missing directory hierarchies are created top-down with `0700`; every new
  directory name is fsynced through its containing parent. The deepest existing
  frontier is also resynced, so retry after a mkdir/parent-fsync failure cannot
  skip durability. Enrollment lock-root creation and local keystore creation use
  the same helper.
- First promotion tests prove both `consumed/` and `accepted/` directory links
  are synchronized before their record writes become successful.

## TDD evidence

Initial wire RED:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_key_binding_wire.py -q
3 failed, 22 passed
```

The minimal null-challenge contract change produced `25 passed`.

Initial state-machine RED:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_enrollment_state.py python/tests/test_reconcile.py -q
ERROR during collection: cannot import name 'enrollment_dir' from tn.conventions
```

Review remediation was also test-first. Captured RED cases included:

- eleven unsafe/colliding Windows scope components;
- lock open/OS-lock acquisition leaking process-lock or descriptor state;
- consumed conflicts incorrectly losing to expiry/freshness;
- unbounded raw rereads and compressed-member inflation before rejection;
- durable approval recovery failing after accepted-write failure and expiry;
- unsolicited and challenged queue/count/byte/variant exhaustion;
- one losing challenge variant blocking unrelated reconciliation;
- CRC and deep-JSON exceptions escaping both direct and absorb boundaries;
- forged STORED/DEFLATED metadata and hostile ZIP flags reaching member reads;
- EOCD entry floods, oversized central directories, ZIP64, multi-disk, and false
  comment signatures reaching ZipFile construction;
- swallowed directory-fsync EIO, non-durable parent creation, and the retry hole
  after a one-shot parent sync failure; and
- ZIP-layer `NotImplementedError` escaping member-read normalization.

Each focused regression is now green and included in the expanded gates below.

## Verification evidence

Fresh core enrollment/container/durability gate:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_enrollment_state.py python/tests/test_reconcile.py python/tests/test_absorb.py python/tests/test_atomic_write.py python/tests/test_keystore_backend.py -q
114 passed in 14.06s
```

Fresh generic package/interop/handler gate:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_tnpkg_container_contract.py python/tests/test_manifest_contract.py python/tests/test_tnpkg_interop.py python/tests/test_packaging.py python/tests/test_multi_ceremony_tnpkg.py python/tests/test_sealed_tnpkg_package_contract.py python/tests/test_fs_scan_handler.py python/tests/test_vault_pull_handler.py python/tests/test_vault_push_handler.py python/tests/test_inbox_accept.py python/tests/test_export_absorb.py python/tests/test_contact_update_tnpkg.py -q
106 passed, 1 skipped in 12.96s
```

Fresh wire-contract gate: `25 passed in 0.18s`.

Scoped Ruff over all Task 4 and approved expansion implementation/test paths:
`All checks passed!`.

Scoped `py_compile` passed. `tools/fixtures/build_trust_v1.py --check` exited
zero with no fixture drift. Scoped `git diff --check` exited zero; output only
contained Git's existing LF-to-CRLF working-copy warnings. Current HEAD remains
`b3dd68058ee7bc284e4608d274e7a416a80f592f`; the index is empty.

## Baseline-dirty and collaboration handling

At task start the index was empty and the only pre-dirty original owned path was
`python/tn/admin/__init__.py`. Its SHA-256 was captured as
`AE1DD58C53C5226D1589A27ABBC1F74ADC0C041E26A6396A25C55B1965BFF008`.
The preexisting HIBE/JWE semantic documentation hunks were preserved. Task 4's
admin semantic changes were limited to its top imports and
`reconcile_enrollment`; a controller-approved Ruff-only normalization touched
the preexisting local import block without changing behavior.

The controller committed and advanced shared HEAD several times while review
continued. This subagent repeatedly rechecked its unstaged diff, preserved
unrelated controller state, and did not stage, commit, or revert shared work.

## Known minor follow-ups

- Permanently expired, never-accepted pending artifacts remain retained and
  consume their bounded queue until an operator manually removes them. No
  automatic deletion/eviction was added because exact signed evidence retention
  and corruption reporting were preferred in this task.
- Pending-quota accounting scans retained accepted history. Unaccepted capacity
  is bounded, but an installation with very large lifetime accepted history may
  eventually benefit from a compact authenticated index.
