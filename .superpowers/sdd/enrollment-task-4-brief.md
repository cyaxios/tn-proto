# Enrollment Task 4: challenge, replay, and pending-offer state

Implement Task 4 from
`docs/superpowers/plans/2026-07-11-trusted-principal-enrollment.md` after
Enrollment Task 3 is committed. Work test-first and leave all changes unstaged
for independent review.

## Exact scope

- Create `python/tn/enrollment.py`
- Create `python/tests/test_enrollment_state.py`
- Modify `python/tn/conventions.py`
- Modify `python/tn/_keystore_backend.py`
- Modify `python/tn/absorb.py`
- Modify `python/tn/reconcile.py`
- Modify `python/tn/admin/__init__.py`
- Modify `python/tests/test_reconcile.py`

`python/tn/admin/__init__.py` already contains approved, unrelated HIBE/JWE
clarification hunks in the working tree. Snapshot and preserve them; identify
Task-4 hunks separately and do not stage or revert anything.

## Required behavior

- Implement the frozen `PendingOffer`, `EnrollmentStore`, and
  `admin.reconcile_enrollment` interfaces from the plan.
- Key retained signed artifacts by ceremony, group, reader DID hash, and offer
  digest. Never reduce a pending offer to DID/key JSON.
- Hold one exported cross-platform advisory lock across challenge consumption,
  exact-digest approval, re-verification, and promotion.
- Use same-directory temp files, fsync where supported, then atomic replace.
- Distinguish exact replay idempotency, replay conflict, consumed challenge,
  expiry, unsolicited pending approval, and two groups for one DID using the
  frozen stable reasons.
- Reverify the retained artifact at promotion and prove returned digests derive
  from those same bytes. No failed path may mutate state.
- Multiprocess approval races must converge exactly as specified by the plan.

## Gates

Record initial RED, then run:

```powershell
.\.venv\Scripts\python.exe -m pytest python/tests/test_enrollment_state.py python/tests/test_absorb.py python/tests/test_reconcile.py -q
ruff check python/tn/enrollment.py python/tn/conventions.py python/tn/_keystore_backend.py python/tn/absorb.py python/tn/reconcile.py python/tn/admin/__init__.py python/tests/test_enrollment_state.py python/tests/test_reconcile.py
git -c core.whitespace=cr-at-eol diff --check -- <owned paths>
```

Write `.superpowers/sdd/enrollment-task-4-report.md` with RED/GREEN evidence,
scope deviations, baseline-dirty handling, and index-empty confirmation.
