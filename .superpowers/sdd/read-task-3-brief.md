# Secure-read Task 3: Python `read()` secure by default

Implement Task 3 from
`docs/superpowers/plans/2026-07-11-secure-default-read.md` after Rust Task 2 is
committed. Preserve the default iterator/result shape and work test-first.
Leave all changes unstaged for independent review.

## Exact scope

- Modify `python/tn/read.py`
- Modify `python/tn/_read_impl.py`
- Modify `python/tn/_entry.py`
- Modify `python/tn/reader.py`
- Modify `python/tn/config.py`
- Modify `python/tn/_handle.py`
- Modify `python/tn/__init__.py`
- Modify `python/tn/cli.py`
- Modify `python/tn/cli_read.py`
- Create `python/tests/test_read_secure_default.py`
- Create `python/tests/test_handle_read_policy.py`
- Create `python/tests/test_cli_read_security.py`
- Modify the five existing read/verify resilience tests listed in the plan.

`python/tn/_handle.py` already contains approved BTN-only package-bundling
hunks. Snapshot and preserve them; do not stage, revert, or silently absorb
them into read logic.

## Required behavior

- Keep `read()` as the main surface and preserve `_ReadIterator` plus existing
  entry shapes. Omitted `verify` resolves to secure `auto`/raise.
- Support exact public options and compatibility aliases from the plan.
  `secure_read()` is a strict wrapper exposing no weakening keywords.
- Resolve `ReadContext` and `LocalReadTrustProvider` once per iterator from the
  bound `TN` handle, never a process-global ceremony when a handle exists.
- A local attached `sign:false` profile may accept absent signatures without
  claiming authentication. Foreign/detached input needs both explicit unsigned
  overrides and never inherits local `sign:false`/`chain:false`.
- Invalid-present signatures are never accepted by
  `allow_unauthenticated`; exact trusted writer DIDs are snapshotted once.
- Route parse/hash/chain/signature/writer checks before decrypt/plaintext.
  Raise uses stable `VerifyError` reasons; Skip preserves counters, callback,
  full raw reason metadata, and exact cursor semantics; Disabled never invents
  authentication/authorization.
- CLI omission must call `read()` without a verify keyword. Explicit raise,
  skip, and false flags are the only weakening mappings.

## Gates

Record initial RED, then run the complete Step-2 pytest command in the plan,
plus scoped Ruff and `git -c core.whitespace=cr-at-eol diff --check`.

Write `.superpowers/sdd/read-task-3-report.md` with RED/GREEN evidence,
baseline-dirty handling, and index-empty confirmation.
