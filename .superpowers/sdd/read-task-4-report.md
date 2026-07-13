# Secure-default read Task 4 report

Date: 2026-07-12

## Scope

Implemented Task 4 from `docs/superpowers/plans/2026-07-11-secure-default-read.md` in the shared dirty checkout without staging or committing. The public `read()` iterator/entry/stats surface remains unchanged. `watch()` remains async-iterator compatible and gains additive read-policy, recipient-mode, and resumable-cursor support.

The owned implementation and test paths are:

- `python/tn/_watch_impl.py`
- `python/tn/read.py` (Task 4 audit/watch hunks only)
- `python/tn/mcp/schemas.py`
- `python/tn/mcp/tools_core.py`
- `python/tests/test_read_security_audit.py` (new)
- `python/tests/test_watch.py`
- `python/tests/test_watch_bugs_w5_w6.py`
- `python/tn/mcp/tests/test_schemas.py`
- `python/tn/mcp/tests/test_tools_core.py`
- `.superpowers/sdd/read-task-4-report.md` (this report)

No unrelated enrollment, ZIP, HIBE, Rust, or TypeScript path was edited for this task.

## Baseline and RED evidence

- Scoped pre-change baseline: `36 passed` for existing watch/MCP tests.
- Added the Task 4 tests before production changes.
- Required RED run: `18 failed, 34 passed`.
- The failures directly demonstrated the missing behavior: no read/watch unsafe-operation audit, watch defaulted to `verify=False`, watch rejected the new policy kwargs, watch did not enforce or expose read decisions, recipient watch was unsupported, cursor types/helpers were absent, and MCP rejected/omitted the secure policy fields.

## Implementation

### Watch parity and cursor progress

- `watch()` now defaults to `verify="auto"` and accepts the same `require_signature`, `allow_unauthenticated`, `trusted_writers`, and `allow_unknown_writers` controls as `read()`.
- The source/context/policy snapshot is resolved once when the async operation begins.
- Each complete NDJSON line advances its source byte offset before any rejection or yield. Skip mode therefore consumes a rejected row once and later polls continue from the scanned byte position, independent of yielded count.
- Added lossless, strictly validated `SourceCursorV1`/`ReadCursorV1` representations and canonical source-ID helpers that consume all shared `read_cursor_vectors.json` cases, including POSIX, Windows, opaque, sequence, and multi-source sorted values.
- `watch()` returns an async-iterator-compatible wrapper whose live `.cursor` snapshots all scanned byte progress. Passing that token back through the additive `cursor=` argument resumes matching sources without replaying rejected rows and retains unrelated source entries for later multi-source use.
- Cursor parsing rejects unsupported versions, extra or missing fields, non-canonical source IDs, mismatched source kinds, lossy numeric values, and negative positions. `cursor=` conflicts with a non-default `since=` value instead of applying ambiguous precedence.
- Initial drain and subsequent polls share one `_SourceState` chain/offset state.

### Pre-decrypt policy enforcement

- Watch now uses the same `ReadTrustPolicy` and `ReadContext` decision engine as read.
- It parses and scans canonical envelope/hash/chain/signature state before decrypting any group.
- A rejected pre-decrypt decision raises or skips with the same stable primary/full reasons as read.
- Accepted rows are decrypted, then evaluated again for AAD and required-recipient conditions.
- `raw=True` returns the on-disk envelope with the same `_valid` authentication/authorization/reason metadata as `read(raw=True)`.
- `as_recipient` and `group` are now supported additively for BTN, JWE, or HIBE recipient material. Existing normal Entry output remains unchanged.
- For typed output, both `read()` and `watch()` now apply the selected verification mode to post-gate `Entry` validation failures: `"auto"`/`"raise"` produce `VerifyError(record_invalid)`, `"skip"` records an observable skip, and `False` preserves the underlying parse exception. A cryptographically valid envelope can no longer disappear silently because its typed record is malformed.

### Weakening observability

- Reused the Foundation-owned `security_audit.py` notice, warning, event type, canonical payload, and `ContextVar` recursion guard; no second warning model was introduced.
- `verify=False`, unsigned policy relaxation outside an automatically unsigned local profile, and `allow_unknown_writers=True` emit exactly one `TnSecurityWarning`.
- A writable active context emits exactly one best-effort `tn.security.unsafe_operation` through the bound runtime.
- Detached/read-only/no-runtime contexts still warn but do not emit an admin event.
- Audit exceptions are swallowed and do not change the requested read result.
- A nested unsafe read during audit emission is suppressed by the shared task-local recursion guard.
- Concurrent async operations retain independent audit recursion state.
- Runtime audit emission returns the exact created event ID. The initiating read/watch scans that event for chain continuity but excludes only that exact event from its own result, so an unsafe admin-log operation cannot return the audit row it just generated and later strict replay remains chain-valid.

### MCP

- `ReadInput.verify` now defaults to `"auto"` and accepts `"auto"`, `"raise"`, `"skip"`, `True`, and `False`.
- Added nullable `require_signature`, nullable `allow_unauthenticated`, nullable exact-DID `trusted_writers`, and `allow_unknown_writers=False`.
- `tn_read_impl()` forwards every policy value unchanged, including explicit `False` and `None`; existing output shape and containment behavior are preserved.

## Verification evidence

- Task 4 prescribed suite:
  - `63 passed in 13.55s`
- Focused read/watch/audit gate:
  - `35 passed in 12.36s`
- Targeted secure-read compatibility gate (including parse resilience and Task 4 audit):
  - `86 passed, 7 warnings in 19.59s`
  - All seven warnings are the expected `TnSecurityWarning` generated by tests that deliberately request unsafe read parameters.
- Broader non-performance secure-read/watch/MCP gate:
  - `178 passed, 7 warnings in 33.27s`
- The three known failures in `python/tests/perf_smoke/instrumentation/test_verified_read_perf_stages.py` remain out of Task 4 scope. That parametrized test calls `tn.reader.read()` directly and expects the old exact three-key `valid` mapping, while current reader output also includes `record` and `aad`. Per controller direction, it remains for the later performance task.
- Ruff across every owned implementation/test path:
  - `All checks passed!`
- Scoped `git diff --check`:
  - exit 0 (only Git's existing CRLF conversion notices were printed)
- Shared Git index:
  - empty; this task staged and committed nothing.

## Compatibility notes

- `read()` remains the main surface and its public shape was not changed.
- Secure watch defaults can be intentionally weakened only through explicit parameters, which are now observable by design.
- Watch remains byte-offset based and async-iterator compatible. Its additive live `.cursor` property and `cursor=` input make progress serializable without changing yielded Entry/raw values.
- Existing watch main-log/admin-log selection, `since`, polling, rotation, truncation warning, raw/Entry output selection, and `where` behavior remain covered by the original regression suite.

## Review remediations

Controller and independent review identified three important gaps after the first implementation pass: unsafe admin-log reads could observe their own newly emitted audit row, typed `read()` output did not yet match watch's post-gate failure policy, and cursor helpers were not exposed through a usable resume path. All three were accepted, implemented, and covered by regression tests before final handoff.
