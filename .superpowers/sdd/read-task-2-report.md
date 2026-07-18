# Secure-Default Read Task 2 Report

## Status

Complete and intentionally left unstaged and uncommitted at the controller's
request. Rust core now exposes the secure-default policy, stable validity and
rejection metadata, canonical multi-source cursors, and one policy-aware file
scanner shared by secure and ordinary validity reads. All Task 2 focused tests
pass after independent-review remediation.

## Git

- BASE / current HEAD: `87ad1fdb1a977dcaf69ae950a4c739e25e2cca44`
- Commit: not created; the controller explicitly required the Task 2 changes
  to remain unstaged and uncommitted in the shared checkout.
- Index: empty for every Task 2 path at handoff.

## Exact Task 2 files

- `crypto/tn-core/src/storage.rs`
- `crypto/tn-core/src/runtime/types.rs`
- `crypto/tn-core/src/runtime/read.rs`
- `crypto/tn-core/src/runtime/mod.rs`
- `crypto/tn-core/tests/secure_default_read.rs`
- `crypto/tn-core/tests/secure_read.rs`
- `crypto/tn-core/tests/secure_read_interop.rs`
- `.superpowers/sdd/read-task-2-report.md`

Consumed without modification:

- `tests/fixtures/trust/v1/read_policy_matrix.json`
- `tests/fixtures/trust/v1/read_cursor_vectors.json`

## RED evidence

- The required initial command,
  `cargo test -p tn-core --test secure_default_read --test secure_read --test secure_read_interop`,
  failed to compile because the policy, reason, cursor, decision, and report
  types and `Runtime::read_with_policy` did not yet exist.
- `relative_option_path_and_source_id_are_anchored_at_yaml_directory` first
  returned no entry because an option path was resolved from the process
  directory. The implementation now resolves it from the bound YAML's parent
  and uses that same path for both reading and the canonical source ID.
- `local_chain_disabled_rows_report_effective_chain_validity` initially
  surfaced `_valid.chain=false` for the second local row under `chain:false`.
  The effective local attached chain exemption now applies consistently to
  both acceptance and reported validity.
- Review regression
  `explicit_file_source_cannot_spoof_local_unsigned_context` initially
  accepted an unsigned foreign file when its caller supplied a forged local
  context. File-source context is now derived inside `Runtime`; only the
  caller's explicit `required_group` request is retained.
- Review regression
  `secure_read_explicit_foreign_btn_remains_fail_closed_until_policy_decrypt_exists`
  initially returned a generic verification rejection. The prior explicit
  `NotImplemented` boundary is restored until policy-aware foreign BTN
  verification/decryption exists.
- Review regression
  `policy_scan_uses_snapshot_reader_without_whole_source_read` initially did
  not compile because storage had no snapshot-reader contract. It now proves
  one snapshot open and zero whole-source reads for the policy scanner. A
  companion test proves the foreign-log peek follows the same path.
- Final re-review regressions
  `oversized_whitespace_line_is_counted_and_skipped` and
  `oversized_whitespace_line_raises_record_invalid` initially failed with
  `scanned=1` instead of 2 and an unexpected successful report, respectively.
  An over-limit physical line is now classified before blank-line skipping,
  even when every retained byte is whitespace.

## GREEN and quality evidence

- Final focused command after all code and lint refactors:
  `cargo test -p tn-core --test secure_default_read --test secure_read --test secure_read_interop --test runtime_read`
  — 37 passed: 16 secure-default, 6 secure-read, 11 interop, and 4 legacy
  runtime-read tests.
- `cargo test -p tn-core` completed successfully after the streaming
  remediation. A later final rerun, after a behavior-preserving lint refactor,
  reached the Task 2 suites without failure but was then blocked by five
  concurrently introduced, controller-confirmed Task 3 RED cases in the
  unowned `tnpkg_container_contract` test. The post-refactor focused Task 2
  command above is the authoritative final gate.
- `python tools/fixtures/build_trust_v1.py --check` — exit 0 with no fixture
  drift.
- `rustfmt --edition 2021 --check` on all seven Rust implementation/test paths
  — exit 0.
- `git diff --check` on all tracked Task 2 paths, plus
  `git -c core.autocrlf=false diff --no-index --check` for the two new files —
  clean. The tracked check emitted only the checkout's existing LF-to-CRLF
  conversion notices.
- Strict scoped Clippy was attempted with
  `cargo clippy -p tn-core --test secure_default_read --test secure_read --test secure_read_interop --test runtime_read --no-deps -- -D warnings`.
  All Task-2-introduced findings were fixed. The command remains nonzero on
  pre-existing crate warnings in legacy storage performance code,
  `RuntimeInitOptions` call sites, and `ForeignReaderMaterial`; no diagnostic
  remains in a Task-2-added hunk or owned test.

## Fixture and contract coverage

- All 33 accepted policy-matrix cases execute through the public Rust
  `ReadTrustPolicy::resolve(...).evaluate(...)` contract and assert exact
  resolved mode, acceptance, ordered reasons, authentication, and
  authorization.
- Additional policy tests cover stable de-duplication, absent versus present
  invalid signatures, exact local unsigned inference, mandatory rejection
  before plaintext, disabled-mode hard failures, bounded skip behavior, and
  oversized whitespace-line accounting under both Skip and Raise.
- Validity preserves `signature`, `row_hash`, and `chain`, and adds
  `writer_authenticated`, `writer_authorized`, and stable ordered `reasons`.
  Missing evidence never defaults to valid.
- Cursor tests consume the accepted vectors and prove canonical sorted source
  IDs, exact byte-offset/sequence/opaque strings, lossless serialization,
  resume after skips, chain seeding across the prefix, and preservation of
  unrelated sources.
- Runtime regressions cover caller-context spoofing, YAML-relative source
  paths, local `sign:false` and `chain:false` compatibility, foreign unsigned
  isolation, foreign BTN fail-closed behavior, and secure-read
  raise/skip/forensic adapters.

## Implementation notes

- `VerifyMode::Auto` freezes to `Raise`. Disabled verification rejects an
  explicit trusted-writer override, bypasses only integrity/authentication/
  authorization gates, and cannot bypass malformed records, AAD failures, or
  an explicitly required missing recipient.
- Receiver-local trust is snapshotted from the bound device DID, configured
  exact writer DIDs, and the private verified-publishers registry. Canonical
  Ed25519 `did:key` validation is shared by policy resolution.
- The gate order is parse/shape, row hash, chain, signature and exact-writer
  authorization, then decryption/AAD/recipient. No plaintext is returned
  before the mandatory pre-decryption gates pass.
- Native filesystem scans open a read-only handle, capture its length from
  that same handle, and stream through a reader capped at the captured length.
  Lines are bounded to 8 MiB of retained state; oversized physical lines are
  drained and rejected as invalid records even when the retained prefix is
  blank. Audit appends therefore cannot enter the current scan or grow its
  cursor.
- The storage trait's object-safe snapshot hook defaults to `None`; custom and
  wasm-style backends retain the compatible whole-buffer `read_bytes`
  fallback. Native `FsStorage` and the focused probe storage use the streaming
  snapshot contract.
- File source IDs use host-independent lexical normalization and a canonical
  NUL-delimited SHA-256 descriptor. Filesystem canonicalization is deliberately
  avoided so nonexistent paths and symlink spellings remain deterministic.

## Deviations and remaining boundaries

- `crypto/tn-core/src/storage.rs` is the approved review-remediation scope
  expansion needed for fixed-length streaming snapshots. No other production
  scope expansion occurred.
- Policy-aware foreign BTN recipient verification/decryption remains
  deliberately unimplemented and explicitly fail-closed, matching the prior
  compatibility boundary.
- The current `SecureReadOptions` surface selects file sources. Generic
  sequence and opaque cursor kinds and fixture source IDs are losslessly
  represented and preserved, but this runtime method does not originate a
  handler or detached-byte source.
- The public APIs are exported through `tn_core::runtime`; the crate-root
  `lib.rs` was outside the authorized path set and was not modified.
- No accepted fixture was changed, no Task 3 source/test was edited by this
  task, and all Task 2 work remains unstaged.
