# Trusted Principal Enrollment Task 3 Report

## Status

- Status: complete after independent-review and final producer-audit remediation.
- Task-start BASE: `87ad1fdb1a977dcaf69ae950a4c739e25e2cca44`.
- Current HEAD at final handoff: `4a3384dc850420e202b9d3675694f206e189002c`
  (`feat(core): enforce read trust policy`), advanced by the concurrent read-track
  owner without changing Task 3's implementation baseline.
- Commit: none created by the Task 3 agent. Staging and commit ownership remained
  with the controller; the Task 3 agent issued no index-mutating command.
- Independent review: the two Important findings were remediated and the fresh
  re-review reported no remaining Critical or Important finding. The later
  strict-writer call-site audit found three stale test producers and stale
  guidance; all were remediated and covered by focused gates below.
- Final independent audit confirmation: **Ready YES**, with no remaining
  actionable Task 3 writer integration and no Critical or Important finding.
- Accepted fixtures were not changed.

## Exact Task 3 paths

Python implementation and tests:

- `python/tn/tnpkg.py`
- `python/tn/export.py`
- `python/tn/cli_compile.py`
- `python/tn/absorb.py`
- `python/tn/_pkg_impl.py`
- `python/tests/test_manifest_contract.py`
- `python/tests/test_tnpkg_container_contract.py`
- `python/tests/test_admin_log.py`
- `python/tests/test_project_seed.py`
- `python/tests/test_contact_update_tnpkg.py`
- `python/tests/test_identity_seed.py`
- `python/tests/test_kit_bundle_sealed.py`
- `python/tests/test_absorb.py`
- `python/tests/test_tnpkg_interop.py`

Rust implementation and tests:

- `crypto/tn-core/src/tnpkg/mod.rs`
- `crypto/tn-core/src/tnpkg/sign.rs`
- `crypto/tn-core/src/tnpkg/zip_read.rs`
- `crypto/tn-core/src/tnpkg/zip_write.rs`
- `crypto/tn-core/src/runtime_export/mod.rs`
- `crypto/tn-core/tests/manifest_contract.rs`
- `crypto/tn-core/tests/tnpkg_container_contract.rs`
- `crypto/tn-core/tests/tnpkg_interop.rs`
- `crypto/tn-wasm/src/lib.rs`
- `rust-sdk/tests/pkg.rs`

TypeScript implementation, tests, and cross-language helpers:

- `ts-sdk/src/core/tnpkg.ts`
- `ts-sdk/src/tnpkg_io.ts`
- `ts-sdk/src/compile.ts`
- `ts-sdk/src/seal_bundle_producer.ts`
- `ts-sdk/src/cli/export.ts`
- `ts-sdk/src/runtime/node_runtime.ts`
- `ts-sdk/src/runtime/absorb_bootstrap.ts`
- `ts-sdk/src/index.ts`
- `ts-sdk/test/manifest_contract.test.ts`
- `ts-sdk/test/tnpkg_container_contract.test.ts`
- `ts-sdk/test/absorb_sealed_bootstrap.test.ts`
- `ts-sdk/test/identity_project_seed.test.ts`
- `ts-sdk/test/dirt_easy_flow.test.ts`
- `ts-sdk/test/tnpkg_export_absorb.test.ts`
- `ts-sdk/test/contact_update_py_helper.py`
- `ts-sdk/test/fixtures/build_agentic20_project_seed.ts`

Task records:

- `.superpowers/sdd/enrollment-task-3-brief.md`
- `.superpowers/sdd/enrollment-task-3-report.md`

Consumed without modification:

- `tests/fixtures/trust/v1/package_body_index.json`
- `ts-sdk/test/fixtures/Agentic20.project.tnpkg`
- `python/tests/fixtures/Agentic20.project.tnpkg`

## Implemented contract

- Python, Rust, and TypeScript manifests expose the additive snake-case wire
  field `body_sha256`, with exact lowercase `sha256:<64 hex>` values.
- Body indexes are computed from final stored bytes before the manifest is
  signed. Central writers reject unsigned manifests, absent/malformed indexes,
  or any member/digest mismatch.
- Verified readers parse and verify the bounded manifest before loading body
  bytes, then require an exact indexed member set before returning any body to
  kind-specific parsing or mutation.
- Strict JSON shape handling distinguishes an absent index from a present
  `null`, array, string, or otherwise malformed index.
- Duplicate members, invalid archive paths, substituted/missing/extra bodies,
  malformed digests, and noncanonical manifest signatures fail closed.
- Security-sensitive TypeScript and Rust absorb paths use verified readers;
  named low-level legacy inspection remains non-mutating and explicitly
  unverified.
- Python no-runtime bootstrap performs only a bounded manifest-kind peek before
  trust, then one verified body read reused for configuration and dispatch.
  Bad signatures and absent/null indexes cannot autoinitialize, parse YAML, or
  create files. The public `tn.absorb` wrapper also uses only that manifest peek.
- Rust path and byte readers validate a structurally real EOCD, archive-end and
  comment relationships, classic entry counts, central-directory bounds, and
  inconsistent/truncated metadata before constructing `ZipArchive`. ZIP64
  sentinel metadata is explicitly rejected.
- The Agentic20 fixture remains an intentional absent-index legacy vector. Its
  generator now uses a clearly named, test-only raw serializer rather than the
  strict production writer, and the test asserts that the fixture remains
  unindexed and fails closed without filesystem mutation.

## RED evidence

Initial required Python command:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_manifest_contract.py python/tests/test_tnpkg_container_contract.py -q
```

Initial result: `16 failed, 14 passed, 1 skipped`; the manifest did not expose
or enforce the body index and the writer/reader ordering tests failed.

Initial required Rust command:

```text
cargo test -p tn-core --test manifest_contract --test tnpkg_container_contract
```

Initial result: compilation failed on the missing manifest fields and missing
body-index builder/verified-reader interfaces.

Initial required TypeScript command, from `ts-sdk/`:

```text
node --import tsx --import ./test/_setup_wasm.mjs --test test/manifest_contract.test.ts test/tnpkg_container_contract.test.ts
```

Initial result: failed on the missing wire field, builders, verifier, strict
writer checks, and verified-reader behavior.

Review/audit-driven RED cycles:

- Raw Python no-runtime tests first proved body bytes were consumed before
  trust and consumed twice on success. Public `tn.absorb` then failed all four
  focused cases because `_pkg_impl` repeated verification and swallowed trust
  rejection into autoinit routing.
- Rust EOCD preflight regression command
  `cargo test -p tn-core --test tnpkg_container_contract preflight -- --nocapture`
  initially failed all 5 tests for fake EOCD, byte/path early limits, ZIP64,
  and inconsistent/truncated metadata.
- Full TypeScript testing initially ended `957 passed, 1 failed, 41 skipped`:
  `contact_update_interop` exposed a Python helper that called the strict writer
  without indexing its final body.
- `cargo test --manifest-path rust-sdk/Cargo.toml --test pkg --no-run` failed
  with E0063 for three stale cross-crate `Manifest` initializers; their helpers
  also used signature-only setup before strict writes.
- The legacy Agentic20 generator threw `body_digest_mismatch` because it called
  the strict production writer for a deliberately absent-index fixture.

## Final GREEN evidence

Required commands:

- Python required command: `36 passed, 1 skipped`.
- Rust required command: `11 passed` in `manifest_contract` and `17 passed` in
  `tnpkg_container_contract`.
- TypeScript required command: `40 passed`.

Expanded task regressions:

- Public Python bootstrap focus:
  `python/tests/test_project_seed.py -k no_runtime_bootstrap -q` — `4 passed`.
- Expanded Python producer/absorb matrix across the eleven task-related test
  modules — `88 passed, 3 skipped`.
- `cargo test -p tn-core` — full crate suite and 22 doctests passed, including
  the 17 container-contract and 4 resource-limit cases.
- `cargo test -p tn-core --doc` after final writer-guidance edits — `22 passed`.
- `cargo check -p tn-wasm` — passed.
- `cargo test --manifest-path rust-sdk/Cargo.toml --test pkg` — `29 passed`.
- Expanded six-file TypeScript Task 3 command — `80 passed` after final
  formatting and legacy-fixture assertion.
- Focused `contact_update_interop.test.ts` — `1 passed`.
- Full TypeScript suite after the contact-helper fix — `958 passed, 41 skipped,
  0 failed`.
- Final `npm run typecheck` and `npm run lint` — passed.
- `tools/fixtures/build_trust_v1.py --check` — passed with no fixture drift.

## Format, static-analysis, and scope evidence

- `cargo fmt --all -- --check` and the Rust SDK manifest-specific format check
  both pass.
- Scoped Python `ruff check` passes on every Task 3 Python path. Scoped format
  checking passes on all Task 3-owned Python content except the unrelated
  pre-existing formatting delta in baseline-dirty `python/tn/_pkg_impl.py`;
  that file was not mechanically reformatted so its BTN-only user changes were
  preserved. The Task 3 hunk itself is formatter-conformant.
- Scoped Prettier passes on all 15 Task 3 TypeScript implementation/test/helper
  files. TypeScript ESLint and typecheck pass.
- A broad `uvx mypy` attempt remains non-gating at the repository baseline:
  105 diagnostics include missing dependencies/stubs and pre-existing project
  errors outside Task 3.
- Strict Clippy remains non-gating at the repository baseline: the dependency
  run stops on three existing `tn-btn` missing-doc warnings, while the
  no-dependency run surfaces more than 100 pre-existing crate-wide warnings.
  Rustfmt, compilation, focused tests, full `tn-core`, and WASM checks are clean.
- The final guidance search finds no stale package-producer instruction to call
  `manifest.sign`/`sign_manifest` before a strict write; complete-package docs
  and errors point to `sign_manifest_with_body`.
- The Task 3 agent never staged, unstaged, committed, reset, stashed, or cleaned
  the shared checkout. The index was repeatedly empty during implementation;
  the controller later created and owned the staged checkpoint while final
  audit fixes continued in the working tree.

## Review resolution and remaining boundaries

- Important Python finding: resolved with manifest-only routing, one verified
  body read, reused verified bytes, and public-wrapper side-effect regressions.
- Important Rust finding: resolved with structural EOCD validation and early
  byte/path metadata caps before `ZipArchive` construction.
- ZIP64 is deliberately unsupported and rejected when classic sentinel fields
  activate it. Inert optional locator bytes without sentinel metadata do not
  override the validated classic limits.
- Legacy packages without `body_sha256` remain readable only through the named
  low-level, non-mutating inspection boundary. Secure absorb rejects them until
  a separately authorized migration path exists.
- No accepted fixture changed and no known Critical or Important correctness or
  security finding remains.
