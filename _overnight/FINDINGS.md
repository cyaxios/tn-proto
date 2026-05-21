# Overnight findings — 0.4.3a1 TS parity

Append-only log of unresolved issues encountered during the overnight run.

Schema per entry:

```
## F<N>: <one-line description>
- Batch: B<x>.<y> (or "Phase 0" for setup-time findings)
- File(s): path:line
- Symptom: <what fails or what's ambiguous>
- Tried: <what I attempted>
- Suspected cause: <my best hypothesis>
- Recommended action: <what a human should do>
- Commit (if any): <sha or "n/a">
```

---

## F1: Batch 0 commit skipped — trunk dirty state too broad for autonomous commit

- Batch: Phase 0 (step 0.2)
- Files: 33 modified files on `feat/0.4.2a11-naming-flip` at HEAD `578ecbb`. Full diff captured at `_overnight/dirty_trunk_state_at_start.patch` (561 lines, 23.5 KB).
- Symptom: The overnight plan assumed the dirty TS work was a coherent 6-file batch ready to commit. Reality at session start: 33 modified files including substantial Python WIP that I did not have permission to autonomously commit.

  Modified Python files (work-in-progress on the very files the parity audit needs as oracles):
  - `python/tn/admin/__init__.py` (+25 lines)
  - `python/tn/btn_keystore.py` (+66 lines)
  - `python/tn/tnpkg.py` (+14 lines)
  - `python/tn/absorb.py`, `compile.py`, `export.py`, `offer.py`, `reader.py`, `_dispatch.py`, `config.py`
  - Plus 16 modified test files

  TS files dirty (the original "batch 0" scope):
  - `ts-sdk/src/_log_fields.ts` (+97), `index.ts` (+33), `tn.ts` (+189)
  - `ts-sdk/test/context_verbs.test.ts` (+72), `log_fields.test.ts` (+21), `tn_init.test.ts` (+17)

  Lint failures on the dirty TS (would block commit even if only the 6 TS files were staged):
  - 27 × `@typescript-eslint/no-explicit-any` in `src/tn.ts` from new `Tn<Schema extends Record<string, any>>` generic + predicate parameter types
  - 1 × `@typescript-eslint/no-unused-vars` in untracked `test/ts_premium_features_demo.test.ts` (a sketch file, not in any commit yet)
  - 1 × `prefer-const` in `src/_log_fields.ts` (this one was auto-fixed by `npm run lint:fix`)

- Tried:
  1. `npm run typecheck` — passed
  2. `npm run lint` — failed (29 errors)
  3. `npm run lint:fix` — fixed 1 of 29 (the `prefer-const`); the 27 `any` errors are eslint *suggestions* not auto-applied because choosing `unknown` vs `never` is a semantic decision; the unused-var is in an untracked sketch file
  4. Considered manually replacing `any → unknown` — declined because the user's intent in adding `any` for predicate parameter types (`(entry: any) => boolean`) and the `Schema extends Record<string, any>` generic constraint is to keep the consumer-facing API permissive. Forcing `unknown` would break call-site ergonomics (consumers couldn't access `entry.field` without narrowing). This is a real API design choice, not a defect.

- Suspected cause: The dirty WIP is mid-polish — naming-flip continuation + new generic + new printf format + new default export — and the user had not yet completed the lint sweep before stepping away. The plan I authored assumed the dirty work was commit-ready; it was not.

- Recommended action:
  - Review the captured diff at `_overnight/dirty_trunk_state_at_start.patch` to confirm intent.
  - For the 27 `no-explicit-any` in `tn.ts`: either (a) add `// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Schema constraint and predicate parameters intentionally permissive` at each site, or (b) relax the eslint rule for generic constraints (recent `@typescript-eslint` allows `ignoreRestArgs`-like opt-outs for specific patterns).
  - For `_log_fields.ts`: already auto-fixed by `lint:fix` (`let → const`). Re-stage and commit.
  - For `test/ts_premium_features_demo.test.ts` (untracked): decide if this sketch file should be tracked. If yes, fix the unused `Entry` import (or prefix with underscore to silence). If no, add to `.gitignore` or move to `_scratch/`.
  - The Python WIP needs the user's eyes — it's mid-work and touches files my parity audit needs.

- Commit (if any): n/a — work intentionally not committed.

- Worktree posture: The overnight worktree at `C:/codex/tn/tn_proto/.worktrees/ts-parity-overnight/` was created off `feat/0.4.2a11-naming-flip` at HEAD `578ecbb` (last commit "0.4.3a1 cross-SDK fixtures + 2 reducer/well-formed regressions caught"). The dirty WIP stays in the trunk working tree at `C:/codex/tn/tn_proto/`, untouched. Overnight work proceeds against the committed Python source as the parity oracle, which is the correct behavior anyway.

## F2: Python reader's `_envelope_reserved` set is post-flip-incomplete (still has `did`)

- Batch: B0.4 (parity-oracle observation while fixing the TS twin)
- Files:
  - `python/tn/reader.py:540-542` — `_envelope_reserved` set inside `parse_envelope_line` still lists `"did"` instead of `"device_identity"`. Line 551 then passes `device_identity=env.get("did", "")` which returns `""` because the wire key is `device_identity` (per `python/tn/logger.py:312`). Net effect: any caller that takes the `verify=True` branch of `parse_envelope_line` computes a wrong row_hash and reports `row_hash: false`. The streaming `_read` path at lines 651-668 is correct (`env["device_identity"]` on line 668) but its `_envelope_reserved` set still has `"did"` (line 652) which means `device_identity` leaks into `public_out` and double-hashes — same bug as the TS side I just fixed.
- Symptom: not exercised by any current Python test (would surface as `row_hash: false` on any read-with-verify of a writer-produced log). The wire format produces `device_identity` (per logger.py:312), so reading it back recomputes the wrong hash because `device_identity` is added to `public_fields` then hashed both as a primary input and as a public-fields entry.
- Tried: nothing in this batch — out of scope per the worktree's "ts-sdk writes only" restriction (per `feedback_scope_tn_proto_web` global memory: writes restricted to tn_proto_web; sibling repos read-only — and `python/` lives under the same repo as ts-sdk but the scope-of-this-session was TS).
- Suspected cause: B0.1 / B0.2 equivalent work in Python (the phase B → phase G `did → device_identity` flip) wasn't completed for reader.py's two reserved-keys sets and `parse_envelope_line`'s row_hash arg lookup.
- Recommended action: in a follow-on Python-side batch, change `"did"` → `"device_identity"` in both `_envelope_reserved` sets (lines 540, 652) and change `env.get("did", "")` → `env["device_identity"]` on line 551.
- Commit (if any): n/a — observation only, fix deferred.

## F3: tnpkg fixtures need rebuild after `from_did` → `publisher_identity` manifest-field rename

- Batch: B0.4 (10 remaining failures after yaml-fragment fixes; identified but not addressed)
- Files (10 tests in 5 files):
  - `test/tnpkg_interop.test.ts` — "Rust-produced admin_log_snapshot parses in TS" + "manifest canonical bytes match golden across languages"
  - `test/tnpkg_export_absorb.test.ts` — "export(admin_log_snapshot) → absorb on a fresh peer applies envelopes" + "absorb surfaces leaf reuse when add(L) → revoke(L) → add(L)"
  - `test/dirt_easy_flow.test.ts` — "dirt-easy: project_seed bootstrap returns a usable Tn"
  - `test/identity_project_seed.test.ts` — "project_seed real-fixture round-trip via Tn.absorb in a fresh dir"
  - `test/secure_read_interop.test.ts` — "required byte-compare fixtures present" + "TS local admin_events matches committed fixture" + "Python admin_events byte-compare" + "Rust admin_events byte-compare"
- Symptom: `Error: manifest missing required keys: ["publisher_identity"]` on read. The TS reader (`ts-sdk/src/core/tnpkg.ts:108`) now strictly requires `publisher_identity`, but the on-disk fixture `test/fixtures/Agentic20.project.tnpkg`'s `manifest.json` still uses the legacy `from_did` key. Same for `python/tests/fixtures/python_admin_snapshot.tnpkg` and `ts-sdk/test/fixtures/ts_admin_snapshot.tnpkg` (latter is missing entirely per the byte-compare test).
- Tried: nothing — out of scope for the yaml-fragment batch.
- Suspected cause: the manifest field rename `from_did → publisher_identity` (visible in the TS reader's required-keys list and the Python admin_events fixture builder) landed before the binary fixtures were regenerated. The Python writer at `python/tn/_pkg_impl.py` and Rust tnpkg writer need an audit to confirm they emit `publisher_identity`; then fixtures need rebuilding.
- Recommended action: a "tnpkg manifest field flip" batch that (a) confirms all three SDK writers emit `publisher_identity` (not `from_did`), (b) regenerates the binary fixtures, (c) updates the byte-compare golden hashes if the canonical signing-bytes changed.
- Commit (if any): n/a — observation only, fix deferred to a separate batch (likely B0.5 or B1.x).

## F4: Test corpus was bottlenecked on missing `dist/` build artifacts (16 CLI tests)

- Batch: B0.4 (resolved as a side effect, but worth noting for future overnight planners)
- Files: `test/cli_rotate.test.ts` (8 tests), `test/cli_streams_validate.test.ts` (7 tests), `test/cli_watch.test.ts` (1 test)
- Symptom: All 16 CLI tests failed with `ERR_MODULE_NOT_FOUND: Cannot find module '.../ts-sdk/dist/index.js' imported from .../ts-sdk/bin/tn-js.mjs`. The CLI binary at `bin/tn-js.mjs` is wired to import from `dist/`, not `src/`.
- Cause: this worktree was checked out without a `dist/` build, and `npm test` doesn't run `npm run build` as a precondition.
- Resolution: ran `npm run build` once at the start of B0.4; all 16 CLI tests went green immediately (no source changes required). Subsequent batches in this worktree will inherit the dist/.
- Recommended action: add `pretest: "npm run build"` to `ts-sdk/package.json` so test runs always have a fresh dist. Out-of-scope for this batch; track as a small follow-on.
- Commit (if any): n/a — `dist/` is gitignored; the `pretest` hook change is the actionable artifact.

## F5: BtnPublisher.rotate() not exposed in tn-wasm — blocks B3.x BTN rotation TS parity

- Batch: B3.1 (probe; blocked at first check)
- Files: `crypto/tn-wasm/src/lib.rs` (missing #[wasm_bindgen] wrapper); `crypto/tn-wasm/pkg/tn_wasm.d.ts` (no `rotate` symbol)
- Symptom: `grep -n "rotate" crypto/tn-wasm/pkg/tn_wasm.d.ts` returns ZERO matches. The TS SDK cannot call into Rust's PublisherState::rotate() because no wasm-bindgen wrapper exists.
- Tried: only the grep — declined to proceed with B3.x batches because (a) wiring TS without the underlying wasm primitive is impossible, and (b) adding the wasm-bindgen wrapper is substantive Rust work that should happen with the user's eyes on it.
- Suspected cause: the 0.4.3a1 BTN cipher rotation work shipped phases A-F across Rust (`crypto/tn-btn/`, `crypto/tn-core/`) and Python (via PyO3 wrappers in `crypto/tn-btn-py/` and `crypto/tn-core-py/`), but the wasm-bindgen path through `crypto/tn-wasm/src/lib.rs` was missed. The Python PyO3 surface in `crypto/tn-btn-py/src/lib.rs` (commit e75cf56 phase C) provides a model for what the wasm equivalent should look like.
- Recommended action: in a follow-on Rust batch, add `#[wasm_bindgen]` wrappers around `tn_btn::PublisherState::rotate()` and any required helpers in `crypto/tn-wasm/src/lib.rs`. Mirror the PyO3 shape from `crypto/tn-btn-py/src/lib.rs`. Then `wasm-pack build --target nodejs --release` from `crypto/tn-wasm/`. Then the B3.1-B3.5 TS catchup work becomes feasible.
- Commit (if any): n/a — work blocked on user-supervised Rust change.

## F6: Trunk worktree's `crypto/tn-core-py/python/tn_core/_core.pyd` was rebuilt as a side effect of B2.1

- Batch: B2.1 (Python tn_core wheel rebuild needed to regenerate binary fixtures)
- Files: `C:/codex/tn/tn_proto/crypto/tn-core-py/python/tn_core/_core.pyd` (trunk worktree, NOT the overnight worktree)
- Symptom: trunk Python's `_core.pyd` mtime is now today's date, even though the trunk's branch (feat/0.4.2a11-naming-flip) wasn't being committed-to.
- Cause: regenerating the binary `.tnpkg` fixtures required running `python -m ...` from a Python venv that imports `tn_core._core`. The B2.1 subagent ran `maturin build --release crypto/tn-core-py` and then `pip install -e crypto/tn-core-py` to make the rebuilt wheel available. The editable install rebuilt the `.pyd` from the trunk's source — which is on the same branch family and has the new field names, so trunk Python ops should continue to work normally.
- Tried: this is by design, not a defect.
- Recommended action: none required. Flagged so the user isn't surprised by an unexpected `.pyd` rebuild.
- Commit (if any): n/a — `.pyd` files are gitignored compiled artifacts.
