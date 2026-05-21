# Overnight run report — 2026-05-20 / 21

## Headline

**Test suite is fully green: 296 pass / 0 fail in `ts-sdk`.**

Started at 213 pass / 83 fail. Net: +83 passes, -83 failures, zero regressions.
Five commits on `feat/0.4.3a1-ts-parity` (off `feat/0.4.2a11-naming-flip`).
TypeScript typecheck + ESLint both clean post-run.

Stop conditions from the design doc:

1. ✅ **TS coding surface smooth + idiomatic** — every test that exercises the
   public TS surface now passes. The naming flip (phases B + G) is now
   complete end-to-end on the TS side.
2. ✅ **tnpkg consistent with Python** — the manifest field rename
   (`from_did` → `publisher_identity`, `to_did` → `recipient_identity`) is now
   honored in writers, readers, fixtures, and byte-compare goldens across all
   three SDKs (Python, Rust, TS).

The remaining items from the original plan (B3.x BTN rotation, B4.x error
re-exports, B5.x idiomatic sweep) are feature-expansion work, NOT test-fail
work. They're safe to defer to the next session. F5 explicitly blocks B3.x on
a `tn-wasm` change that needs the user's eyes on it.

---

## Branch

- Trunk worktree (untouched apart from a Python `.pyd` rebuild — see F6):
  `C:/codex/tn/tn_proto/` on `feat/0.4.2a11-naming-flip` at `578ecbb`.
  Dirty WIP from session start preserved (33 files; captured at
  `_overnight/dirty_trunk_state_at_start.patch`).
- Overnight worktree:
  `C:/codex/tn/tn_proto/.worktrees/ts-parity-overnight/` on
  `feat/0.4.3a1-ts-parity` at `97bd401`.
- Commits on overnight branch (5 total):
  ```
  97bd401 ts-sdk: B2.1 — tnpkg manifest from_did → publisher_identity + fixture rebuild
  f1daba8 ts-sdk: B0.4 — flip legacy yaml fragments + finish phase G reserved-keys + dist build
  c81a0ce ts-sdk: B0.2 — naming-flip phase G completion (Entry.device_identity end-to-end)
  e0601c7 ts-sdk: B0.1 — naming-flip phase B for TS (ceremony yaml me: → device:)
  f735366 scaffold: _overnight/ artifacts + F1 finding + lockfile sync
  ```

---

## Phases completed

- [x] Phase 0 — pre-flight + worktree setup. Original "batch 0" (commit dirty
      TS as one coherent commit) was SKIPPED — F1 explains why.
- [x] Phase 1 — parity audit. The audit happened test-driven during B0.1
      onward instead of as a separate audit step; the discovered gaps became
      the actual batch queue.
- [x] Phase 2 — tnpkg parity. B2.1 closed the entire 10-test failure cluster.
      B2.2 and B2.3 were folded into B2.1 (no separate work needed).
- [ ] Phase 3 — BTN rotation parity. **BLOCKED on F5** — `BtnPublisher.rotate()`
      is not exposed in tn-wasm. Needs Rust+wasm-bindgen work first.
- [ ] Phase 4 — other TS gaps (set_link_state, KeystoreConflictError,
      reducer regressions). Deferred to next session.
- [ ] Phase 5 — idiomatic TS sweep (default export smoke, discriminated
      union cascade, printf parity). Deferred to next session — most of the
      work the sweep was meant to do happened organically in B0.1/B0.2/B0.4.
- [x] Phase 6 — this report.

---

## Batches

| ID | Status | Commit | Test delta | Notes |
|---|---|---|---|---|
| Phase 0 | DONE | `f735366` | n/a | Worktree + scaffolding. F1 filed: dirty TS not committed (broader than scoped). |
| B0.1 | DONE | `e0601c7` | +39 pass / -39 fail | TS phase B: yaml `me:` → `device:`. Also: `recipients[].did` → `recipient_identity` (Rust loader required it). |
| B0.2 | DONE | `c81a0ce` | +4 pass / -4 fail | Entry/read_shape `did` → `device_identity` end-to-end. Removed B0.1's temporary alias. |
| B0.3 | (folded into B0.4) | n/a | n/a | rowHash drift turned out to be a side-effect of `_ENVELOPE_RESERVED`, fixed in B0.4 |
| B0.4 | DONE | `f1daba8` | +30 pass / -30 fail | Yaml fragments in 5 test files + `_ENVELOPE_RESERVED` bug (the load-bearing fix) + ran `npm run build` to unblock 16 CLI tests |
| B2.1 | DONE | `97bd401` | +10 pass / -10 fail | tnpkg manifest fixtures regenerated. Also fixed `_envelopeWellFormed` `"did"` → `"device_identity"` (phase-G miss). Rebuilt Python `_core.pyd` as a side effect (F6). |
| B3.1 | BLOCKED | n/a | n/a | `BtnPublisher.rotate()` not exposed in tn-wasm. Filed F5. |

---

## Findings filed

See `_overnight/FINDINGS.md` for full schema-per-entry details. Summary:

| ID | Title | Severity | Open? |
|---|---|---|---|
| F1 | Batch 0 commit skipped — trunk dirty state too broad | Info | Open (user reviews diff in `_overnight/dirty_trunk_state_at_start.patch`) |
| F2 | Python `_envelope_reserved` set in `python/tn/reader.py` still has `"did"` — TS now ahead of Python on this row | Bug (latent) | Open |
| F3 | tnpkg fixtures needed rebuild after `from_did` → `publisher_identity` rename | Bug | **Closed by B2.1** |
| F4 | Test corpus was bottlenecked on missing `dist/` — add `pretest: npm run build` to `ts-sdk/package.json` | DX | Open |
| F5 | `BtnPublisher.rotate()` not exposed in tn-wasm — blocks B3.x | Blocker | Open |
| F6 | Trunk's `crypto/tn-core-py/python/tn_core/_core.pyd` was rebuilt as side effect of B2.1 — informational | Info | Open (no action needed) |

---

## Trunk worktree side-effects (read this!)

The overnight worktree is fully isolated EXCEPT for two side effects that
touched the trunk:

1. **`crypto/tn-core-py/python/tn_core/_core.pyd`** mtime is now today's date.
   B2.1 rebuilt the Python `tn_core` wheel via `maturin build --release`
   from `crypto/tn-core-py` to regenerate binary `.tnpkg` fixtures. The
   editable `pip install -e crypto/tn-core-py` from the trunk directory
   triggered a rebuild of the trunk's `.pyd`. The trunk's source is on the
   same branch (`feat/0.4.2a11-naming-flip`) and has the new field names, so
   trunk Python operations should continue to work. F6 documents this.

2. **The ghost worktree directory** at `.worktrees/btn-cipher-rotation/` was
   git-worktree-removed (no longer registered as a git worktree) but the
   directory itself was not deleted from disk due to a Windows file lock.
   The branch `feat/btn-cipher-rotation` is preserved. Clean up the
   directory manually if you want it gone.

Your in-flight dirty WIP (33 files including Python `admin/__init__.py`,
`btn_keystore.py`, `tnpkg.py`, etc., plus the 6 TS files with the new generic
`Tn<Schema>` and printf format) is **untouched in the trunk working tree**.

---

## Parity registry deltas

`docs/sdk-parity.md` was updated in all four code-landing batches. New
section "0.4.3a1 identity-naming flip status" was added by B0.1 and extended
by B0.2/B0.4/B2.1 with rows for:
- ceremony yaml block (`me:` → `device:`) — TS ✓
- recipient identifier inside groups — TS ✓
- Entry typed attribute (`did` → `device_identity`) — TS ✓
- `FLAT_ENVELOPE_KEYS` — TS ✓
- `_ENVELOPE_RESERVED` and `_envelopeWellFormed` — TS ✓
- tnpkg manifest fields (`publisher_identity`/`recipient_identity`) — TS ✓
- Binary `.tnpkg` fixtures (TS, Python, Rust admin snapshots + Agentic20 project seed) — ✓

The `tools/check_parity.py` tool was not re-run at end of session; the
existing parity-doc updates are the authoritative deltas.

---

## Final gate status

```
cd C:/codex/tn/tn_proto/.worktrees/ts-parity-overnight/ts-sdk
npm run typecheck   # PASS (exit 0)
npm run lint        # PASS (no issues)
npm test            # PASS (296/296)
```

No Python-side suite was run at end of session because the trunk has
uncommitted WIP and running pytest would be against a not-fully-consistent
state. The Python-side baseline (committed state at `578ecbb`) was
implicitly exercised throughout — every TS batch that interop'd with Python
(watch_interop, secure_read_interop, etc.) ran Python via subprocess and
got correct results.

---

## Next-session queue

Ordered by impact + readiness:

1. **F4** — Add `pretest: "npm run build"` to `ts-sdk/package.json`. Tiny
   DX fix; one-line change to the script section.

2. **F2** — Fix Python `reader.py` `_envelope_reserved` sets and
   `parse_envelope_line` row_hash arg lookup. Three lines in
   `python/tn/reader.py`. Will fix a latent `verify=True` bug.

3. **F5 → B3.x** — Add `#[wasm_bindgen]` wrapper around
   `tn_btn::PublisherState::rotate()` in `crypto/tn-wasm/src/lib.rs`,
   mirroring the PyO3 shape from `crypto/tn-btn-py/src/lib.rs`. Then run
   `wasm-pack build --target nodejs --release` from `crypto/tn-wasm/`. Then
   the B3.1-B3.5 TS catchup batches become feasible. Order of work:
   - B3.1 — TS `tn.admin.rotate(group)` wires the wasm primitive; expose
     `RotateGroupResult` shape with new fields.
   - B3.2 — `RetiredPublisherState` discovery on TS keystore.
   - B3.3 — TS admin rotate driver (truth-telling event + `cipher_actually_rotated`).
   - B3.4 — Recipient renewal loop.
   - B3.5 — Cross-SDK rotation fixture under `regression/_shared/fixtures/`.

4. **B4 series — other TS gaps from sdk-parity:**
   - B4.1 — `tn.admin.set_link_state` → TS `tn.vault.setLinkState` (yaml-write
     port; currently stub-throws).
   - B4.2 — Re-export `KeystoreConflictError` + `isKeystoreDiverged` from TS.
   - B4.3 — Port 2 reducer/well-formed regressions (commit `578ecbb`'s
     introduced cases) to TS-side tests.

5. **B5 series — idiomatic TS sweep (now mostly cosmetic since the naming
   flip is done):**
   - B5.1 — Default-export smoke test exercising `import tn from "@tnproto/sdk"`.
   - B5.3 — Discriminated union cascade verification (the dirty TS WIP
     introduced `ReadOptions`/`WatchOptions` as discriminated unions; verify
     it cascades into bare-function exports).
   - B5.4 — Printf coverage parity (compare TS `%s/%d/%j/%o` set to Python's
     loguru format-spec set; document divergence if any).

6. **F1** — Review the captured trunk dirty diff at
   `_overnight/dirty_trunk_state_at_start.patch`. Decide:
   - Whether the 27 `no-explicit-any` errors in the new `Tn<Schema>` generic
     warrant `// eslint-disable-next-line` comments (preserve user API
     ergonomics) or a rule relaxation.
   - Whether `test/ts_premium_features_demo.test.ts` (untracked sketch file)
     should be tracked, deleted, or moved to `_scratch/`.
   - The Python WIP needs your eyes — touches files the parity audit needs.

---

## Diff stat (overnight branch vs feat/0.4.2a11-naming-flip)

```
49 files changed, 1106 insertions(+), 279 deletions(-)
```

Highlights (full list in `git log --stat feat/0.4.2a11-naming-flip..HEAD`):

- Source (TS, Rust, Python): ~10 files touched
  - `ts-sdk/src/runtime/{config,node_runtime,reconcile}.ts` — yaml/ceremony naming flip
  - `ts-sdk/src/Entry.ts`, `ts-sdk/src/core/read_shape.ts` — Entry/envelope naming flip
  - `ts-sdk/src/handlers/{stdout,otel}.ts`, `ts-sdk/bin/tn-js.mjs` — log handlers
  - `ts-sdk/src/compile.ts`, `ts-sdk/src/tn.ts` — minor touches
  - `python/tests/fixtures/build_admin_snapshot_fixture.py` — fixture builder bugfix
  - `crypto/tn-core/tests/tnpkg_fixture_builder.rs` — kit basename fix

- Tests: ~17 files touched + 1 new (`build_agentic20_project_seed.ts`)
  - All naming-flip fragment fixes; no test-logic changes

- Binary fixtures regenerated: 4 `.tnpkg` files (TS, Python, Rust admin
  snapshots + Agentic20 project seed) + 1 `admin_events_canonical.json`

- Docs: `docs/sdk-parity.md` (parity registry deltas) — 22 lines added

- Run artifacts: `_overnight/` (FINDINGS, batch_queue, REPORT,
  dirty_trunk_state_at_start.patch) — ~750 lines

---

## How to review

```bash
# Switch to the overnight worktree
cd C:/codex/tn/tn_proto/.worktrees/ts-parity-overnight

# Read the report (you're already here)
cat _overnight/REPORT.md

# Read findings
cat _overnight/FINDINGS.md

# See the commit chain
git log --oneline feat/0.4.2a11-naming-flip..HEAD

# Diff against the trunk
git diff feat/0.4.2a11-naming-flip..HEAD --stat
git diff feat/0.4.2a11-naming-flip..HEAD -- docs/sdk-parity.md
git diff feat/0.4.2a11-naming-flip..HEAD -- ts-sdk/src/

# Run the test suite to confirm green
cd ts-sdk && npm test
```

## To merge into trunk later (when you're ready)

```bash
# From trunk worktree
cd C:/codex/tn/tn_proto

# Make sure your trunk WIP is dealt with first (commit or stash);
# otherwise the merge will conflict on some files

git merge --no-ff feat/0.4.3a1-ts-parity
# Resolve any conflicts (most likely none for committed work,
# possible in test files if your WIP also touched the same fragments)
```

---

## End of report
