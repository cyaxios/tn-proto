# Batch queue — populated by Phase 1 audit

Ordered list of batches drawn from `docs/sdk-parity.md` ⊝ rows plus post-0.4.3a1
gaps the audit identifies. Phase 1 fills this; Phases 2-5 drain it.

Format per batch:
```
- [ ] B<phase>.<n> — <one-line description> (sdk-parity row: `<verb>`)
```

When a batch lands, flip to `- [x]` and append the commit SHA.
When a batch is BLOCKED, mark `- [ ] [BLOCKED: F<n>]` with the finding number.

---

- [x] B0.1 — ts-sdk naming-flip phase B (ceremony yaml `me:` → `device:`, `recipient_identity` inside group recipients) + read_shape `device_identity → did` alias (commit pending). 213→252 passes, 83→44 failures (39 fewer). 2 new failures (ex02 envelope-shape, ex02 independent-verify) caused by wasm rebuild surfacing pre-existing phase G incompleteness in `Entry.fromFlat` / `FLAT_ENVELOPE_KEYS`. Wasm artifact rebuilt under `crypto/tn-wasm/pkg/` (gitignored) to expose the renamed Rust deserializer.
- [x] B0.2 — ts-sdk naming-flip phase G completion: `Entry.device_identity` typed attr (constructor + fromRaw + fromFlat + toJSON + util.inspect), `FLAT_ENVELOPE_KEYS` carries `device_identity` natively (alias removed), stdout/otel handler envelope-key sets flipped, `tn-js` CLI read output flipped, three internal envelope-readers (`tn.ts:_isForeignLog`, `_emitTamperedRowSkipped`, admin_cache forge-fork test) flipped. 252→256 passes, 44→40 failures. 4 tests went green: ex02/envelope-shape, ex02/independent-verify (the two B0.2 targets), AdminStateCache same-coordinate-fork (bonus from forge-envelope rename), stdout pretty format (bonus from test envelope rename). Zero regressions.
- [x] B0.4 — ts-sdk naming-flip phase G follow-through + scenario-test yaml flip. Three layers:
  1. **Build fix (16 CLI tests)**: `npm run build` was missing — CLI binary at `bin/tn-js.mjs` imports from `dist/`, not `src/`. Ran build; all 16 cli_rotate / cli_streams_validate / cli_watch tests went green with zero source changes. See F4.
  2. **`_ENVELOPE_RESERVED` set in `node_runtime.ts`** (1 line, but the big lever): the runtime's reserved-envelope-keys set still listed `"did"` instead of `"device_identity"`. Net effect: the read-side row_hash recompute pulled `device_identity` from the envelope into `publicFields`, hashed it both as a primary input AND as a public field, and every `verify: true` check failed. Phase G work that was missed in B0.2. Fixed all 9 `chain_verified` / row_hash failures: alice s01/s02/s03/s04/s06/s08 + ex02/all-entries-verify + read_shape `read({verify: true, raw: true})`.
  3. **Yaml-fragment flip (5 tests)**: `me: { did: ... }` → `device: { device_identity: ... }`, `recipients: - did: ...` → `recipients: - recipient_identity: ...` in five test files that build ceremony yamls inline:
     - `test/scenarios/alice/s07_field_routing.test.ts`
     - `test/scenarios/alice/s09_multi_recipient.test.ts`
     - `test/scenarios/examples/ex03_groups.test.ts` (2 tests in 1 file)
     - `test/core_browser_contract.test.ts` (`rowHash({did: ...})` → `rowHash({device_identity: ...})`)
     - `test/sdk_smoke.test.ts` (both `rowHash` and `buildEnvelopeLine` calls)

  Test impact: 256→286 passes (+30), 40→10 failures (-30). Zero regressions. Typecheck + lint clean.

  Findings filed:
  - **F2** — Python `_envelope_reserved` (in both `parse_envelope_line` AND `_read`) still has `"did"` post-flip, and `parse_envelope_line` line 551 passes `env.get("did", "")`. The streaming `_read` path's `_envelope_reserved` set has the same bug (would leak `device_identity` into `public_out`). Out of scope for this TS-only worktree; tagged for a follow-on Python batch.
  - **F3** — 10 remaining failures all flow from the `from_did → publisher_identity` manifest field rename outpacing the binary `.tnpkg` fixtures. The TS reader strictly requires `publisher_identity`; fixtures still emit `from_did`. Needs a "tnpkg manifest field flip" batch.
  - **F4** — `pretest: "npm run build"` should be added to `ts-sdk/package.json` so future runs always have a fresh dist. Trivial; deferred.

  Remaining 10 failures (all F3-category — fixture rebuild blocked):
    - tnpkg_interop: Rust-produced admin_log_snapshot parses in TS
    - tnpkg_interop: manifest canonical bytes match golden across languages
    - tnpkg_export_absorb: export → absorb on fresh peer applies envelopes
    - tnpkg_export_absorb: absorb surfaces leaf reuse
    - dirt_easy_flow: project_seed bootstrap returns usable Tn
    - identity_project_seed: project_seed real-fixture round-trip
    - secure_read_interop: required byte-compare fixtures present (literally missing)
    - secure_read_interop: TS local admin_events matches committed fixture
    - secure_read_interop: Python admin_events byte-compare
    - secure_read_interop: Rust admin_events byte-compare

- [x] B2.1 — tnpkg manifest from_did → publisher_identity + fixture rebuild (resolves F3). Five layers:
  1. **Producer audit**: all three SDK writers (Rust `crypto/tn-core/src/tnpkg.rs`, Python `python/tn/tnpkg.py`, TS `ts-sdk/src/core/tnpkg.ts`) already emit the new wire field names — no writer source change required. Python keeps `from_did`/`to_did` as the internal dataclass attribute but serialises them as `publisher_identity`/`recipient_identity` on the wire. Confirmed via grep before any edits.
  2. **TS canonical scenario flip** (`ts-sdk/test/fixtures/secure_read_canonical_scenario.ts`): `tn.coupon.issued.to_did` → `recipient_identity`; `tn.enrolment.absorbed.from_did` → `publisher_identity`. Brought TS into line with Python/Rust scenarios. Regenerated `admin_events_canonical.json` via `build_secure_read_fixtures.ts` — now byte-identical across all three SDKs.
  3. **TS golden-bytes test flip** (`ts-sdk/test/tnpkg_interop.test.ts:169`): the inline-literal "manifest canonical bytes match golden" comparison still asserted the legacy `from_did`/`to_did` keys. Flipped to `publisher_identity`/`recipient_identity` so the test matches the renamed wire.
  4. **Fixture regeneration** (4 binary fixtures):
     - `ts-sdk/test/fixtures/ts_admin_snapshot.tnpkg` (new): minted by `build_admin_snapshot_fixture.ts` against the renamed wire.
     - `python/tests/fixtures/python_admin_snapshot.tnpkg` (new): minted by `build_admin_snapshot_fixture.py` after a one-line builder fix (`leaf_index=leaf_a` → `leaf_a.leaf_index` — `add_recipient` returns `AddRecipientResult`, not int). Required rebuilding `tn_core-py` wheel via `maturin build --release` first because the editable install in the venv was lagging behind commit `d73b7f1`; restored editable install after the build so the trunk venv is unaffected.
     - `crypto/tn-core/tests/fixtures/rust_admin_snapshot.tnpkg` (rebuild): regenerated via `cargo test -p tn-core --features fs --test tnpkg_fixture_builder -- --ignored` after a builder fix (kit basenames `alice.kit` / `bob.kit` → `alice.btn.mykit` / `bob.btn.mykit` to satisfy the `kit_bundle` exporter's regex).
     - `Agentic20.project.tnpkg` (both TS and Python copies): minted from scratch by a new helper `ts-sdk/test/fixtures/build_agentic20_project_seed.ts`. The committed binary on `main` was already corrupted in transit (UTF-8 replacement characters injected into the zip bytes; `parseTnpkg` chokes on it, Python `zipfile` raises `BadZipFile`). The fresh fixture mints a real btn ceremony in a tempdir, harvests `tn.yaml` + keystore, and wraps as a signed project_seed manifest with the post-0.4.3a1 yaml shape.
  5. **`_envelopeWellFormed` phase-G miss** (`ts-sdk/src/runtime/node_runtime.ts:2402`): the absorb-side admin-snapshot gate was still checking `env["did"]`. Without this, `_absorbAdminLogSnapshot` discarded every snapshot envelope and returned `acceptedCount: 0`. Flipped to `device_identity`. Resolves 2 tests that the F3 finding had attributed to fixture issues but were actually a separate naming-flip gap.

  Test impact: 286→296 passes (+10), 10→0 failures. Zero regressions. Typecheck + lint clean.

  No new findings filed — B2.1 closed F3 and incidentally caught a phase-G gap that wasn't in F2's scope. The Python `_envelope_reserved` gap (F2) and `pretest: npm run build` follow-on (F4) remain open.

- [ ] [BLOCKED: F5] B3.1 — TS wiring of BTN cipher rotate. Probe revealed `BtnPublisher.rotate()` is not exposed in `crypto/tn-wasm/pkg/tn_wasm.d.ts` (zero `rotate` symbols). The Rust `tn_btn::PublisherState::rotate()` exists (commit 73cf761) and the PyO3 surface exists (commit e75cf56), but the wasm-bindgen wrapper was missed. Needs a Rust+wasm batch before any of B3.1-B3.5 can proceed. F5 filed with the recommended fix shape.

- [ ] B3.2-B3.5 — TS BTN rotation parity (retired publisher state, admin rotate driver, recipient renewal, cross-SDK rotation fixture). All blocked downstream of B3.1.

- [ ] B4.1 — `set_link_state` → TS `tn.vault.setLinkState` (yaml-write port). Deferred to next session.
- [ ] B4.2 — Re-export `KeystoreConflictError` + `isKeystoreDiverged` from TS. Deferred.
- [ ] B4.3 — Port 2 reducer regressions (commit 578ecbb cases) to TS-side tests. Deferred.

- [ ] B5.1 — Default-export consumer smoke test. Deferred.
- [ ] B5.3 — Discriminated union cascade verification. Deferred.
- [ ] B5.4 — Printf coverage parity with Python's loguru format-spec set. Deferred.

---

## End-of-session summary

**Test suite: 296/296 fully green** (started at 213 pass / 83 fail).
Five commits on `feat/0.4.3a1-ts-parity` (Phase 0 scaffold + B0.1 + B0.2 + B0.4 + B2.1).
B3.1 blocked on F5. B3.2-B5.4 deferred to next session.
See `_overnight/REPORT.md` for the full handover.
