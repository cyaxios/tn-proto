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

(Phase 1 will populate the rest of this; placeholder.)
