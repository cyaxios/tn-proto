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

(Phase 1 will populate the rest of this; placeholder.)
