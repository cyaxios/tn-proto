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

(Phase 1 will populate this; placeholder for now.)
