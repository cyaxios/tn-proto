# tn-core

TN protocol runtime (Rust). See [the plan](../../../docs/superpowers/plans/2026-04-21-tn-rust-core-phases-0-3.md).

## Status

- **Phase 0 (scaffold + fixtures):** complete.
- **Phase 1 (primitives):** complete — `canonical`, `chain`, `indexing`, `signing`, `envelope` all byte-equal to the Python oracle against the golden corpus in `tests/fixtures/`.
- **Phase 2 (cipher adapters):** in progress — btn first-class; JWE/BGW stubbed.
- **Phase 3 (runtime + CLI):** not started.

Regenerate fixtures with:

```bash
.venv/Scripts/python.exe tn-protocol/python/tools/generate_rust_fixtures.py
```
