# Walk tier — placeholder

The walk tier is **designed but not built** as of the Foundation PR.
It gets implemented after crawl is locked-green.

This file exists so the directory isn't empty and the `regression/`
tree is uniformly browsable.

## Planned silos

Per the plan doc (`docs/superpowers/plans/...`), walk-tier silos:

| candidate | what it would prove |
|---|---|
| **W1 — Recipient flow end-to-end** | Alice mints invite → Frank claims via vault → Frank receives `.tnpkg` → Frank's machine absorbs → log delivered out-of-band → Frank decrypts. TN provides crypto; log transport is dev's problem. |
| **W2 — Cross-language workflow** | Python publisher → TS reader and the reverse. Extends C5 across runtimes. |
| **W3 — Multi-machine vault sync nuances** | yaml/keystore staying consistent across re-syncs; conflict resolution; generation counter behavior. |
| **W4 — Handler variants** | `file.timed_rotating`, `fs.drop`, `fs.scan`, `vault.push` for admin-log distribution. |
| **W5 — Jupyter onboarding path** | Notebook-driven `tn.init()` + auto-link with the IPython display path. Late-walk per direction. |

## How walk silo design will work

Same shape as crawl: each silo gets a directory, README with failure-
investigation table, named-assertion tests, a Make target, a CI job.

The walk tier introduces **multi-process / multi-tempdir** patterns
(e.g. W1 needs Alice's machine state + Frank's machine state
simultaneously). The plan is to use the existing pytest fixtures
pattern from `tn_proto_web/tests/e2e/conftest.py` as the reference for
how to manage that — lift the pattern into `_shared/` rather than
import from there.

## When walk gets built

Crawl must be locked-green first. Once crawl is in regression CI as a
required check on every PR, the walk-design pass starts and silos land
PR-by-PR following the same per-silo PR shape as crawl.
