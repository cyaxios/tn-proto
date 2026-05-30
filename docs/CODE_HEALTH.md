# Code health: report + ratchet

This repo tracks first-party source size and enforces a one-directional
"ratchet" on it: **files may only shrink.** No file may grow past its
recorded budget, and no new file may be born over the global ceiling. The
goal is to keep the largest modules from creeping further while refactors
chip them down over time.

Two pieces:

- `scripts/code_health.py` -- the **report**. Scans the source tree and
  prints a worst-first table (and optional JSON).
- `scripts/check_code_health.py` -- the **ratchet gate**. Compares the live
  tree against `.code-health-budget.json` and fails CI on any growth.

Both share the same scanner, so the report and the gate always agree on
which files count and how lines are counted. Both run in CI as steps of the
existing `complexity budget (radon)` job.

## What gets scanned

```
python/tn/**.py
ts-sdk/src/**.ts
ts-sdk/bin/**.mjs
crypto/*/src/**.rs
```

Excluded anywhere in the path: `.venv`, `node_modules`, `pkg`, `pkg-web`,
`target`, `__pycache__`, `dist`, `.worktrees`, and `tests` / `test` /
`__tests__` directories. Generated `.d.ts` stubs are skipped too.

## Running the report

```bash
# Human table, worst 30 files:
python scripts/code_health.py

# All files:
python scripts/code_health.py --top 0

# Machine-readable JSON (for tooling / the gate):
python scripts/code_health.py --json report.json
python scripts/code_health.py --no-table --json -   # JSON to stdout
```

Columns: total **LINES** (the budget unit), code **LOC** (blank/comment
lines stripped), language, the **longest function** and its length, and --
for Python -- the **max radon cyclomatic complexity** in the file. The CC
column reuses the same `radon` tooling the "complexity budget (radon)" CI
job already depends on; if radon is missing the column reads `n/a` and the
rest of the report still runs.

## Running the ratchet check

```bash
# Pass/fail gate (this is what CI runs):
python scripts/check_code_health.py

# After a refactor shrinks a listed file, lower its budget to match:
python scripts/check_code_health.py --update
```

## The budget / ratchet rule

`.code-health-budget.json` holds:

- `global_ceiling` -- the cap for **new / unlisted** source files
  (currently **800**).
- `files` -- a map of every file that was already at or over the ceiling
  when the ratchet was introduced, each pinned to its **current** physical
  line count (its grandfathered ceiling).

The rule, in one line:

> **Files may only shrink; no file may grow; new files must be under the
> global ceiling.**

Concretely the gate fails if:

1. a **listed** file **exceeds** its recorded budget (exit 1), or
2. a **new / unlisted** file exceeds the global ceiling (800 lines)
   (exit 1), or
3. the budget references a file that no longer exists -- a stale entry to
   remove (exit 2).

When a refactor shrinks a listed file, the budget is **lowered to match**
so the ratchet can never slip back up. Run
`python scripts/check_code_health.py --update` to rewrite
`.code-health-budget.json` with the new, smaller numbers, then commit it.
The check **never raises a budget automatically** -- growth is always a
deliberate, reviewed change to the JSON.

The budgets were seeded at current values, so CI is green on the day the
gate landed. Every entry is a debt to pay down, not a target to fill.

## Current top-20 backlog (worst-first)

Re-generate any time with `python scripts/code_health.py --top 20`.

| Rank | Lines | Lang | Longest fn (lines) | Max CC | File |
| ---: | ----: | ---- | --- | ---: | --- |
| 1 | 4927 | rust | `emit_inner` (766) | - | `crypto/tn-core/src/runtime.rs` |
| 2 | 3343 | python | `build_parser` (477) | 51 | `python/tn/cli.py` |
| 3 | 2902 | ts | `rotateGroup` (171) | - | `ts-sdk/src/runtime/node_runtime.ts` |
| 4 | 1882 | python | `state` (83) | 18 | `python/tn/admin/__init__.py` |
| 5 | 1790 | python | `_apply_enrolment` (109) | 27 | `python/tn/absorb.py` |
| 6 | 1503 | python | `_ceremony_create_lock` (82) | 14 | `python/tn/_multi.py` |
| 7 | 1499 | python | `_build_field_to_groups` (120) | 22 | `python/tn/config.py` |
| 8 | 1389 | python | `_auto_link_after_init` (83) | 21 | `python/tn/__init__.py` |
| 9 | 1382 | mjs | `adminCmd` (204) | - | `ts-sdk/bin/tn-js.mjs` |
| 10 | 1371 | ts | `init` (91) | - | `ts-sdk/src/tn.ts` |
| 11 | 1273 | rust | `resolve_admin_log_path` (1201) | - | `crypto/tn-core/src/admin_cache.rs` |
| 12 | 1101 | python | `decrypt_body_blob` (79) | 29 | `python/tn/export.py` |
| 13 | 986 | rust | `secure_read_js` (66) | - | `crypto/tn-wasm/src/runtime.rs` |
| 14 | 938 | python | `_load_from_disk` (77) | 26 | `python/tn/admin/cache.py` |
| 15 | 936 | python | `authenticate` (61) | 5 | `python/tn/vault_client.py` |
| 16 | 916 | rust | `admin_state` (132) | - | `crypto/tn-core-py/src/lib.rs` |
| 17 | 889 | ts | `constructor` (14) | - | `ts-sdk/src/browser/tn.ts` |
| 18 | 871 | python | `_push_snapshot` (89) | 11 | `python/tn/handlers/vault_push.py` |
| 19 | 867 | rust | `export` (98) | - | `crypto/tn-core/src/runtime_export.rs` |
| 20 | 823 | rust | `substitute_env_vars` (84) | - | `crypto/tn-core/src/config.rs` |

At the time this was seeded: **232 files** scanned,
**81,547 total lines**, **21 file(s) at or over 800 lines** (all
grandfathered into `.code-health-budget.json`).
