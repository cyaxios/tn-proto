# Crawl tier — foundational silos

**The crawl tier is the green-or-no-release bar.** If anything here is
failing, the platform is not shippable. This is also the tier most
likely to catch the kind of bug that takes down basic users.

## Tier philosophy

Crawl tests are:

- **Single-machine, single-process** where possible. No cross-network
  surprises in this tier.
- **No real OAuth.** If a silo needs an authenticated vault, it uses
  the test vault's dev-mode auth (see C7).
- **No real CF Workers.** FastAPI subprocess + mongomock-motor or a
  real local Mongo (CI uses local mongomock for speed; local
  developer can override).
- **Deterministic.** Personas have fixed seeds; no OS RNG decides
  anything that the test then asserts on.
- **Fast.** Each silo should run in <60s locally. The full tier
  should run in <10 min.

## The 9 silos

| # | dir | runtime | what it proves |
|---|---|---|---|
| C1 | [`c1_python_module_log/`](c1_python_module_log/) | Python | Module-level: `tn.init()` + `tn.info` etc. → `tn.read()` round-trip; default file handler + stdout |
| C2 | [`c2_python_object_log/`](c2_python_object_log/) | Python | Object-level: `t = tn.use(name); t.info(...); t.read()` round-trip |
| C3 | [`c3_ts_module_log/`](c3_ts_module_log/) | TS / Node | Top-level `tn.info(...)` round-trip on Node |
| C4 | [`c4_ts_object_log/`](c4_ts_object_log/) | TS / Node | `Tn` class instance round-trip on Node |
| C5 | [`c5_groups_recipients_inproc/`](c5_groups_recipients_inproc/) | Python | Groups + recipients, single machine, separate-kit decrypt |
| C6 | [`c6_cli_verbs/`](c6_cli_verbs/) | Python (subproc) | `tn init / add_recipient / rotate`; yaml + vault stay consistent |
| C7 | [`c7_key_custody_default/`](c7_key_custody_default/) | Python + test vault | Load-bearing: init mints keys, auto-backs-up, claim URL works |
| C8 | [`c8_restore_new_machine/`](c8_restore_new_machine/) | Python + test vault | Fresh install → pull keys → log chain continues seamlessly |
| C9 | [`c9_chrome_ext_decrypt/`](c9_chrome_ext_decrypt/) | Browser + ext | Chrome extension inline decryption against fixture data |

## How to run

```bash
# Whole tier
make -C regression crawl

# By runtime
make -C regression crawl-python    # C1, C2, C5, C6, C7, C8
make -C regression crawl-ts        # C3, C4
make -C regression crawl-browser   # C9

# Single silo
make -C regression c7
```

Reports land at `regression/.reports/c<N>/last.json` regardless of
pass/fail.

## Sequencing (PR-by-PR build-out)

Per the design doc:

1. **Foundation** (this commit) — tree skeleton + `_shared/` utilities + CI scaffolding.
2. **C1 + C3** — module-level on both runtimes. Simplest round-trip; shakes out `_shared/`.
3. **C2 + C4** — object-level on both runtimes. Singleton-vs-instance dispatch parity.
4. **C5** — groups + recipients in-process. Introduces recipient persona.
5. **C6** — CLI verbs. Adds subprocess invocation pattern.
6. **C7** — default key custody (load-bearing onboarding). Requires test vault.
7. **C8** — restore on new machine. Extends C7 with a second tempdir.
8. **C9** — Chrome extension. Most external tooling; saved for last.

Each PR ships one silo, green, with the per-silo README + failure-
investigation table. Walk tier is scaffolded but not built until crawl
is locked.

## Per-silo skeleton

Each silo directory has the same shape:

```
c<N>_<name>/
├── README.md                  # what flow, why, code paths, failure guide
├── test_*.py  OR  *.test.ts   # the actual tests
└── (silo-local fixtures)      # canned ceremonies/kits specific to this silo
```

A new silo's README must include:

- **What this silo proves** (one paragraph)
- **Why it's load-bearing** (one paragraph)
- **Code paths exercised** (bullet list with file:line refs)
- **Tests in this silo** (one-liner per test file)
- **How to run only this silo** (exact command)
- **Failure investigation guide** (table: symptom → first place to look)
