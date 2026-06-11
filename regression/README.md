# TN regression test platform

The managed regression suite for the TN protocol stack. **The crawl tier
must be green before any release ships.**

## Why this exists

The repo had ~1,100 tests scattered across `python/tests/`,
`ts-sdk/test/`, `python/scenarios/`, `ts-sdk/test/scenarios/`,
`tn_proto_web/tests/e2e/`, `tn_proto_web/tests_ui/`,
`extensions/tn-decrypt/test/`, and `crypto/tn-wasm/test/`. They cover a
lot, but they don't tell a coherent story when something breaks. This
tree is the single place a maintainer comes to ask "is the platform OK?"
and a contributor comes to ask "where do I add coverage for the flow I
just touched?"

## Conventions in one breath

- **Use cases, not consumer modalities.** Silos are named after what a
  user is trying to do (`c7_key_custody_default`), not what runs the
  code (Python lib / TS lib / browser). Runtimes are variants inside a
  silo.
- **Named assertions, no bare equality.** Every check has a name and
  prints `expected: …, observed: …, look at: …` on failure. See
  [`_shared/README.md`](_shared/README.md).
- **TN-native assertions query the attested log.** When the flow under
  test is TN's own protocol, the assertion is "find an envelope where
  `event_type=… AND group=…`," and the failure prints the row_hash +
  sequence of the closest match (or the whole list of event_types
  present on miss).
- **Self-documenting tests.** Every test file starts with a structured
  preamble (`SILO`, `TEST`, `SEE`, `Flow`, `Asserts (named)`, `Failure
  modes`). Every silo has a README with a failure-investigation table.
- **No "emit" terminology.** Public verbs only: `tn.log`, `tn.info`,
  `tn.warning`, `tn.error`, `tn.debug` — in code, comments, docstrings,
  test names.

## Silo index

### Crawl (foundational — green-or-no-release)

| # | silo | what it proves |
|---|---|---|
| C1 | [`c1_python_module_log`](crawl/c1_python_module_log/) | `tn.init()` + module verbs round-trip on Python; default file handler + stdout |
| C2 | [`c2_python_object_log`](crawl/c2_python_object_log/) | `t = tn.use(name); t.info(...); t.read()` round-trip on Python |
| C3 | [`c3_ts_module_log`](crawl/c3_ts_module_log/) | Top-level `tn.info(...)` round-trip on Node |
| C4 | [`c4_ts_object_log`](crawl/c4_ts_object_log/) | `Tn` class instance round-trip on Node |
| C5 | [`c5_groups_recipients_inproc`](crawl/c5_groups_recipients_inproc/) | Local groups + recipients, single-machine, separate-kit decrypt |
| C6 | [`c6_cli_verbs`](crawl/c6_cli_verbs/) | `tn init / add_recipient / rotate`; yaml + vault stay consistent |
| C7 | [`c7_key_custody_default`](crawl/c7_key_custody_default/) | **Load-bearing**: init mints keys, auto-backs-up, claim URL works |
| C8 | [`c8_restore_new_machine`](crawl/c8_restore_new_machine/) | Fresh install → pull keys → chain continues seamlessly |
| C9 | [`c9_chrome_ext_decrypt`](crawl/c9_chrome_ext_decrypt/) | Chrome extension inline decryption against fixture data |

### Walk (next round — designed, not built)

See [`walk/README.md`](walk/README.md).

### Run (deferred — no test code)

Serverless deployment (Vercel/AWS Lambda), tier-3 org/multi-team vault,
MCP / AI-agent integration. Listed in the design doc but not
implemented; record where they slot in for future planning.

## How to run

```bash
# Everything (currently: just crawl)
make -C regression all

# Whole crawl tier
make -C regression crawl

# Single silo
make -C regression c7

# Just the Python silos (C1, C2, C5, C6, C7, C8)
make -C regression crawl-python

# Just the TS silos (C3, C4)
make -C regression crawl-ts

# Just the browser silo (C9)
make -C regression crawl-browser
```

A failing silo prints its named-assertion report to stdout AND drops a
JSON report at `regression/.reports/<silo>/last.json` for CI to pick
up as a build artifact.

## How to add a new silo

1. Pick a number (next crawl is `c10_*`, walk numbering starts at `w1_*`).
2. `mkdir regression/<tier>/c<N>_<name>/`
3. Copy the README skeleton from an existing silo and fill in:
   - **What this silo proves** — one paragraph
   - **Why it's load-bearing** — one paragraph
   - **Code paths exercised** — bullet list with file:line refs
   - **Tests in this silo** — bullet list of test filenames with one-liner each
   - **How to run only this silo** — exact command
   - **Failure investigation guide** — table mapping symptom → first place to look
4. Write tests following the inline preamble convention.
5. Add a Make target.
6. Add a CI job in `.github/workflows/regression-crawl.yml`.
7. Open a PR with the silo's directory + Make target + CI job in one
   commit. Don't mix multiple silos in one PR.

## Failing test? Three steps:

1. **Read the test's preamble.** It names the silo, the flow, the
   assertions, and where to look for the cause.
2. **Read the silo's README "Failure investigation guide" table.**
   Match the symptom to a code path.
3. **Look at `regression/.reports/<silo>/last.json`** for the
   structured failure record (named assertion, expected, observed,
   pointer).

If those three don't tell you what broke, the test is under-instrumented
— fix the test docs in the same PR that fixes the bug. The bar is "an
LLM reading the preamble + README can locate the breakage without
spelunking."

## Reference (vibe only, not migrated)

Old test trees we looked at for ideas. Do not depend on them; do not
copy from them blindly. They will eventually be retired.

- `python/tests/` — Python unit tests (stay as unit tier)
- `ts-sdk/test/` — TS unit tests (stay as unit tier)
- `python/scenarios/` — persona scenarios (interesting reference for
  persona registry shape)
- `ts-sdk/test/scenarios/` — TS persona scenarios
- `tn_proto_web/tests/e2e/` — existing Playwright multi-context
  (FastAPI subprocess + mongomock-motor pattern worth lifting)
- `tn_proto_web/tests_ui/` — existing Playwright headless (dashboard
  wasm exercises)
- `crypto/tn-wasm/test/` — cross-language interop drivers (byte-compare
  shapes worth keeping)
- `extensions/tn-decrypt/test/` — Chrome extension test harness

## Plan + history

The design that produced this tree:
`C:\Users\gilsa\.claude\plans\rosy-tumbling-sifakis.md`.

Each silo PR should link to this README in its description.
