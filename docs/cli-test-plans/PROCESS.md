# Combined process: fix the bug, then test the bug

One unit of work = one bug. Order is fixed: **reproduce → fix → regression test → verify**.
The test is written AFTER the fix, but must be proven to FAIL without it (revert/mutation),
so it's a real regression test, not a description of whatever the code happens to do.

## The five steps (every bug)
1. **Reproduce** — run the thing, capture the actual wrong output/exit/exception. If you can't reproduce it, it isn't a bug yet — stop.
2. **Root cause** — name the exact line and why it's wrong (not the symptom).
3. **Fix** — smallest change that addresses the root cause. No "while I'm here."
4. **Regression test** — write a test that asserts the now-correct behavior, then **revert the fix and confirm the test goes RED**, re-apply and confirm GREEN. If it can't go red, it isn't testing the fix.
5. **Verify** — the bug's test passes, the verb's other tests still pass, and (if the bug enabled wrong data through) the negative case is asserted.

## Hard rules (carried from the campaign)
- **No mock-to-green.** If a real test can't genuinely pass (missing infra/feature), leave it OUT and document why — the absence is the signal, a fake pass is a lie.
- **Real artifacts, real round-trips.** Produce inputs with the real originate verb; don't hand-build fixtures to dodge the actual path (that's how the `inbox accept` entry-name bug hid).
- **One file per agent** when fanning out; only the designated owner touches shared files (`bin/tn-js.mjs`, `package.json`, `cli.py` dispatch). Report new test filenames for registration rather than editing the run-set.
- **Mutation-check the negative cases** (forged sig, broken chain, wrong recipient) — prove the assertion bites the specific check, not just `row_hash`.

## Reusable agent template (fill `{{BUG}}`, `{{FILES}}`)
```
Fix ONE bug, then write its regression test. Repo: C:\codex\tn\tn_proto.
Edit ONLY: {{FILES}} (own files + the bug's test file). Do NOT touch
bin/tn-js.mjs / package.json / cli.py dispatch unless you are the named owner.

BUG: {{BUG}}  (symptom + suspected line)

1. REPRODUCE: run it, paste the actual wrong output/exit/exception.
2. ROOT CAUSE: the exact line and why it's wrong.
3. FIX: smallest change at the root cause.
4. REGRESSION TEST: assert the correct behavior; then REVERT the fix and
   confirm the test goes RED, re-apply and confirm GREEN. Cite both runs.
5. VERIFY: bug test passes + the verb's other tests still pass.

HARD RULE: no mock-to-green. If a real test can't pass without infra/feature
that doesn't exist, leave it OUT with a comment (it shows as a gap). Use the
real originate verb to produce inputs — never hand-build fixtures to dodge the path.

Run: TS `cd ts-sdk && node --import tsx --import ./test/_setup_wasm.mjs --test test/<f>.test.ts`
     Py `cd python && COVERAGE_CORE=sysmon PYTHONPATH=. <venv>/python -m pytest -q tests/<f>.py`

REPORT: reproduce output, root cause, fix (line refs), RED→GREEN proof, what (if anything) was left out and why.
```

## Commit shape
- One commit per bug (or per tight group), message = `Fix <verb>: <bug> + regression test`.
- New TS test files get registered in `package.json` by the integrator after the agents report.
