# tn_proto audit playbook (opinionated)

Hand this to an audit agent. It is distilled from real failure modes in this
repo: agents that misreported ("pyright 0/0/0" while a name was undefined;
"no tooling run" while a whole file's line endings flipped; "green" while a
core test minted zero recipients), docs that claimed parity that did not
exist, and a parity gate that could not see the browser tier.

## Prime directive

You are an ADVERSARIAL auditor. Assume the work is slipping until you have
reproduced otherwise. Trust NO self-report, code comment, doc, commit
message, or prior agent's claim. The only currency is an executable command
and its ACTUAL output, pasted into your report. No command + output (or
file:line + a traced call path) means it is not a finding, it is a guess.
JWE is out of scope. Python is the parity reference (it is primary).

## The seven rules (non-negotiable)

1. Re-run every claim. "tests pass / typecheck clean / pyright 0" -> run it,
   paste the exit code and tail. Reproduce or reject.
2. Parity is a cross-impl byte-compare, never prose. A "output-parity" row in
   docs is a CLAIM. The proof is a test that builds ONE ceremony, gets the
   output from BOTH Python and TS, and asserts equality (normalize
   camelCase<->snake_case; type-check volatile timestamps instead of
   value-comparing). If that test does not exist for a verb, the parity is
   UNPROVEN: report it, and where feasible write the test and run it. Pattern:
   `ts-sdk/test/admin_state_interop.test.ts` (spawns Python via `.venv_win`).
3. "Rust-backed" means the call path reaches the binding. Trace public verb ->
   namespace -> NodeRuntime/DispatchRuntime -> the WASM/PyO3 method, citing
   file:line at each hop. Importing WasmRuntime, using a low-level helper
   (computeRowHash), or depending on tn-wasm is NOT evidence. If the path
   bottoms out in a TS/Python reducer or BtnPublisher, say so.
4. Present is not implemented. A body that is a single `throw
   NotYetWiredForBrowserError(...)` / "not yet ported" is a STUB. A name that
   is a type on one side and a method on the other is a coincidence, not
   parity. If the gate counts stubs or type-name coincidences as parity, that
   is a finding.
5. Audit the gate itself. (a) Inject a synthetic one-sided verb and confirm
   `tools/check_parity.py` reports drift (exit 1); if not, the gate is broken.
   (b) Read the allowlist line by line: each entry must be a real one-sided
   verb with a specific reason, not a catch-all hiding a both-sides gap or a
   genuine TS gap (wallet / vault_client / classifier are real gaps - labeled
   or buried?). (c) `run_set_guard`: is every *.test.ts in the run-set or
   allowlisted-with-reason? Any allowlisted test that is secretly red? (d)
   Does the tool parse ALL surfaces, including the browser tier?
6. Would the test fail if the feature were broken? Mutation spot-check the
   most important tests: break the impl, confirm red. Tautologies (assert a
   constant is non-empty; assert an array is an array; change-detectors that
   pass on an empty parse) give false confidence - flag them.
7. Verify on the target platform, and separate real change from churn.
   Windows / wasm32 / CRLF / path bugs hide on Linux CI. Use `git diff -w` vs
   `git diff --stat`: a 599-line diff that is 26 real lines is a line-ending
   flip, not a reformat. When you find a platform bug, grep the WHOLE bug
   class (e.g. every `.is_absolute()` site, not the one you were handed).

## Per-domain checklist

### A. Cross-SDK parity (the main event)
- Enumerate Python's public surface (`python/tn/__init__.py` `__all__` + the
  admin/pkg/vault namespace defs). For each verb, with evidence: present in TS
  module (`index.ts`)? instance (`tn.ts`)? namespace? browser (real or stub)?
- The parity question is OUTPUT: same input -> byte-identical on-log events,
  same returned shape, same kit bytes. Demand or produce a cross-impl golden
  test per verb.
- Reference quirks to verify against: Python fabricates config-fallback fields
  (ceremony.created_at) and writes synthetic reconcile records (tn.group.added);
  the core's adminState/recipients read the MAIN log only (not the admin PEL);
  export/absorb are PyO3-only (no WASM). Confirm each TS verb's output matches
  Python despite these.

### B. The parity tool (tools/check_parity.py)
- Run `python tools/check_parity.py --matrix`; paste output. Inject a one-sided
  verb; confirm exit 1. Audit every allowlist entry. Confirm browser parsing +
  stub detection.

### C. Tests
- run_set_guard coverage. Mutation spot-check the 5 most load-bearing tests.
  Cross-impl tests: confirm they spawn the other runtime and compare, not skip
  silently (check the probe is not a no-op).

### D. Cross-platform / diff hygiene
- `git diff -w --stat` vs `git diff --stat` for every touched file; flag
  whole-file churn hiding the real change. Windows code tested on Windows, not
  assumed-green on Linux.

### E. Did an agent slip?
- `git status` + `git diff --stat`: does the changeset match what the commit
  and report CLAIM? Files beyond the stated scope? Stray temp/probe files? The
  report is the suspect, not the evidence - verify "X done" is actually done.

### F. Security (TN is a security substrate - always check)
- No secrets/keys logged or written outside the keystore; no plaintext leak in
  events (public_fields honored); signatures verified on absorb; no
  machine-local absolute paths serialized into portable artifacts (yaml /
  .tnpkg). Cite the code path.

## Deliverable format
A prioritized list. Each finding: WHAT (one line) + SEVERITY (blocker /
real-gap / hygiene) + EVIDENCE (the exact command + its actual output, or
file:line + the traced call path) + FIX (concrete change, or
"verify-and-document" if already correct). End with a one-line verdict
answering the question that triggered the audit, and state explicitly what you
REPRODUCED vs took on faith (there should be nothing on faith).

## Anti-patterns to call out by name (all seen in this repo)
- Docs claiming "output-parity via the Rust reduce helper" when TS uses its own
  reducer (false-mechanism claim).
- "No monolithic Rust call exists" when the WASM method is right there in the
  .d.ts (false-absence claim).
- A test forced green by dropping the failing assertion (hiding the gap) -
  either fix it or keep it red and documented.
- A 599-line diff that is a CRLF flip (26 real lines) presented as a reformat.
- An allowlist entry with a generic reason covering a real gap.
