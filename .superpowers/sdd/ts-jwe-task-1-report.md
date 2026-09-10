# TypeScript JWE/BTN Fail-Closed — Task 1 Report

## Status

DONE_WITH_CONCERNS

Task 1 is implemented and committed as `3dbbdfd` (`fix(ts): fail closed when sealed groups cannot encrypt`). The commit contains exactly the four paths authorized by the brief.

## TDD RED evidence

Added two real-ceremony regression tests to `ts-sdk/test/seal_unseal.test.ts` before changing production code:

- JWE: initialized a JWE ceremony, removed `<keystore>/default.jwe.recipients`, called `client.seal(..., { receipt: false })`, and asserted the original `jwe: no recipients file for group "default"` error.
- BTN: initialized a BTN ceremony, reached the loaded private runtime with the repository's `as unknown as { _rt: ... }` cast pattern, cleared the loaded `default` group's `stateBytes`, called `client.seal(..., { receipt: false })`, and asserted the original `btn: no state file in this keystore` error.

Command:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test --test-name-pattern='seal fails closed' test/seal_unseal.test.ts
```

Result: exit 1, 2 tests run, 0 passed, 2 failed. Both failures were the expected `AssertionError [ERR_ASSERTION]: Missing expected rejection.` The output also showed the prior fail-open warnings for the missing JWE recipients file and missing BTN state, confirming that the old code warned, dropped the protected group, and returned instead of rejecting.

## Minimal production change

- `ts-sdk/src/core/sealed_object.ts`
  - Replaced the `try/catch/warn/continue` boundary with a direct awaited `ctx.sealGroup(...)` call.
  - Removed `SealContext.warn` and updated the adjacent context documentation.
- `ts-sdk/src/seal.ts`
  - Removed the Node seal adapter's now-unused `process.emitWarning` callback.
  - Did not change `NodeRuntime` or its normal log-emission behavior.
- `ts-sdk/src/browser/seal.ts`
  - Removed the browser seal adapter's now-unused `console.warn` callback.
  - Updated the adjacent comment to describe consistent error propagation.

The direct await preserves and propagates the original cipher error. Because the group loop now aborts on the first encryption failure, the later envelope hashing/signing path cannot produce a signed object with that protected group silently omitted.

## GREEN evidence

Focused regression and round-trip command:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test --test-name-pattern='seal fails closed|seal returns|unseal round-trips' test/seal_unseal.test.ts
```

Result: exit 0, 6 tests run, 6 passed, 0 failed. Passing coverage included both fail-closed regressions, the standalone sealed-object convention test, the default JWE unseal round trip, and the BTN and HIBE round trips.

Typecheck command:

```powershell
npm run typecheck
```

Result: exit 0 (`tsc --noEmit -p tsconfig.json`).

## Staged diff and commit review

Before commit:

- `git diff --cached --name-status` listed exactly:
  - `ts-sdk/src/browser/seal.ts`
  - `ts-sdk/src/core/sealed_object.ts`
  - `ts-sdk/src/seal.ts`
  - `ts-sdk/test/seal_unseal.test.ts`
- `git diff --cached --check` exited 0.
- The complete staged diff was inspected.
- Staged diff summary: 4 files changed, 43 insertions, 23 deletions.
- A final path-set guard ran immediately before `git commit` and refused to commit if the index differed from those four paths.

Commit:

```text
3dbbdfd fix(ts): fail closed when sealed groups cannot encrypt
```

## Self-review

- Requirements: both required cipher-specific missing-publisher cases are covered with real ceremonies and `receipt: false`.
- Error fidelity: assertions match the existing original BTN/JWE errors; production code does not wrap or replace them.
- Fail-closed boundary: no catch remains around `SealContext.sealGroup`, so no protected group can be skipped by `sealObjectCore` after encryption fails.
- API cleanup: `warn` is removed from the shared context interface and both Node/browser context construction sites.
- Scope: no `NodeRuntime` code was touched; all unrelated dirty/untracked files were preserved.
- Hygiene: each test closes the client and recursively removes its temporary ceremony in `finally`.
- Diff integrity: only the four brief-authorized paths were staged and committed; this report remains untracked and was not committed.

## Concerns

- A supplemental scoped Prettier check reports style issues in three of the four committed files. The same stdin-based Prettier check fails on the pre-Task-1 parent (`3dbbdfd^`) versions of all four scoped files, establishing this as existing repository formatting debt rather than a Task 1 regression. No broad formatter rewrite was made because it would add unrelated churn beyond the approved slice.
- The checkout contains many unrelated dirty and untracked files owned by other work. They were not staged, modified, or committed by Task 1.
