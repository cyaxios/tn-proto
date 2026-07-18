### Task 1: Fail Closed When Any Protected Group Cannot Seal

**Files:**
- Modify: `ts-sdk/test/seal_unseal.test.ts`
- Modify: `ts-sdk/src/core/sealed_object.ts`
- Modify: `ts-sdk/src/seal.ts`
- Modify: `ts-sdk/src/browser/seal.ts`

**Interfaces:**
- Consumes: `SealContext.sealGroup(gname, cipher, plaintext, aad)`.
- Produces: `sealObjectCore(...)` rejects with the original cipher error; it never signs an object after dropping a protected group.

- [ ] **Step 1: Add the failing BTN and JWE regression tests**

Add two tests to `test/seal_unseal.test.ts`. Each initializes a real ceremony, removes the relevant publisher material, calls `client.seal(..., { receipt: false })`, and asserts the original BTN or JWE error is propagated. For JWE, remove `<keystore>/default.jwe.recipients`. For BTN, clear the loaded `default` group's `stateBytes` through the same private-runtime cast pattern already used by repository tests.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test --test-name-pattern='seal fails closed' test/seal_unseal.test.ts
```

Expected: both tests fail with `Missing expected rejection` because current code warns, skips the protected group, and returns a signed object.

- [ ] **Step 3: Remove the fail-open boundary**

In `sealObjectCore`, replace the `try/catch/warn/continue` block with a direct awaited call:

```ts
const ct = await ctx.sealGroup(gname, gcfg.cipher, plaintextBytes, aadBytes);
```

Remove the now-unused `warn` member from `SealContext` and from both Node and browser context construction. Do not alter normal log-emission behavior in `NodeRuntime`.

- [ ] **Step 4: Run focused tests and typecheck**

Run:

```powershell
node --import tsx --import ./test/_setup_wasm.mjs --test --test-name-pattern='seal fails closed|seal returns|unseal round-trips' test/seal_unseal.test.ts
npm run typecheck
```

Expected: exit 0; both fail-closed tests and existing round trips pass.

- [ ] **Step 5: Commit only Task 1 files**

```powershell
git add ts-sdk/test/seal_unseal.test.ts ts-sdk/src/core/sealed_object.ts ts-sdk/src/seal.ts ts-sdk/src/browser/seal.ts
git commit -m "fix(ts): fail closed when sealed groups cannot encrypt"
```

