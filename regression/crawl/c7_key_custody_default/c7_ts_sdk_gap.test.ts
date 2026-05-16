/**
 * SILO: C7 — Default key custody
 * STATUS: SKIPPED — TS SDK has no vault auto-backup today.
 * SEE: .tn-internal/critic log (C7 TS section)
 *
 * What this test WOULD do, mirroring the Python side:
 *   1. Hermetic machine + TN_VAULT_URL pointed at the live vault.
 *   2. await Tn.init({ link: true })  — does not exist.
 *   3. Assert claim_url.txt is written.
 *   4. Assert vault has a pending_claims row.
 *   5. dev-auth login + GET pending-claim should return bytes.
 *
 * What's missing on the TS side:
 *   - `TnInitOptions` has no `link` flag; only `{ stdout?: boolean }`.
 *   - No equivalent of `python/tn/handlers/vault_push.py:init_upload`.
 *   - No claim_url.txt persistence path.
 *   - No `tn.sync_state.get_pending_claim` analog.
 *
 * The Python side (test_init_link_mints_claim_url.py + idempotent +
 * url_format + offline) covers the surface end-to-end. The cross-
 * language restore (c8 directory) proves the wire format is
 * symmetric, so the TS-side restore half works WITHOUT TS having
 * the init-upload half. That's currently sufficient — but a TS-only
 * consumer can't drive the funnel-critical onboarding flow.
 *
 * Track this in critic log as a [blocking-track]: implement
 * TS-side init-upload + claim_url surface, then this skipped test
 * becomes a real one.
 *
 * To convert when the SDK lands the feature: copy the Python file
 * test_init_link_mints_claim_url.py's structure, swap pytest fixtures
 * for the C3/C4 chdir+tmpdir pattern, and call
 * `await Tn.init(yamlPath, { link: true })`.
 */
import { test } from "node:test";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

test("C7 (TS): vault auto-backup — SKIPPED (TS SDK gap)", { skip: true }, () => {
  // The test body never runs (skip: true above). It exists so the
  // silo's report counts this as a tracked-gap rather than silently
  // omitting TS coverage.
  setTestContext({ silo: "c7", test: "c7_ts_sdk_gap::placeholder" });
  assertNamed({
    name: "ts-init-link-exists",
    expected: true,
    observed: false,
    onMiss:
      "When this fires for real, TnInitOptions has gained a `link` field " +
      "and Tn.init({ link: true }) triggers the vault init-upload + " +
      "writes claim_url.txt. See critic log C7 TS section.",
  });
});
