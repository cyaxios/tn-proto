// Absorb-time equivocation classification — TS parity with Python
// `tn-protocol/python/tests/test_absorb_equivocation.py`.
//
// A `tn.recipient.added` reusing a revoked (group, leaf) is always
// excluded from derived state (revocation is terminal). `reuseIsInformed`
// adds the causal distinction from the snapshot's vector clock:
//   - clock COVERS the revoke  -> publisher knew, re-added anyway -> informed
//   - clock does NOT cover it   -> concurrent race -> not informed
// Conservative: missing coordinate / unknown seq -> not informed (never
// falsely accuse).

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { reuseIsInformed } from "../src/core/tnpkg.js";

const REVOKED = "tn.recipient.revoked";

test("informed when clock covers the revoke exactly", () => {
  assert.equal(reuseIsInformed("did:key:zPub", 5, { "did:key:zPub": { [REVOKED]: 5 } }), true);
});

test("informed when clock exceeds the revoke seq", () => {
  assert.equal(reuseIsInformed("did:key:zPub", 5, { "did:key:zPub": { [REVOKED]: 9 } }), true);
});

test("concurrent when clock below the revoke seq", () => {
  assert.equal(reuseIsInformed("did:key:zPub", 5, { "did:key:zPub": { [REVOKED]: 4 } }), false);
});

test("concurrent when the revoke's did is absent from the clock", () => {
  assert.equal(reuseIsInformed("did:key:zPub", 5, { "did:key:zOther": { [REVOKED]: 99 } }), false);
});

test("concurrent when the revoked event_type is absent", () => {
  assert.equal(
    reuseIsInformed("did:key:zPub", 5, { "did:key:zPub": { "tn.recipient.added": 12 } }),
    false,
  );
});

test("concurrent when the clock is empty", () => {
  assert.equal(reuseIsInformed("did:key:zPub", 5, {}), false);
});

test("concurrent when the revoke seq is unknown (null)", () => {
  assert.equal(reuseIsInformed("did:key:zPub", null, { "did:key:zPub": { [REVOKED]: 5 } }), false);
});

test("concurrent when the clock is null/undefined", () => {
  assert.equal(reuseIsInformed("did:key:zPub", 5, null), false);
  assert.equal(reuseIsInformed("did:key:zPub", 5, undefined), false);
});
