import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  VerificationError,
  ChainConflictError,
  RotationConflictError,
  LeafReuseError,
  SameCoordinateForkError,
} from "../src/core/errors.js";

test("each error class is a real Error subclass", () => {
  const cases: Error[] = [
    new VerificationError({ event_type: "x", sequence: 1 }, ["signature"]),
    new ChainConflictError("default", "a".repeat(64), "b".repeat(64)),
    new RotationConflictError("default", 1, 2),
    new LeafReuseError("default", 0, null, null),
    new SameCoordinateForkError("default", "1.0"),
  ];
  for (const e of cases) {
    assert.ok(e instanceof Error, `${e.constructor.name} is not Error`);
    assert.equal(typeof e.name, "string");
    assert.notEqual(e.name, "Error");
    assert.ok(e.message.length > 0);
  }
});

test("error subclasses preserve their fields", () => {
  const v = new VerificationError({ event_type: "evt.test", sequence: 42 }, ["chain", "row_hash"]);
  assert.deepEqual(v.invalidReasons, ["chain", "row_hash"]);
  assert.equal(v.envelope["event_type"], "evt.test");

  const c = new ChainConflictError("g", "x".repeat(64), "y".repeat(64));
  assert.equal(c.group, "g");

  const l = new LeafReuseError("g", 7, "did:key:zP", "did:key:zA");
  assert.equal(l.leafIndex, 7);
  assert.equal(l.priorRecipientDid, "did:key:zP");
});
