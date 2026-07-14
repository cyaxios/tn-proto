import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  AuthenticationFailedError,
  LimitExceededError,
  MalformedError,
  NotEntitledError,
} from "../src/primitive_errors.js";

test("primitive errors expose stable categories as real Error subclasses", () => {
  const cases = [
    [new NotEntitledError("reader cannot open ciphertext"), "NotEntitled"],
    [new MalformedError("ciphertext is invalid"), "Malformed"],
    [new AuthenticationFailedError("AAD differs"), "AuthenticationFailed"],
    [new LimitExceededError("too many recipients"), "LimitExceeded"],
  ] as const;

  for (const [error, category] of cases) {
    assert.ok(error instanceof Error);
    assert.equal(error.category, category);
    assert.equal(error.name, `${category}Error`);
  }
});
