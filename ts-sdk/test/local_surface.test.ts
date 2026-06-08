import { test } from "node:test";
import assert from "node:assert/strict";

test("tn-proto/local exports expected symbols", async () => {
  const mod = await import("../src/local/index.js");
  for (const sym of [
    "openLogFile", "logFileFromHandle",
    "openKeystore", "keystoreFromJson",
    "localRead", "localWatch", "fromText",
  ]) {
    assert.equal(typeof (mod as Record<string, unknown>)[sym], "function", `missing: ${sym}`);
  }
});
