// src/version.ts is the single source of the SDK's self-reported version
// (User-Agent on every outbound HTTP call). A release bump that touches
// package.json but misses version.ts would silently ship a stale UA — this
// pins them together.
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { SDK_VERSION, USER_AGENT } from "../src/version.js";

test("SDK_VERSION matches package.json version", () => {
  const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };
  assert.equal(SDK_VERSION, pkg.version);
  assert.equal(USER_AGENT, `tn-proto-ts/${pkg.version}`);
});
