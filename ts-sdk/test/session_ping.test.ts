// Session usage ping (src/index.ts::_sessionPing) — one anonymous
// GET /api/v1/ping per process, gated on the ceremony's vault settings.
//
// Run:
//   node --import tsx --import ./test/_setup_wasm.mjs --test "test/session_ping.test.ts"

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { _sessionPingInternals } from "../src/index.ts";
import type { Tn } from "../src/tn.ts";

function fakeTn(vault: unknown): Tn {
  return { config: () => ({ vault }) } as unknown as Tn;
}

function captureFetch(calls: string[]): typeof fetch {
  return (async (url: string | URL) => {
    calls.push(String(url));
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
}

test("sessionPing — fires once per process and strips trailing slashes", () => {
  _sessionPingInternals.reset();
  delete process.env["TN_NO_LINK"];
  const calls: string[] = [];
  const f = captureFetch(calls);
  const tn = fakeTn({ enabled: true, url: "http://vault.test/" });

  _sessionPingInternals.fire(tn, f);
  _sessionPingInternals.fire(tn, f);

  assert.deepEqual(calls, ["http://vault.test/api/v1/ping"]);
});

test("sessionPing — disabled vault: no ping, no latch", () => {
  _sessionPingInternals.reset();
  delete process.env["TN_NO_LINK"];
  const calls: string[] = [];
  const f = captureFetch(calls);

  _sessionPingInternals.fire(fakeTn({ enabled: false, url: "http://vault.test" }), f);
  assert.deepEqual(calls, [], "disabled vault must not ping");

  // A later init with a linked ceremony still gets its ping.
  _sessionPingInternals.fire(fakeTn({ enabled: true, url: "http://vault.test" }), f);
  assert.deepEqual(calls, ["http://vault.test/api/v1/ping"]);
});

test("sessionPing — TN_NO_LINK=1 is a hard opt-out", () => {
  _sessionPingInternals.reset();
  process.env["TN_NO_LINK"] = "1";
  try {
    const calls: string[] = [];
    _sessionPingInternals.fire(
      fakeTn({ enabled: true, url: "http://vault.test" }),
      captureFetch(calls),
    );
    assert.deepEqual(calls, []);
  } finally {
    delete process.env["TN_NO_LINK"];
  }
});

test("sessionPing — fetch failure is swallowed", () => {
  _sessionPingInternals.reset();
  delete process.env["TN_NO_LINK"];
  const rejecting = (async () => {
    throw new Error("vault unreachable");
  }) as unknown as typeof fetch;

  // Must not throw (sync) nor produce an unhandled rejection (async).
  _sessionPingInternals.fire(
    fakeTn({ enabled: true, url: "http://vault.test" }),
    rejecting,
  );
});
