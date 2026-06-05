// Tests for the `tn firehose stats|list|get` CLI verbs (src/cli/firehose.ts),
// the TS parity port of Python's cmd_firehose_stats / _list / _get.
//
// Every branch is exercised in-process with INJECTED deps — a stub `fetch`,
// an in-memory env, and captured stdout/stderr/bytes/writeFile sinks — so the
// suite is fully network-, fs-, and process.exit-free. We assert the GET URLs,
// the gating (TN_FIREHOSE_URL / TN_FIREHOSE_TOKEN), the bearer header, the
// pretty-printed sorted JSON, the raw-text fallback, the byte download, and the
// exit codes carried by FirehoseExit — all byte-for-byte mirroring Python.
//
// Run standalone with coverage:
//   ./node_modules/.bin/c8 --include='src/cli/firehose.ts' --reporter=text \
//     node --import tsx --import ./test/_setup_wasm.mjs \
//     --test test/cli_firehose.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  firehoseStatsCmd,
  firehoseListCmd,
  firehoseGetCmd,
  firehoseCmd,
  firehoseEnabled,
  FirehoseExit,
  type FirehoseDeps,
  type FirehoseFetch,
  type FirehoseFetchResponse,
} from "../src/cli/firehose.js";

const BASE = "https://fh.example.workers.dev";

/** A captured GET call the stub fetch recorded. */
interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
}

/** Build a stub fetch returning a canned response and recording each call. */
function stubFetch(
  resp: Partial<FirehoseFetchResponse> & { status: number },
  calls: Call[],
): FirehoseFetch {
  return async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers });
    return {
      status: resp.status,
      text: resp.text ?? (async () => ""),
      arrayBuffer: resp.arrayBuffer ?? (async () => new ArrayBuffer(0)),
    };
  };
}

/** A throwing fetch (mirrors Python's httpx.HTTPError path). */
function throwingFetch(err: unknown): FirehoseFetch {
  return async () => {
    throw err;
  };
}

interface Sinks {
  out: string[];
  err: string[];
  bytes: Uint8Array[];
  files: { path: string; data: Uint8Array }[];
}

/** Assemble injectable deps + a Sinks handle to assert against. */
function makeDeps(
  over: Partial<FirehoseDeps> & { env?: Record<string, string | undefined> },
): { deps: Partial<FirehoseDeps>; sinks: Sinks } {
  const sinks: Sinks = { out: [], err: [], bytes: [], files: [] };
  const deps: Partial<FirehoseDeps> = {
    env: over.env ?? { TN_FIREHOSE_URL: BASE, TN_FIREHOSE_TOKEN: "tok-abc" },
    fetch: over.fetch,
    stdout: (s) => sinks.out.push(s),
    stderr: (s) => sinks.err.push(s),
    stdoutBytes: (b) => sinks.bytes.push(b),
    writeFile: (path, data) => sinks.files.push({ path, data }),
  };
  return { deps, sinks };
}

/** Run `fn`, asserting it throws a FirehoseExit with the given code+message. */
async function expectExit(
  fn: () => Promise<unknown>,
  code: number,
  msgRe: RegExp,
): Promise<void> {
  await assert.rejects(fn, (e: unknown) => {
    assert.ok(e instanceof FirehoseExit, `expected FirehoseExit, got ${String(e)}`);
    assert.equal(e.code, code);
    assert.match(e.message, msgRe);
    return true;
  });
}

// --------------------------------------------------------------------------
// stats
// --------------------------------------------------------------------------

test("firehose stats: GETs /stats/<tenant>, pretty-prints sorted JSON, exits 0", async () => {
  const calls: Call[] = [];
  const { deps, sinks } = makeDeps({
    fetch: stubFetch({ status: 200, text: async () => '{"zeta":1,"alpha":2}' }, calls),
  });
  const code = await firehoseStatsCmd({ tenant: "acme" }, deps);
  assert.equal(code, 0);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${BASE}/stats/acme`);
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[0].headers.accept, "application/json");
  // Token present -> bearer header even though stats does not require it.
  assert.equal(calls[0].headers.authorization, "Bearer tok-abc");
  // sort_keys + indent=2, trailing newline.
  assert.equal(sinks.out.join(""), '{\n  "alpha": 2,\n  "zeta": 1\n}\n');
});

test("firehose stats: anonymous (no token) omits the bearer header", async () => {
  const calls: Call[] = [];
  const { deps } = makeDeps({
    env: { TN_FIREHOSE_URL: BASE },
    fetch: stubFetch({ status: 200, text: async () => "{}" }, calls),
  });
  await firehoseStatsCmd({ tenant: "acme" }, deps);
  assert.equal(calls[0].headers.authorization, undefined);
});

test("firehose stats: non-JSON body falls back to raw text", async () => {
  const calls: Call[] = [];
  const { deps, sinks } = makeDeps({
    fetch: stubFetch({ status: 200, text: async () => "not json" }, calls),
  });
  const code = await firehoseStatsCmd({ tenant: "acme" }, deps);
  assert.equal(code, 0);
  assert.equal(sinks.out.join(""), "not json\n");
});

test("firehose stats: non-200 dies with code 2 and truncates body", async () => {
  const calls: Call[] = [];
  const big = "E".repeat(500);
  const { deps, sinks } = makeDeps({
    fetch: stubFetch({ status: 503, text: async () => big }, calls),
  });
  await expectExit(() => firehoseStatsCmd({ tenant: "acme" }, deps), 2, /firehose stats returned 503/);
  // body truncated to 200 chars in the message
  assert.match(sinks.err.join(""), /tn: error: firehose stats returned 503: E{200}$/m);
});

test("firehose stats: fetch failure dies with code 1", async () => {
  const { deps } = makeDeps({ fetch: throwingFetch(new Error("conn reset")) });
  await expectExit(
    () => firehoseStatsCmd({ tenant: "acme" }, deps),
    1,
    /firehose stats request failed: conn reset/,
  );
});

test("firehose stats: fetch failure with non-Error coerces to string", async () => {
  const { deps } = makeDeps({ fetch: throwingFetch("boom") });
  await expectExit(
    () => firehoseStatsCmd({ tenant: "acme" }, deps),
    1,
    /firehose stats request failed: boom/,
  );
});

test("firehose stats: missing TN_FIREHOSE_URL dies", async () => {
  const { deps } = makeDeps({ env: {}, fetch: stubFetch({ status: 200 }, []) });
  await expectExit(() => firehoseStatsCmd({ tenant: "acme" }, deps), 1, /TN_FIREHOSE_URL is not set/);
});

// --------------------------------------------------------------------------
// list
// --------------------------------------------------------------------------

test("firehose list: GETs inbox/<tenant>/incoming with bearer, sorted JSON", async () => {
  const calls: Call[] = [];
  const { deps, sinks } = makeDeps({
    fetch: stubFetch({ status: 200, text: async () => '{"b":2,"a":1}' }, calls),
  });
  const code = await firehoseListCmd({ tenant: "acme" }, deps);
  assert.equal(code, 0);
  assert.equal(calls[0].url, `${BASE}/api/v1/inbox/acme/incoming`);
  assert.equal(calls[0].headers.authorization, "Bearer tok-abc");
  assert.equal(sinks.out.join(""), '{\n  "a": 1,\n  "b": 2\n}\n');
});

test("firehose list: --did overrides the inbox path", async () => {
  const calls: Call[] = [];
  const { deps } = makeDeps({
    fetch: stubFetch({ status: 200, text: async () => "[]" }, calls),
  });
  await firehoseListCmd({ tenant: "acme", did: "did:key:zABC" }, deps);
  assert.equal(calls[0].url, `${BASE}/api/v1/inbox/did:key:zABC/incoming`);
});

test("firehose list: non-JSON body falls back to raw text", async () => {
  const calls: Call[] = [];
  const { deps, sinks } = makeDeps({
    fetch: stubFetch({ status: 200, text: async () => "raw-listing" }, calls),
  });
  await firehoseListCmd({ tenant: "acme" }, deps);
  assert.equal(sinks.out.join(""), "raw-listing\n");
});

test("firehose list: missing token dies (inbox route requires it)", async () => {
  const { deps } = makeDeps({
    env: { TN_FIREHOSE_URL: BASE },
    fetch: stubFetch({ status: 200 }, []),
  });
  await expectExit(
    () => firehoseListCmd({ tenant: "acme" }, deps),
    1,
    /TN_FIREHOSE_TOKEN is required for inbox routes/,
  );
});

test("firehose list: non-200 dies with code 2", async () => {
  const calls: Call[] = [];
  const { deps } = makeDeps({
    fetch: stubFetch({ status: 404, text: async () => "nope" }, calls),
  });
  await expectExit(() => firehoseListCmd({ tenant: "acme" }, deps), 2, /firehose list returned 404: nope/);
});

test("firehose list: fetch failure dies with code 1", async () => {
  const { deps } = makeDeps({ fetch: throwingFetch(new Error("dns")) });
  await expectExit(() => firehoseListCmd({ tenant: "acme" }, deps), 1, /firehose list request failed: dns/);
});

// --------------------------------------------------------------------------
// get
// --------------------------------------------------------------------------

test("firehose get: GETs snapshot path; --out writes bytes + prints count", async () => {
  const calls: Call[] = [];
  const payload = new TextEncoder().encode("TNPKGBYTES");
  const { deps, sinks } = makeDeps({
    fetch: stubFetch(
      { status: 200, arrayBuffer: async () => payload.buffer.slice(0) },
      calls,
    ),
  });
  const code = await firehoseGetCmd(
    { tenant: "acme", ceremony: "cer1", name: "snap.tnpkg", out: "/tmp/out/snap.tnpkg" },
    deps,
  );
  assert.equal(code, 0);
  assert.equal(calls[0].url, `${BASE}/api/v1/inbox/acme/snapshots/cer1/snap.tnpkg`);
  assert.equal(calls[0].headers.authorization, "Bearer tok-abc");
  assert.equal(sinks.files.length, 1);
  assert.equal(sinks.files[0].path, "/tmp/out/snap.tnpkg");
  assert.deepEqual(Array.from(sinks.files[0].data), Array.from(payload));
  assert.equal(sinks.out.join(""), `wrote ${payload.length} bytes to /tmp/out/snap.tnpkg\n`);
  // No raw stdout-bytes when --out is given.
  assert.equal(sinks.bytes.length, 0);
});

test("firehose get: no --out streams bytes to stdout buffer; --did override", async () => {
  const calls: Call[] = [];
  const payload = new TextEncoder().encode("BYTES2");
  const { deps, sinks } = makeDeps({
    fetch: stubFetch({ status: 200, arrayBuffer: async () => payload.buffer.slice(0) }, calls),
  });
  await firehoseGetCmd(
    { tenant: "acme", ceremony: "cer1", name: "s.tnpkg", did: "did:key:zXY" },
    deps,
  );
  assert.equal(calls[0].url, `${BASE}/api/v1/inbox/did:key:zXY/snapshots/cer1/s.tnpkg`);
  assert.equal(sinks.bytes.length, 1);
  assert.deepEqual(Array.from(sinks.bytes[0]), Array.from(payload));
  assert.equal(sinks.files.length, 0);
});

test("firehose get: default writeFile creates parent dirs and writes bytes to disk", async () => {
  const calls: Call[] = [];
  const payload = new TextEncoder().encode("REALFS");
  const root = mkdtempSync(join(tmpdir(), "tn-fh-get-"));
  const outPath = join(root, "nested", "dir", "snap.tnpkg");
  // Inject everything EXCEPT writeFile so the real node:fs default body runs.
  const sinks: Sinks = { out: [], err: [], bytes: [], files: [] };
  const deps: Partial<FirehoseDeps> = {
    env: { TN_FIREHOSE_URL: BASE, TN_FIREHOSE_TOKEN: "tok-abc" },
    fetch: stubFetch({ status: 200, arrayBuffer: async () => payload.buffer.slice(0) }, calls),
    stdout: (s) => sinks.out.push(s),
    stderr: (s) => sinks.err.push(s),
    stdoutBytes: (b) => sinks.bytes.push(b),
    // writeFile intentionally omitted -> defaultDeps().writeFile (lines 81-84).
  };
  try {
    const code = await firehoseGetCmd(
      { tenant: "acme", ceremony: "c", name: "n", out: outPath },
      deps,
    );
    assert.equal(code, 0);
    assert.deepEqual(Array.from(readFileSync(outPath)), Array.from(payload));
    assert.equal(sinks.out.join(""), `wrote ${payload.length} bytes to ${outPath}\n`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("firehose get: non-200 dies with code 2", async () => {
  const calls: Call[] = [];
  const { deps } = makeDeps({
    fetch: stubFetch({ status: 500, text: async () => "boom" }, calls),
  });
  await expectExit(
    () => firehoseGetCmd({ tenant: "acme", ceremony: "c", name: "n" }, deps),
    2,
    /firehose get returned 500: boom/,
  );
});

test("firehose get: missing token dies", async () => {
  const { deps } = makeDeps({
    env: { TN_FIREHOSE_URL: BASE },
    fetch: stubFetch({ status: 200 }, []),
  });
  await expectExit(
    () => firehoseGetCmd({ tenant: "acme", ceremony: "c", name: "n" }, deps),
    1,
    /TN_FIREHOSE_TOKEN is required/,
  );
});

test("firehose get: fetch failure dies with code 1", async () => {
  const { deps } = makeDeps({ fetch: throwingFetch(new Error("reset")) });
  await expectExit(
    () => firehoseGetCmd({ tenant: "acme", ceremony: "c", name: "n" }, deps),
    1,
    /firehose get request failed: reset/,
  );
});

// --------------------------------------------------------------------------
// dispatcher + gating helper
// --------------------------------------------------------------------------

test("firehoseCmd dispatches stats/list/get and dies on unknown sub", async () => {
  const callsS: Call[] = [];
  const callsL: Call[] = [];
  const callsG: Call[] = [];
  const s = makeDeps({ fetch: stubFetch({ status: 200, text: async () => "{}" }, callsS) });
  assert.equal(await firehoseCmd("stats", { tenant: "a" }, s.deps), 0);
  assert.equal(callsS[0].url, `${BASE}/stats/a`);

  const l = makeDeps({ fetch: stubFetch({ status: 200, text: async () => "{}" }, callsL) });
  assert.equal(await firehoseCmd("list", { tenant: "a" }, l.deps), 0);
  assert.equal(callsL[0].url, `${BASE}/api/v1/inbox/a/incoming`);

  const g = makeDeps({
    fetch: stubFetch({ status: 200, arrayBuffer: async () => new ArrayBuffer(0) }, callsG),
  });
  assert.equal(await firehoseCmd("get", { tenant: "a", ceremony: "c", name: "n" }, g.deps), 0);
  assert.equal(callsG[0].url, `${BASE}/api/v1/inbox/a/snapshots/c/n`);

  const u = makeDeps({ fetch: stubFetch({ status: 200 }, []) });
  await expectExit(
    () => firehoseCmd("bogus" as "stats", { tenant: "a" }, u.deps),
    2,
    /unknown firehose subcommand: bogus/,
  );
});

test("firehoseEnabled reflects TN_FIREHOSE_ENABLED=1", () => {
  assert.equal(firehoseEnabled({ TN_FIREHOSE_ENABLED: "1" }), true);
  assert.equal(firehoseEnabled({ TN_FIREHOSE_ENABLED: "0" }), false);
  assert.equal(firehoseEnabled({}), false);
});

test("jsonDumps sorts nested keys and arrays recursively (via stats output)", async () => {
  const calls: Call[] = [];
  const { deps, sinks } = makeDeps({
    fetch: stubFetch(
      { status: 200, text: async () => '{"z":{"y":1,"x":2},"a":[{"d":4,"c":3}]}' },
      calls,
    ),
  });
  await firehoseStatsCmd({ tenant: "t" }, deps);
  assert.equal(
    sinks.out.join(""),
    [
      "{",
      '  "a": [',
      "    {",
      '      "c": 3,',
      '      "d": 4',
      "    }",
      "  ],",
      '  "z": {',
      '    "x": 2,',
      '    "y": 1',
      "  }",
      "}",
      "",
    ].join("\n"),
  );
});
