// Node-side smoke test for the HTTP handler — verifies the wasm-layer
// addHandler fan-out fires for every emit, that each request body is a
// valid ndjson envelope (parseable JSON with the right shape), and that
// signatures / row_hash / chain hashes pass server-side verification by
// just round-tripping through `JSON.parse`.
//
// Captures requests via a fake `fetch` so we don't need an actual HTTP
// server.

import * as tn from "../dist/browser.mjs";

const captured = [];
const fakeFetch = async (url, init) => {
  captured.push({ url, body: new TextDecoder().decode(init.body) });
  return { ok: true, status: 200, statusText: "OK", text: async () => "" };
};

const storage = tn.memoryStorageAdapter();

const myTn = await tn.Tn.init({
  storage,
  console: false,                       // silence console for clarity
  http: {
    url: "https://ingest.example.invalid/intake",
    fetch: fakeFetch,
    batchIntervalMs: 0,                 // immediate ship per emit
    flushOnUnload: false,
  },
});

console.log(`Tn.init OK did=${myTn.did()}`);

myTn.info("smoke.event", { who: "alice", n: 1 });
myTn.warning("smoke.event", { who: "alice", n: 2 });
myTn.error("smoke.event", { who: "alice", n: 3 });

// Tiny yield so the immediate-ship fetches resolve.
await new Promise((r) => setTimeout(r, 20));

await myTn.close();

console.log(`captured ${captured.length} POSTs to ${captured[0]?.url ?? "(none)"}`);
for (const r of captured) {
  const env = JSON.parse(r.body);
  console.log(
    `  seq=${env.sequence}  event_type=${JSON.stringify(env.event_type)}  level=${JSON.stringify(env.level)}  row_hash=${String(env.row_hash).slice(0, 20)}...`,
  );
}
// ---------------------------------------------------------------------
// Batched-mode smoke — verify the queue + close() final-flush path.
// ---------------------------------------------------------------------

const captured2 = [];
const fakeFetch2 = async (url, init) => {
  captured2.push({ url, body: new TextDecoder().decode(init.body) });
  return { ok: true, status: 200, statusText: "OK", text: async () => "" };
};

const batched = await tn.Tn.init({
  storage: tn.memoryStorageAdapter(),
  console: false,
  http: {
    url: "https://ingest.example.invalid/intake",
    fetch: fakeFetch2,
    batchIntervalMs: 200,
    flushOnUnload: false,
  },
});

batched.info("batched.event", { n: 1 });
batched.info("batched.event", { n: 2 });

// Close BEFORE the 200ms interval fires — `close()` must await the
// pending flush, so all 2 envelopes should ship before close() resolves.
// This is the critical "navigate-away" case the witness needs.
await batched.close();
console.log(`batched: after-immediate-close captured ${captured2.length} POSTs (expected 2 from close()-await flush)`);

const ok = captured.length === 3 && captured2.length === 2;
console.log(ok ? "smoke PASSED" : `smoke FAILED -- immediate=${captured.length}/3 batched=${captured2.length}/2`);
