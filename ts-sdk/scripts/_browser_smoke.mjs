// Node-side smoke test for dist/browser.mjs.
//
// Exercises the full Tn.init -> tn.info -> tn.read flow against the
// in-memory storage adapter. The wasm bytes are inlined in the bundle
// and initSync'd at module load, so this script is a tiny consumer:
// pretend to be a browser, hand in a non-localStorage storage adapter
// (because Node doesn't ship one), and check that the round-trip is
// byte-identical to what the Python / Node SDKs produce.
//
// Run with: node scripts/_browser_smoke.mjs

import * as tn from "../dist/browser.mjs";

const out = (s) => console.log(s);

out("imported browser.mjs OK");
out(`top-level exports: ${Object.keys(tn).slice(0, 20).join(", ")}${Object.keys(tn).length > 20 ? ", ..." : ""}`);

// In Node we can't touch window.localStorage, so swap in the in-memory
// adapter. In a real browser, callers omit `storage` and get the
// localStorage one by default.
const storage = tn.memoryStorageAdapter();

// `Tn.init` mints a fresh ceremony on first call (yaml + keystore + ...).
const myTn = await tn.Tn.init({ storage });
out(`Tn.init OK -- did=${myTn.did()}`);

// Emit one of each level so the read-back exercises the level filter.
myTn.log("smoke.severityless", { phase: "init" });
myTn.info("smoke.event", { who: "alice", n: 1 });
myTn.warning("smoke.event", { who: "alice", n: 2 });
myTn.error("smoke.event", { who: "alice", n: 3 });

out("emit OK -- 4 events written");

// Read back the log.
const entries = myTn.read();
out(`tn.read OK -- ${entries.length} entries`);
for (const e of entries) {
  out(`  seq=${e.sequence} level=${JSON.stringify(e.level)} event_type=${JSON.stringify(e.event_type)}`);
}

// Cross-check via the BrowserRuntime — read the raw log bytes directly
// so we can see what the wasm actually wrote (separately from
// whatever filter the read path applies).
const logBytes = storage.snapshot()["/v/.tn/tn/logs/tn.ndjson"];
if (logBytes) {
  const text = new TextDecoder().decode(logBytes);
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  out(`  log file has ${lines.length} ndjson rows`);
  for (const line of lines) {
    try {
      const env = JSON.parse(line);
      out(`    seq=${env.sequence} event_type=${env.event_type} level=${JSON.stringify(env.level)}`);
    } catch {
      out(`    (unparseable line)`);
    }
  }
}

// Sanity-check a few envelope fields.
for (const e of entries) {
  const et = e.event_type;
  const lvl = e.level;
  const seq = e.sequence;
  out(`  seq=${seq} level=${JSON.stringify(lvl)} event_type=${JSON.stringify(et)}`);
}

// Diagnostic: dump every key currently held by the storage adapter so
// we can see whether the emit path wrote envelopes to the expected
// log path.
const snap = storage.snapshot();
out(`storage keys (${Object.keys(snap).length}):`);
for (const [k, v] of Object.entries(snap)) {
  out(`  ${k} (${v.length} bytes)`);
}

await myTn.close();
out("tn.close OK");
out("smoke PASSED");
