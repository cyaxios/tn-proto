// Node-side smoke for Tn.initFromSeed.
//
// Flow:
//   1. Mint a fresh ceremony via Tn.init (gets seed + publisher state).
//   2. Read both out of the storage adapter.
//   3. Tear that ceremony down.
//   4. Call Tn.initFromSeed with the bytes recovered in step 2.
//   5. Confirm the new instance has the same DID as step 1.
//   6. Confirm tn.info / tn.read work against the adopted state.
//
// This is the round-trip a witness-style flow does, just with the
// "server mints + ships" step replaced by an in-memory mint we then
// hand back to a separate runtime.

import * as tn from "../dist/browser.mjs";

const out = (s) => console.log(s);

// ---- Step 1-2: mint a ceremony, capture its secrets ----------------

const mintStorage = tn.memoryStorageAdapter();
const minted = await tn.Tn.init({ storage: mintStorage, console: false });
const originalDid = minted.did();
out(`step 1: minted ceremony did=${originalDid}`);

const snap = mintStorage.snapshot();
const seed = snap["/v/.tn/tn/keys/local.private"];
const btnState = snap["/v/.tn/tn/keys/default.btn.state"];
if (!seed || !btnState) {
  throw new Error("step 2: expected keystore files missing from snapshot");
}
out(`step 2: extracted seed (${seed.length}B) + btn state (${btnState.length}B)`);

await minted.close();

// ---- Step 3-4: adopt the secrets in a fresh runtime ----------------

const adopted = await tn.Tn.initFromSeed({
  seed,
  btnPublisherState: btnState,
  console: false,
});

if (adopted.did() !== originalDid) {
  throw new Error(
    `step 5 FAIL: adopted did ${adopted.did()} != original ${originalDid}`,
  );
}
out(`step 5: adopted runtime did=${adopted.did()} matches original`);

// ---- Step 6: emit + read against the adopted runtime ----------------

adopted.info("adopted.hello", { from: "initFromSeed" });
adopted.warning("adopted.caution", { ok: true });

const entries = adopted.read();
out(`step 6: read ${entries.length} entries from the adopted runtime`);
for (const e of entries) {
  out(`  seq=${e.sequence} level=${JSON.stringify(e.level)} event_type=${JSON.stringify(e.event_type)}`);
}

await adopted.close();

// ---- Step 7: confirm + and HTTP combo (the witness shape) -----------
// Adopt the seed AGAIN, this time with no local storage and an HTTP
// handler so we exercise the production witness path: emit signed
// envelopes that ship to a server, never persist locally.

const captured = [];
const fakeFetch = async (url, init) => {
  captured.push(new TextDecoder().decode(init.body));
  return { ok: true, status: 200, statusText: "OK", text: async () => "" };
};

const witness = await tn.Tn.initFromSeed({
  seed,
  btnPublisherState: btnState,
  http: {
    url: "https://ingest.example.invalid/intake",
    fetch: fakeFetch,
    batchIntervalMs: 0,
    flushOnUnload: false,
  },
});

if (witness.did() !== originalDid) {
  throw new Error(`step 7 FAIL: witness did ${witness.did()} != ${originalDid}`);
}

witness.info("witness.scenario.attempted", { kind: "agreement.success" });
witness.info("witness.scenario.attempted", { kind: "agreement.success" });

await new Promise((r) => setTimeout(r, 30));
await witness.close();

out(`step 7: witness-style runtime shipped ${captured.length} envelopes to ingest`);
for (const body of captured) {
  const env = JSON.parse(body);
  out(`  POST: seq=${env.sequence} did=${String(env.device_identity).slice(0, 24)}... event_type=${JSON.stringify(env.event_type)}`);
}

if (captured.length !== 2) {
  throw new Error(`step 7 FAIL: expected 2 POSTs, got ${captured.length}`);
}

out("smoke PASSED");
