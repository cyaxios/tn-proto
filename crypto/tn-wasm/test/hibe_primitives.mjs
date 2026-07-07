// Executable reference for the wasm HIBE primitives (the `hibe*` exports the
// TS SDK re-exports from `tn-wasm`). Bytes in, bytes out — byte-identical to
// Python's tn._hibe. Run: node hibe_primitives.mjs (after wasm-pack build).
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const w = await import(join(here, "..", "pkg", "tn_wasm.js"));

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const short = (b) => Buffer.from(b).subarray(0, 8).toString("hex") + `... (${b.length} bytes)`;

// setup -> { mpk_b64, msk_b64 }
const boot = w.hibeSetup(2);
const mpk = b64(boot.mpk_b64), msk = b64(boot.msk_b64);
console.log("hibeSetup            mpk:", short(mpk), " msk:", short(msk));
console.log("hibeMpkFingerprint      :", Buffer.from(w.hibeMpkFingerprint(mpk)).toString("hex"));
console.log("hibeMpkMaxDepth         :", w.hibeMpkMaxDepth(mpk));

// keygen -> sk bytes
const sk = w.hibeKeygen(mpk, msk, "alice/reports");
console.log("hibeKeygen           sk :", short(sk), " path:", w.hibeKeyIdPath(sk));

// seal / open (+ aad marker)
const blob = w.hibeSeal(mpk, "alice/reports", enc("quarterly numbers"), undefined);
assert.equal(dec(w.hibeOpen(mpk, sk, blob, undefined)), "quarterly numbers");
const aad = enc("policy=finra-oba");
const gov = w.hibeSeal(mpk, "alice/reports", enc("governed body"), aad);
assert.equal(dec(w.hibeOpen(mpk, sk, gov, aad)), "governed body");
assert.throws(() => w.hibeOpen(mpk, sk, gov, enc("policy=other")));
console.log("hibeSeal/hibeOpen (+aad):", "ok (wrong aad rejected)");

// KEM directly
const cek = new Uint8Array(32).map((_, i) => i);
const wrapped = w.hibeKemWrap(mpk, "alice/reports", cek);
assert.deepEqual(w.hibeKemUnwrap(mpk, sk, wrapped), cek);
console.log("hibeKemWrap/Unwrap      :", short(wrapped), " round-trip ok");

// delegate parent -> child (no msk)
const parent = w.hibeKeygen(mpk, msk, "alice");
const child = w.hibeDelegate(mpk, parent, "reports");
assert.equal(w.hibeKeyIdPath(child), "alice/reports");
assert.equal(dec(w.hibeOpen(mpk, child, blob, undefined)), "quarterly numbers");
console.log("hibeDelegate            :", "alice ->", w.hibeKeyIdPath(child), "opens the blob");

console.log("\nwasm HIBE primitives: ALL OK");
