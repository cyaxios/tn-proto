// Full hibe lifecycle at the JS layer, against the wasm pkg surface — the
// same API the ts-sdk cipher seam will call. One story: setup → persist
// material as bytes → seal epoch-a → grant → open → delegate → refuse a
// stranger → rotate the policy path → old key keeps history and loses new
// seals → ancestor key and authority span epochs.
//
// Run: node hibe_lifecycle.mjs   (after: wasm-pack build --target nodejs)

import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const wasm = await import(join(here, "..", "pkg", "tn_wasm.js"));

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));

// --- Act 1: authority bootstraps; material round-trips as bytes (the
// keystore boundary).
const boot = wasm.hibeSetup(3);
const mpk = b64(boot.mpk_b64);
const msk = b64(boot.msk_b64);
const fp0 = Buffer.from(wasm.hibeMpkFingerprint(mpk)).toString("hex");

// --- Act 2: epoch-a seals to the reader's admission path.
const PATH_A = "reader-did/policy-a";
const e1 = wasm.hibeSeal(mpk, PATH_A, enc("epoch-a entry 1"));
const e2 = wasm.hibeSeal(mpk, PATH_A, enc("epoch-a entry 2"));

// --- Act 3: grant. Key bytes travel like a kit; the path survives.
const readerSk = wasm.hibeKeygen(mpk, msk, PATH_A);
assert.equal(wasm.hibeKeyIdPath(readerSk), PATH_A);
assert.equal(dec(wasm.hibeOpen(mpk, readerSk, e1)), "epoch-a entry 1");
assert.equal(dec(wasm.hibeOpen(mpk, readerSk, e2)), "epoch-a entry 2");

// Second grant: independent bytes, same access.
const reader2Sk = wasm.hibeKeygen(mpk, msk, PATH_A);
assert.notEqual(
  Buffer.from(reader2Sk).toString("hex"),
  Buffer.from(readerSk).toString("hex"),
);
assert.equal(dec(wasm.hibeOpen(mpk, reader2Sk, e1)), "epoch-a entry 1");
console.log("acts 1-3: setup, epoch-a seals, grants open");

// --- Act 4: delegation, parent → child, no msk.
const deptSk = wasm.hibeKeygen(mpk, msk, "reader-did");
const derived = wasm.hibeDelegate(mpk, deptSk, "policy-a");
assert.equal(wasm.hibeKeyIdPath(derived), PATH_A);
assert.equal(dec(wasm.hibeOpen(mpk, derived, e1)), "epoch-a entry 1");
console.log("act 4: delegated key opens");

// --- Act 5: a stranger's key is refused (throws), never garbles.
const strangerSk = wasm.hibeKeygen(mpk, msk, "other-did/policy-a");
assert.throws(() => wasm.hibeOpen(mpk, strangerSk, e1));
// So is a tampered blob under the right key.
const tampered = Uint8Array.from(e1);
tampered[Math.floor(tampered.length / 2)] ^= 1;
assert.throws(() => wasm.hibeOpen(mpk, readerSk, tampered));
console.log("act 5: stranger key and tampered blob both refused");

// --- Act 6: policy-path rotation.
const PATH_B = "reader-did/policy-b";
const e3 = wasm.hibeSeal(mpk, PATH_B, enc("epoch-b entry"));
assert.throws(() => wasm.hibeOpen(mpk, readerSk, e3)); // loses new seals
assert.equal(dec(wasm.hibeOpen(mpk, readerSk, e1)), "epoch-a entry 1"); // keeps history
const derivedB = wasm.hibeDelegate(mpk, deptSk, "policy-b"); // ancestor survives
assert.equal(dec(wasm.hibeOpen(mpk, derivedB, e3)), "epoch-b entry");
const freshB = wasm.hibeKeygen(mpk, msk, PATH_B); // authority spans epochs
assert.equal(dec(wasm.hibeOpen(mpk, freshB, e3)), "epoch-b entry");
console.log("act 6: rotation semantics hold (old key keeps a, loses b; ancestor + authority span)");

// --- Act 7: the bare CEK KEM (what rides inside a group blob) has the
// same story: wrap, unwrap, wrong-key refusal.
const cek = new Uint8Array(32).fill(9);
const wrapped = wasm.hibeKemWrap(mpk, PATH_A, cek);
assert.deepEqual(wasm.hibeKemUnwrap(mpk, readerSk, wrapped), cek);
assert.throws(() => wasm.hibeKemUnwrap(mpk, strangerSk, wrapped));
assert.equal(wasm.hibeMpkMaxDepth(mpk), 3);
console.log("act 7: KEM wrap/unwrap + depth introspection");

// --- Act 8: public material still fingerprints identically.
assert.equal(Buffer.from(wasm.hibeMpkFingerprint(mpk)).toString("hex"), fp0);
console.log("hibe lifecycle (js): ALL OK");
