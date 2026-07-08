// HIBE Python↔wasm interop, node side. Two directions:
//  1. Open a blob Python sealed (fixture from hibe_py_check.py --emit).
//  2. Seal a blob here for Python to open (written next to the fixture).
// Run via run_hibe_interop.sh, which sequences the Python halves.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const wasm = await import(join(here, "..", "pkg", "tn_wasm.js"));

const fixturePath = join(here, "hibe_fixture.json");
const fx = JSON.parse(readFileSync(fixturePath, "utf-8"));
const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));

const mpk = b64(fx.mpk);
const sk = b64(fx.sk);

// Direction 1: Python sealed, wasm opens.
const opened = wasm.hibeOpen(mpk, sk, b64(fx.sealed));
const openedText = new TextDecoder().decode(opened);
if (openedText !== fx.body) {
  throw new Error(`python->wasm open mismatch: ${openedText}`);
}
console.log("wasm opened python-sealed blob: ok");

// Key path survives the wire.
const path = wasm.hibeKeyIdPath(sk);
if (path !== fx.id_path) {
  throw new Error(`id path mismatch: ${path} != ${fx.id_path}`);
}

// Delegation parity: delegate down from the parent key Python minted and
// open the blob Python sealed to the CHILD path.
const childSk = wasm.hibeDelegate(mpk, b64(fx.parent_sk), fx.child_label);
const childOpened = wasm.hibeOpen(mpk, childSk, b64(fx.child_sealed));
if (new TextDecoder().decode(childOpened) !== fx.child_body) {
  throw new Error("wasm-delegated key failed to open python child-sealed blob");
}
console.log("wasm-delegated key opened python child-sealed blob: ok");

// Direction 2: wasm seals, Python opens (checked by hibe_py_check.py --verify).
const back = wasm.hibeSeal(mpk, fx.id_path, new TextEncoder().encode(fx.reply_body));
writeFileSync(
  join(here, "hibe_js_out.json"),
  JSON.stringify({
    sealed: Buffer.from(back).toString("base64"),
    body: fx.reply_body,
    mpk_fp: Buffer.from(wasm.hibeMpkFingerprint(mpk)).toString("base64"),
  }),
);
console.log("wasm sealed reply for python: ok");
