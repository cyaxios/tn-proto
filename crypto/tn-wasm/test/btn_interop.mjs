// btn interop: JS produces state/kit/ciphertext, Python reads. And
// vice versa. Writes a shared fixture file so the Python side can do
// deterministic round-trips without re-deriving from an OS RNG.
//
// Usage:
//   node test/btn_interop.mjs             # phase 1: JS produces, writes btn_fixture.json
//   python test/btn_py_check.py           # phase 2: Python decrypts + cross-check
//   node test/btn_interop.mjs --verify-py # phase 3: JS decrypts Python's output
//
// Or run the full circle via run_btn_interop.sh.

import { readFileSync, writeFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  BtnPublisher,
  btnDecrypt,
  btnKitLeaf,
  btnKitPublisherId,
  btnCiphertextPublisherId,
} from "../pkg/tn_wasm.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, "btn_fixture.json");
const b64 = (b) => Buffer.from(b).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

let passed = 0;
let failed = 0;
function ok(name) {
  console.log(`[ok]   ${name}`);
  passed += 1;
}
function fail(name, why) {
  console.log(`[fail] ${name}: ${why}`);
  failed += 1;
}

const mode = process.argv.includes("--verify-py") ? "verify-py" : "produce";

if (mode === "produce") {
  // Deterministic master seed so the Python side can also re-derive the
  // publisher and get matching bytes end to end.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 5 + 1) & 0xff;

  const pub = new BtnPublisher(seed);
  if (pub.issuedCount() !== 0) fail("initial issuedCount=0", pub.issuedCount());
  else ok("initial issuedCount=0");

  const kitA = pub.mint();
  const kitB = pub.mint();
  const kitC = pub.mint();
  if (pub.issuedCount() !== 3) fail("after 3 mints active=3", pub.issuedCount());
  else ok("after 3 mints active=3");

  // Publisher IDs must match across kit, state, and ciphertext.
  const pubId = pub.publisherId();
  const pubIdHex = Buffer.from(pubId).toString("hex");
  if (Buffer.from(btnKitPublisherId(kitA)).toString("hex") !== pubIdHex) {
    fail("kit publisher_id matches state", "mismatch");
  } else {
    ok("kit publisher_id matches state");
  }

  // Encrypt 3 payloads.
  const payloads = [
    "hello btn",
    "a longer payload with some punctuation!",
    "", // empty plaintext
  ].map((s) => new Uint8Array(Buffer.from(s, "utf8")));
  const ciphertexts = payloads.map((p) => pub.encrypt(p));

  for (let i = 0; i < ciphertexts.length; i += 1) {
    const ctPubId = Buffer.from(btnCiphertextPublisherId(ciphertexts[i])).toString("hex");
    if (ctPubId !== pubIdHex) fail(`ct[${i}].publisher_id matches`, "diff");
    else ok(`ct[${i}].publisher_id matches`);
  }

  // JS round-trip: decrypt with each kit.
  for (const [kname, kit] of [
    ["A", kitA],
    ["B", kitB],
    ["C", kitC],
  ]) {
    const leaf = btnKitLeaf(kit);
    for (let i = 0; i < ciphertexts.length; i += 1) {
      const pt = btnDecrypt(kit, ciphertexts[i]);
      const recovered = Buffer.from(pt).toString("utf8");
      const expected = Buffer.from(payloads[i]).toString("utf8");
      if (recovered === expected) ok(`JS decrypt ct[${i}] with kit ${kname}(leaf=${leaf})`);
      else fail(`JS decrypt ct[${i}] with kit ${kname}`, `got ${JSON.stringify(recovered)}`);
    }
  }

  // Revoke kit B, make sure a new ciphertext does not decrypt under B.
  pub.revokeByLeaf(btnKitLeaf(kitB));
  if (pub.revokedCount() !== 1) fail("after revoke, revokedCount=1", pub.revokedCount());
  else ok("after revoke, revokedCount=1");

  const ctPostRevoke = pub.encrypt(new Uint8Array(Buffer.from("after revoke", "utf8")));
  // A and C still decrypt.
  const ptA = btnDecrypt(kitA, ctPostRevoke);
  if (Buffer.from(ptA).toString("utf8") === "after revoke") ok("kit A still decrypts post-revoke");
  else fail("kit A post-revoke", "wrong plaintext");

  let revokedOk = false;
  try {
    btnDecrypt(kitB, ctPostRevoke);
  } catch {
    revokedOk = true;
  }
  if (revokedOk) ok("kit B rejected post-revoke");
  else fail("kit B rejected post-revoke", "unexpectedly decrypted");

  // Persist state for Python side.
  const stateBytes = pub.toBytes();
  const restored = BtnPublisher.fromBytes(stateBytes);
  // issued_count is active readers (minted minus revoked), revoked_count
  // is the revoked set. 3 minted, 1 revoked => active=2, revoked=1.
  if (
    restored.issuedCount() === 2 &&
    restored.revokedCount() === 1 &&
    Buffer.from(restored.publisherId()).toString("hex") === pubIdHex
  ) {
    ok("toBytes/fromBytes round-trip");
  } else {
    fail(
      "toBytes/fromBytes round-trip",
      `active=${restored.issuedCount()} revoked=${restored.revokedCount()}`,
    );
  }

  // Write fixture for Python cross-check.
  writeFileSync(
    fixturePath,
    JSON.stringify(
      {
        seed_b64: b64(seed),
        publisher_id_hex: pubIdHex,
        state_bytes_b64: b64(stateBytes),
        kits: {
          A: b64(kitA),
          B: b64(kitB),
          C: b64(kitC),
        },
        payloads: payloads.map((p) => b64(p)),
        ciphertexts: ciphertexts.map((c) => b64(c)),
        ciphertext_post_revoke_b64: b64(ctPostRevoke),
      },
      null,
      2,
    ) + "\n",
  );

  console.log(`\n[produce] wrote ${fixturePath}`);
  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

if (mode === "verify-py") {
  // Python has (re-)written the fixture with its own ciphertexts under
  // the same seed. We decrypt them using JS kits and assert the plaintext
  // matches the recorded payloads.
  const fx = JSON.parse(readFileSync(fixturePath, "utf8"));
  if (!fx.py_ciphertexts) {
    fail("verify-py", "fixture does not contain py_ciphertexts");
    process.exit(1);
  }
  for (let i = 0; i < fx.payloads.length; i += 1) {
    const ct = fromB64(fx.py_ciphertexts[i]);
    const kit = fromB64(fx.kits.A);
    const pt = btnDecrypt(kit, ct);
    const expected = Buffer.from(fromB64(fx.payloads[i])).toString("utf8");
    if (Buffer.from(pt).toString("utf8") === expected) {
      ok(`JS decrypts Python ct[${i}]`);
    } else {
      fail(`JS decrypts Python ct[${i}]`, "plaintext mismatch");
    }
  }
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}
