import assert from "node:assert/strict";

import { jweDecrypt, jweEncrypt, jweKeygen } from "../pkg/tn_wasm.js";

const first = jweKeygen();
const second = jweKeygen();
const aad = new TextEncoder().encode("tenant=acme");
const plaintext = new TextEncoder().encode("standard JWE from Rust/WASM");

assert.equal(first.publicKey.length, 32);
assert.equal(first.privateKey.length, 32);

const ciphertext = jweEncrypt(
  plaintext,
  [first.publicKey, second.publicKey],
  aad,
);
const wire = JSON.parse(new TextDecoder().decode(ciphertext));

assert.equal(wire.recipients.length, 2);
assert.equal(wire.recipients[0].header.alg, "ECDH-ES+A256KW");
assert.equal(wire.recipients[0].header.epk.crv, "X25519");
assert.equal(wire.recipients[1].header.epk.crv, "X25519");
assert.equal(
  new TextDecoder().decode(jweDecrypt(ciphertext, [first.privateKey], aad)),
  "standard JWE from Rust/WASM",
);
assert.equal(
  new TextDecoder().decode(jweDecrypt(ciphertext, [second.privateKey], aad)),
  "standard JWE from Rust/WASM",
);
assert.throws(() => jweDecrypt(ciphertext, [first.privateKey], new Uint8Array([1])));

wire.recipients[0].header.epk.x = Buffer.alloc(32).toString("base64url");
assert.throws(
  () => jweDecrypt(new TextEncoder().encode(JSON.stringify(wire)), [second.privateKey], aad),
  /low-order X25519 public key/,
);

console.log("tn-wasm standard JWE primitives: ok");
