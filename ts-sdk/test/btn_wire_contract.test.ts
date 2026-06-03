// Cross-language BTN wire contract (TS/WASM side).
//
// The BTN binary wire format is owned by Rust (crypto/tn-btn) and reached
// from TS via WASM (btn_decrypt_js, re-exported as btnDecrypt). This test
// decodes the SAME shared golden ciphertext that the Python test
// (python/tests/test_btn_wire_contract.py) and the Rust test
// (crypto/tn-core/tests/cipher_btn.rs) decode — proving no SDK
// reinterprets the wire independently.
//
// Shared golden: crypto/tn-core/tests/fixtures/btn_vectors.json.
// See docs/spec-next/btn-wire.md.

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { btnDecrypt } from "../src/raw.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(HERE, "..", "..", "crypto", "tn-core", "tests", "fixtures", "btn_vectors.json");

const BTN_MAGIC = 0xb7;
const BTN_VERSION = 0x01;
const KIND_CIPHERTEXT = 0x01;
const KIND_READER_KIT = 0x02;
const KIND_PUBLISHER_STATE = 0x03;

function hexToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

interface BtnVector {
  reader_kit_bytes_hex: string;
  ciphertext_hex: string;
  plaintext_hex: string;
  publisher_state_bytes_hex: string;
}

const v = JSON.parse(readFileSync(FIXTURE, "utf-8")) as BtnVector;

test("btn: WASM decrypts the shared golden ciphertext", () => {
  const kit = hexToBytes(v.reader_kit_bytes_hex);
  const ct = hexToBytes(v.ciphertext_hex);
  const pt = btnDecrypt(kit, ct);
  assert.equal(bytesToHex(pt), v.plaintext_hex);
});

test("btn: wire headers (magic/version/kind) match the layout", () => {
  for (const [hex, kind] of [
    [v.ciphertext_hex, KIND_CIPHERTEXT],
    [v.reader_kit_bytes_hex, KIND_READER_KIT],
    [v.publisher_state_bytes_hex, KIND_PUBLISHER_STATE],
  ] as const) {
    const b = hexToBytes(hex);
    assert.equal(b[0], BTN_MAGIC);
    assert.equal(b[1], BTN_VERSION);
    assert.equal(b[2], kind);
  }
});
