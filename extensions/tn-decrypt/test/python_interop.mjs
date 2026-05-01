// Cross-language interop: Python `tn_btn` -> extension wasm bundle.
//
// What this proves:
//   The exact `wasm/tn_wasm.js` + `wasm/tn_wasm_bg.wasm` bytes shipped
//   in the extension can decrypt ciphertexts minted by Python `tn_btn`,
//   using the same `btnDecrypt` and `btnKitPublisherId` functions
//   `background.js` calls at runtime.
//
// Why we test against the EXTENSION'S COPY of the bundle (not the
// repo-root pkg-web/ copy): the extension ships a checked-in copy of
// the wasm artifacts. If those drift from pkg-web, the dashboard tests
// will keep passing while the extension silently breaks. Loading the
// extension's bundle here makes drift a build-time failure.
//
// Pipeline:
//   1. Spawn Python via `.venv/Scripts/python.exe` to run
//      `python_fixture_gen.py <tmpdir>`. That writes kit.bin,
//      ciphertext.bin, plaintext.json, meta.json.
//   2. Read the extension's wasm bundle and `__wbg_init` it with the
//      bytes (mirrors how the dashboard's wasm_e2e test loads pkg-web).
//   3. Assert `btnKitPublisherId(kit) === btnCiphertextPublisherId(ct)`
//      — Python's publisher-id matches what the extension sees.
//   4. Assert `btnDecrypt(kit, ct) === plaintext` — the extension's
//      decrypt path round-trips the Python plaintext.
//
// Refs:
//   - D-22 (passphrase fallback — orthogonal; this test exercises only
//     the decrypt path, no unlock state)
//   - dashboard wasm_e2e (reverse direction: JS -> Python)
//   - D-28 (typed errors / structured logging — informs the rich
//     `[ext:test]` output here)

import { Buffer } from "node:buffer";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const extRoot = resolve(here, "..");
const repoRoot = resolve(here, "../../../..");

let passed = 0, failed = 0;
function ok(m) { console.log(`[ok]   ${m}`); passed += 1; }
function fail(m, why) { console.log(`[fail] ${m}: ${why}`); failed += 1; }

function hex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── 1. Generate fixture from Python ─────────────────────────────────────

const fixtureDir = join(tmpdir(), `tn-ext-py-interop-${Date.now()}`);
mkdirSync(fixtureDir, { recursive: true });

const pyBin = process.env.TN_PYTHON
  || resolve(repoRoot, ".venv/Scripts/python.exe");
const fixtureScript = resolve(here, "python_fixture_gen.py");

console.log(`[ext:test] generating Python fixture at ${fixtureDir}`);
const proc = spawnSync(pyBin, [fixtureScript, fixtureDir], {
  encoding: "utf8", cwd: repoRoot,
});
if (proc.status !== 0) {
  console.error(`[ext:test] python fixture generator failed (rc=${proc.status})`);
  console.error("stdout:", proc.stdout);
  console.error("stderr:", proc.stderr);
  process.exit(2);
}

const kitBytes = readFileSync(join(fixtureDir, "kit.bin"));
const ctBytes = readFileSync(join(fixtureDir, "ciphertext.bin"));
const plaintextBytes = readFileSync(join(fixtureDir, "plaintext.json"));
const meta = JSON.parse(readFileSync(join(fixtureDir, "meta.json"), "utf8"));

console.log(`[ext:test] fixture: kit=${kitBytes.length}b ct=${ctBytes.length}b pt=${plaintextBytes.length}b publisher=${meta.publisher_id_hex?.slice(0, 16)}...`);

// ── 2. Load the EXTENSION'S copy of the wasm bundle ────────────────────
//
// This is the Node-equivalent of the loader pattern the SW uses
// (chrome-extension://<id>/wasm/tn_wasm.js). We can't ship a
// chrome-extension URL into Node, so we precompile the .wasm and pass
// the WebAssembly.Module to wasm-bindgen's `__wbg_init`. That branch
// works regardless of target ("nodejs" vs "web") because it bypasses
// the URL fetch path entirely.

const wasmJsPath = resolve(extRoot, "wasm/tn_wasm.js");
const wasmBgPath = resolve(extRoot, "wasm/tn_wasm_bg.wasm");

console.log(`[ext:test] loading extension wasm bundle js=${wasmJsPath}`);
const wasmMod = await import(pathToFileURL(wasmJsPath).href);
if (typeof wasmMod.default === "function") {
  const bytes = readFileSync(wasmBgPath);
  const m = await WebAssembly.compile(bytes);
  // wasm-bindgen prefers an object with `module_or_path` to avoid the
  // deprecation warning we used to see under `await wasmMod.default(m)`.
  await wasmMod.default({ module_or_path: m });
}

const { btnDecrypt, btnCiphertextPublisherId, btnKitPublisherId } = wasmMod;
if (typeof btnDecrypt !== "function") fail("wasm exports", "btnDecrypt missing");
if (typeof btnCiphertextPublisherId !== "function") fail("wasm exports", "btnCiphertextPublisherId missing");
if (typeof btnKitPublisherId !== "function") fail("wasm exports", "btnKitPublisherId missing");

// ── 3. Publisher-ID parity ──────────────────────────────────────────────

const kitU8 = new Uint8Array(kitBytes);
const ctU8 = new Uint8Array(ctBytes);

let kitPub, ctPub;
try { kitPub = hex(btnKitPublisherId(kitU8)); }
catch (e) { fail("btnKitPublisherId(kit)", `${e?.name || "Error"} ${e?.message || ""}`); }
try { ctPub = hex(btnCiphertextPublisherId(ctU8)); }
catch (e) { fail("btnCiphertextPublisherId(ct)", `${e?.name || "Error"} ${e?.message || ""}`); }

if (kitPub && ctPub && kitPub === ctPub) {
  ok(`extension wasm sees same publisher_id as Python: ${kitPub.slice(0, 16)}...`);
} else {
  fail("publisher_id parity", `kit=${kitPub} ct=${ctPub}`);
}

if (meta.publisher_id_hex && kitPub === meta.publisher_id_hex) {
  ok("publisher_id_hex matches Python meta.json");
} else if (meta.publisher_id_hex) {
  fail("publisher_id vs Python meta", `wasm=${kitPub} python=${meta.publisher_id_hex}`);
}

// ── 4. The actual decrypt — extension wasm vs Python ciphertext ────────

let ptU8;
try {
  ptU8 = btnDecrypt(kitU8, ctU8);
} catch (e) {
  fail("btnDecrypt", `${e?.name || "Error"} ${e?.message || ""}`);
}

if (ptU8) {
  const recovered = Buffer.from(ptU8);
  if (recovered.length === plaintextBytes.length && recovered.equals(plaintextBytes)) {
    ok(`extension wasm decrypts Python ciphertext byte-for-byte (${recovered.length}b)`);
  } else {
    fail("plaintext mismatch", `got ${recovered.length}b expected ${plaintextBytes.length}b`);
  }

  // Also assert the JSON round-trips cleanly into the same object.
  let recoveredObj = null;
  try { recoveredObj = JSON.parse(new TextDecoder().decode(recovered)); } catch {}
  if (recoveredObj && recoveredObj.customer_name === meta.plaintext_obj.customer_name) {
    ok("plaintext parses as the original JSON object");
  } else {
    fail("json parity", JSON.stringify(recoveredObj));
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
