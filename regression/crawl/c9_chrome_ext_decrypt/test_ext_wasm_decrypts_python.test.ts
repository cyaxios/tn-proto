/**
 * SILO: C9 — Chrome extension inline decryption
 * TEST: the extension's bundled wasm decrypts a Python-minted ciphertext
 *       byte-for-byte.
 * SEE: regression/crawl/c9_chrome_ext_decrypt/README.md
 *
 * Why we load the EXTENSION's copy of the wasm and not the SDK's
 * pkg-web/ copy: the extension ships a checked-in vendored bundle.
 * If that bundle drifts from what the SDK builds, dashboard tests
 * keep passing while the extension silently breaks for real users.
 * Loading the extension's bundle here makes drift a regression-suite
 * failure.
 *
 * Pipeline:
 *   1. Spawn Python to run `python_fixture_gen.py <tmpdir>`. That
 *      uses tn_btn to mint a kit + ciphertext + plaintext.
 *   2. Read the extension's wasm bundle and `__wbg_init` it with the
 *      pre-compiled WebAssembly.Module (bypasses URL fetch — works
 *      in Node).
 *   3. Assert publisher_id parity (kit vs ciphertext, both via wasm).
 *   4. Assert `btnDecrypt(kit, ciphertext)` matches Python's plaintext
 *      bytes exactly + parses to the same JSON.
 *
 * Asserts (named):
 *   - "python-fixture-gen-exit-0"
 *   - "ext-wasm-exports-btndecrypt"
 *   - "ext-wasm-publisher-id-matches-python"
 *   - "ext-wasm-decrypt-byte-identical"
 *   - "ext-wasm-plaintext-parses-as-json"
 */
import { test } from "node:test";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const here = pathResolve(fileURLToPath(import.meta.url), "..");
const repoRoot = pathResolve(here, "../../..");
const extRoot = pathResolve(repoRoot, "extensions/tn-decrypt");

const PY =
  process.env["TN_REGRESSION_PYTHON"] ??
  pathResolve(repoRoot, ".venv/Scripts/python.exe");

function hex(bytes: Uint8Array | Buffer): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

test("C9: extension's bundled wasm decrypts Python ciphertext", async () => {
  setTestContext({
    silo: "c9",
    test: "c9_ext_wasm_decrypts_python::cross_language_decrypt",
  });

  // ── 1. Python mints fixture ─────────────────────────────────────
  const fixtureDir = join(tmpdir(), `c9-ext-fixture-${Date.now()}`);
  mkdirSync(fixtureDir, { recursive: true });

  const fixtureScript = pathResolve(
    extRoot,
    "test/python_fixture_gen.py",
  );
  const proc = spawnSync(PY, [fixtureScript, fixtureDir], {
    encoding: "utf-8",
    cwd: repoRoot,
    timeout: 30000,
  });
  assertNamed({
    name: "python-fixture-gen-exit-0",
    expected: 0,
    observed: proc.status ?? -1,
    onMiss:
      `python_fixture_gen.py exited ${proc.status}. ` +
      `stderr=${JSON.stringify(proc.stderr?.slice(0, 500) ?? "")}. ` +
      `Likely cause: tn_btn not installed in ${PY}. Run ` +
      `\`pip install --pre --index-url https://test.pypi.org/simple/ ` +
      `--extra-index-url https://pypi.org/simple/ tn-btn\`.`,
  });

  const kitBytes = readFileSync(join(fixtureDir, "kit.bin"));
  const ctBytes = readFileSync(join(fixtureDir, "ciphertext.bin"));
  const plaintextBytes = readFileSync(join(fixtureDir, "plaintext.json"));
  const meta = JSON.parse(
    readFileSync(join(fixtureDir, "meta.json"), "utf-8"),
  ) as { publisher_id_hex: string; plaintext_obj: Record<string, unknown> };

  // ── 2. Load the EXTENSION's wasm bundle ─────────────────────────
  const wasmJsPath = pathResolve(extRoot, "wasm/tn_wasm.js");
  const wasmBgPath = pathResolve(extRoot, "wasm/tn_wasm_bg.wasm");

  const wasmMod = (await import(pathToFileURL(wasmJsPath).href)) as {
    default?: (opts: { module_or_path: WebAssembly.Module }) => Promise<unknown>;
    btnDecrypt?: (kit: Uint8Array, ct: Uint8Array) => Uint8Array;
    btnKitPublisherId?: (kit: Uint8Array) => Uint8Array;
    btnCiphertextPublisherId?: (ct: Uint8Array) => Uint8Array;
  };

  if (typeof wasmMod.default === "function") {
    const bytes = readFileSync(wasmBgPath);
    const m = await WebAssembly.compile(bytes);
    await wasmMod.default({ module_or_path: m });
  }

  assertNamed({
    name: "ext-wasm-exports-btndecrypt",
    expected: true,
    observed:
      typeof wasmMod.btnDecrypt === "function" &&
      typeof wasmMod.btnKitPublisherId === "function" &&
      typeof wasmMod.btnCiphertextPublisherId === "function",
    onMiss:
      `Extension wasm bundle missing one of btnDecrypt / ` +
      `btnKitPublisherId / btnCiphertextPublisherId. The vendored ` +
      `wasm in extensions/tn-decrypt/wasm/ has drifted from the SDK ` +
      `build. Re-vendor from crypto/tn-wasm/pkg-web/.`,
  });

  if (
    typeof wasmMod.btnDecrypt !== "function" ||
    typeof wasmMod.btnKitPublisherId !== "function" ||
    typeof wasmMod.btnCiphertextPublisherId !== "function"
  ) {
    return; // earlier assert already captured the failure
  }

  // ── 3. Publisher-id parity (kit vs ciphertext, via wasm) ────────
  const kitU8 = new Uint8Array(kitBytes);
  const ctU8 = new Uint8Array(ctBytes);

  const kitPub = hex(wasmMod.btnKitPublisherId(kitU8));
  const ctPub = hex(wasmMod.btnCiphertextPublisherId(ctU8));

  assertNamed({
    name: "ext-wasm-publisher-id-matches-python",
    expected: meta.publisher_id_hex,
    observed: kitPub,
    onMiss:
      `Extension wasm sees publisher_id=${kitPub.slice(0, 16)}... but ` +
      `Python meta.json reports ${meta.publisher_id_hex?.slice(0, 16)}... ` +
      `Wire-format mismatch between extension's vendored wasm and ` +
      `python's tn_btn — re-vendor or rebuild the Python wheel.`,
  });

  assertNamed({
    name: "ext-wasm-kit-ct-publisher-ids-agree",
    expected: kitPub,
    observed: ctPub,
    onMiss:
      `btnKitPublisherId says ${kitPub.slice(0, 16)}... but ` +
      `btnCiphertextPublisherId says ${ctPub.slice(0, 16)}.... ` +
      `That means the wasm bundle disagrees with itself about how to ` +
      `derive publisher_id from the two artifacts. Check ` +
      `crypto/tn-btn/src/lib.rs.`,
  });

  // ── 4. Decrypt + bytes equal Python plaintext ───────────────────
  const recovered = wasmMod.btnDecrypt(kitU8, ctU8);
  const recoveredBuf = Buffer.from(recovered);

  assertNamed({
    name: "ext-wasm-decrypt-byte-identical",
    expected: plaintextBytes.length,
    observed: recoveredBuf.length,
    onMiss:
      `Decrypt produced ${recoveredBuf.length} bytes; expected ` +
      `${plaintextBytes.length}. Length mismatch indicates the cipher ` +
      `body was truncated or padded differently.`,
  });

  const equal = recoveredBuf.equals(plaintextBytes);
  assertNamed({
    name: "ext-wasm-decrypt-bytes-equal-python",
    expected: true,
    observed: equal,
    onMiss:
      `Length matched but bytes diverged. ` +
      `recovered_hex=${recoveredBuf.toString("hex").slice(0, 64)}... ` +
      `expected_hex=${plaintextBytes.toString("hex").slice(0, 64)}... ` +
      `Wire-format drift between Python tn_btn and the extension's ` +
      `vendored wasm.`,
  });

  // JSON parses to the same object.
  let recoveredObj: Record<string, unknown> | null = null;
  try {
    recoveredObj = JSON.parse(new TextDecoder().decode(recoveredBuf));
  } catch {
    /* leave null */
  }
  assertNamed({
    name: "ext-wasm-plaintext-parses-as-json",
    expected: meta.plaintext_obj["customer_name"],
    observed: recoveredObj?.["customer_name"],
    onMiss:
      `Decrypted JSON didn't parse cleanly or shape changed. ` +
      `recovered=${JSON.stringify(recoveredObj)}, ` +
      `expected=${JSON.stringify(meta.plaintext_obj)}`,
  });
});
