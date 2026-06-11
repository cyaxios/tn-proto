/**
 * SILO: C9 — Chrome extension inline decryption
 * STATUS: SKIPPED — full Chrome+Playwright DOM-rewrite E2E is walk-tier.
 * SEE: regression/crawl/c9_chrome_ext_decrypt/README.md
 *
 * What this test WOULD do if not skipped:
 *
 *   1. Launch Chromium via Playwright with the extension loaded
 *      unpacked from `extensions/tn-decrypt/`.
 *   2. Open the extension popup, import a fixture kit.
 *   3. Lock with a passphrase.
 *   4. Navigate to a fixture page (or `extensions/tn-decrypt/test-page.html`)
 *      containing TN-encrypted blobs in DOM JSON.
 *   5. The extension's content script scans the DOM, asks the SW to
 *      decrypt, rewrites the page in place.
 *   6. Assert the plaintext renders inline + the passphrase actually
 *      gates access (locked extension does not decrypt).
 *
 * Why skipped in crawl tier: the load-bearing security property of
 * the extension is the CRYPTO layer — that the bundled wasm correctly
 * decrypts ciphertexts. `test_ext_wasm_decrypts_python.test.ts` gates
 * that. The DOM-rewrite + popup-UI + service-worker-orchestration
 * layers are mechanical wiring; their bug shape is "decrypt isn't
 * being called" or "result isn't being injected", which would surface
 * as content-script errors visible to a real user immediately.
 *
 * Lift to walk tier when:
 *   - Playwright Chromium + extension-loading is verified working
 *     in CI (uncertain on the Windows test runner today)
 *   - We have a stable encrypted-blob fixture page checked in
 *   - A failure here is actionable beyond "the extension's wiring
 *     drifted, dev needs to reload + check console"
 */
import { test } from "node:test";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

test(
  "C9: extension inline DOM rewrite (full Chrome+Playwright E2E) — SKIPPED",
  { skip: "Walk-tier — crypto-level proof in test_ext_wasm_decrypts_python.test.ts is sufficient for crawl. See README." },
  () => {
    setTestContext({ silo: "c9", test: "c9_ext_dom_rewrite::placeholder" });
    assertNamed({
      name: "playwright-ext-loaded",
      expected: true,
      observed: false,
      onMiss:
        "When this fires for real, Playwright is launching Chromium with the " +
        "extension loaded and a fixture page renders decrypted plaintext.",
    });
  },
);
