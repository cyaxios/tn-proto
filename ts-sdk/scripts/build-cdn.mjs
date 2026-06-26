// Copy the self-contained browser bundle into the repo-root cdn/ directory so
// it can be served directly — GitHub raw, jsDelivr, or any static host / CDN —
// without going through npm. The bundle inlines the wasm (base64), so there is
// no separate .wasm to pair or serve.
//
// Run via `npm run build:cdn` (which builds the browser bundle first). Keep
// cdn/tn-proto.browser.mjs in lockstep with the published version.
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "dist", "browser.mjs");
const outDir = join(here, "..", "..", "cdn");
mkdirSync(outDir, { recursive: true });
const out = join(outDir, "tn-proto.browser.mjs");
copyFileSync(src, out);
console.log(`cdn: wrote ${out}`);
