import { test } from "node:test";
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const CORE_DIR = join(import.meta.dirname, "..", "src", "core");
const FORBIDDEN = [
  /from\s+["']node:/,
  /from\s+["'](fs|path|os|child_process|crypto|zlib|stream|http|https|net|tls|dgram)["']/,
  /import\s+["']node:/,
  /require\(["']node:/,
];

function* walk(dir: string): Generator<string> {
  for (const ent of readdirSync(dir)) {
    const p = join(dir, ent);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (p.endsWith(".ts")) yield p;
  }
}

test("Layer 1 (src/core/) has no node:* imports", () => {
  const violations: string[] = [];
  for (const file of walk(CORE_DIR)) {
    const text = readFileSync(file, "utf8");
    for (const rx of FORBIDDEN) {
      if (rx.test(text)) violations.push(`${file}: matches ${rx}`);
    }
  }
  assert.deepEqual(violations, [], `Layer 1 must be browser-safe: ${violations.join("\n")}`);
});
