// TS parity for the genesis-anchor opt-in. Mirrors the Python
// tests/test_genesis_anchor.py guarantees: the reader trusts the first entry
// it sees by default (ordinary/resumed/rotated/partial reads start mid-chain),
// but with expectGenesis=true the first entry of each event_type chain must
// anchor at ZERO_HASH, catching a front-truncation. verifyChainLink is the
// single source of truth; this covers it directly and through rt.read().
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { verifyChainLink, ZERO_HASH } from "../src/core/chain.js";

const Z = String(ZERO_HASH());

test("verifyChainLink: default trusts the first entry, then chains", () => {
  const m = new Map<string, string>();
  assert.equal(verifyChainLink(m, "e", "sha256:anything", "sha256:r1"), true);
  assert.equal(verifyChainLink(m, "e", "sha256:r1", "sha256:r2"), true); // links
  assert.equal(verifyChainLink(m, "e", "sha256:bad", "sha256:r3"), false); // broken
});

test("verifyChainLink: genesis opt-in requires ZERO_HASH on the first entry", () => {
  assert.equal(verifyChainLink(new Map(), "e", Z, "sha256:r1", true), true);
  assert.equal(verifyChainLink(new Map(), "e", "sha256:notzero", "sha256:r1", true), false);
});

test("verifyChainLink: the genesis requirement is per event_type", () => {
  const m = new Map<string, string>();
  assert.equal(verifyChainLink(m, "a", Z, "sha256:a1", true), true); // a anchors
  assert.equal(verifyChainLink(m, "b", Z, "sha256:b1", true), true); // b anchors
  assert.equal(verifyChainLink(m, "a", "sha256:a1", "sha256:a2", true), true); // a links
  assert.equal(verifyChainLink(m, "b", "sha256:nope", "sha256:b2", true), false); // b breaks
});

function envLine(prev: string, row: string): string {
  return JSON.stringify({ event_type: "order.created", prev_hash: prev, row_hash: row });
}

test("rt.read threads expectGenesis: default tolerates truncation, opt-in catches it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-genesis-"));
  const yaml = join(dir, "tn.yaml");
  try {
    const tn = await Tn.init(yaml);
    const rt = (
      tn as unknown as {
        _rt: {
          read: (
            p: string,
            g?: boolean,
          ) => Iterable<{ envelope: Record<string, unknown>; valid: { chain: boolean } }>;
        };
      }
    )._rt;

    // A valid 3-link chain (genesis + 2) and the same chain front-truncated.
    const full = join(dir, "full.ndjson");
    writeFileSync(
      full,
      [envLine(Z, "sha256:h1"), envLine("sha256:h1", "sha256:h2"), envLine("sha256:h2", "sha256:h3")].join("\n") + "\n",
    );
    const truncated = join(dir, "trunc.ndjson");
    writeFileSync(
      truncated,
      [envLine("sha256:h1", "sha256:h2"), envLine("sha256:h2", "sha256:h3")].join("\n") + "\n",
    );

    const chains = (p: string, g: boolean): boolean[] => [...rt.read(p, g)].map((e) => e.valid.chain);

    assert.deepEqual(chains(full, false), [true, true, true], "default: full chain links");
    assert.deepEqual(chains(full, true), [true, true, true], "opt-in: a real genesis passes");
    assert.deepEqual(chains(truncated, false), [true, true], "default: truncation tolerated");
    assert.deepEqual(chains(truncated, true), [false, true], "opt-in: front-truncation caught");

    await tn.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
