// SDK never crashes user space: an INFRASTRUCTURE failure in the wasm logging
// boundary (core unavailable, init failure, a Rust panic/abort during emit)
// must be contained — surfaced once, never thrown into the host process. That
// is what crashed the Vercel dev server. APPLICATION errors (a malformed event
// failing schema validation) still propagate so callers can handle them and a
// real data bug is never silently swallowed. This pins both halves so a future
// change can't re-introduce the crash, or start papering over data bugs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../src/tn.js";

type RtLike = { attachWasm: () => unknown };

test("infrastructure wasm failures are contained, never crash the host", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-nocrash-"));
  try {
    const tn = await Tn.init(join(dir, "tn.yaml"), { stdout: false });
    try {
      const rt = (tn as unknown as { _rt: RtLike })._rt;

      // A Rust panic surfaces as a wasm trap (WebAssembly.RuntimeError).
      rt.attachWasm = () => {
        throw new WebAssembly.RuntimeError("unreachable (simulated wasm panic)");
      };
      assert.doesNotThrow(() => {
        const r = tn.info("evt.panic", { seq: 1 });
        assert.equal(r.sequence, 0, "contained emit yields a zero receipt");
      });

      // The core can't load at all (no fs on edge, missing .wasm after a bundle).
      rt.attachWasm = () => {
        throw new Error("tn-wasm is unavailable (see prior tn-proto warning)");
      };
      assert.doesNotThrow(() => {
        for (let i = 0; i < 5; i++) tn.info("evt.unavailable", { seq: i });
      });
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("application errors (bad data / schema) propagate to the caller", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-appfail-"));
  try {
    const tn = await Tn.init(join(dir, "tn.yaml"), { stdout: false });
    try {
      const rt = (tn as unknown as { _rt: RtLike })._rt;
      // wasm is healthy, but the event is malformed — a real data error the
      // caller (e.g. the inbox-accept CLI) must see, not a silent no-op.
      rt.attachWasm = () =>
        ({
          emitReturningLine: () => {
            throw new Error('malformed admin event data: failed schema: missing required field "x"');
          },
        }) as unknown;
      assert.throws(() => tn.info("evt.malformed", { seq: 1 }), /failed schema/);
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recovers (re-inits) after a transient wasm failure", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-recover-"));
  try {
    const tn = await Tn.init(join(dir, "tn.yaml"), { stdout: false });
    try {
      const rt = (tn as unknown as { _rt: RtLike })._rt;
      const real = rt.attachWasm.bind(rt);
      let calls = 0;
      rt.attachWasm = () => {
        calls += 1;
        if (calls === 1) throw new WebAssembly.RuntimeError("transient (simulated)");
        return real();
      };

      // First emit: transient failure, contained (zero receipt) — host survives.
      const r1 = tn.info("evt.recover", { seq: 1 });
      assert.equal(r1.sequence, 0, "first emit contained on the transient failure");

      // Next emit: the runtime was dropped, so this re-inits and actually emits.
      const r2 = tn.info("evt.recover", { seq: 2 });
      assert.ok(
        r2.eventId !== "" || r2.sequence > 0,
        "logger recovered and emitted after the transient failure",
      );
      assert.ok(calls >= 2, "attachWasm was retried after the failure");
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
