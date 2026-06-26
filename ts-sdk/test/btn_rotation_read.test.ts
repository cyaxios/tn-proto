// TS parity for rotation read access. Mirrors the Python
// tests/test_rotate_multi_kit.py guarantees: a rotation must not cost a
// prior member its pre-rotation read access - performed in place (test 1)
// or received through a group_keys sync (test 2). A first-time joiner stays
// forward-only (correct), which is a separate case not asserted here.
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";

function orderIds(tn: Tn): Set<string> {
  const ids = new Set<string>();
  for (const e of tn.read({ allRuns: true })) {
    const ent = e as {
      event_type?: string;
      eventType?: string;
      fields?: Record<string, unknown>;
    };
    if ((ent.event_type ?? ent.eventType) === "order.created") {
      ids.add(String(ent.fields?.order_id));
    }
  }
  return ids;
}

test("btn read spans a rotation boundary (rotated in place)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-rot-inplace-"));
  const yaml = join(dir, "tn.yaml");
  try {
    let tn = await Tn.init(yaml);
    tn.info("order.created", { order_id: "OLD" });
    await tn.admin.rotate("default");
    tn.info("order.created", { order_id: "NEW" });
    await tn.close();

    tn = await Tn.init(yaml);
    const ids = orderIds(tn);
    await tn.close();
    assert.ok(ids.has("NEW"), `post-rotation entry should read; saw ${[...ids]}`);
    assert.ok(ids.has("OLD"), `pre-rotation entry should read after rotate; saw ${[...ids]}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("group_keys sync keeps a prior member's pre-rotation read access", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-rot-sync-"));
  const yaml = join(dir, "tn.yaml");
  try {
    let tn = await Tn.init(yaml);
    tn.info("order.created", { order_id: "OLD" });
    const ks = (tn.config() as { keystorePath: string }).keystorePath;
    const did = tn.did;
    // The epoch-1 reader material (the prior-member view).
    const s1 = readFileSync(join(ks, "default.btn.state"));
    const k1 = readFileSync(join(ks, "default.btn.mykit"));
    // Rotate to mint epoch-2 material (what a peer device would publish).
    await tn.admin.rotate("default");
    const s2 = new Uint8Array(readFileSync(join(ks, "default.btn.state")));
    const k2 = new Uint8Array(readFileSync(join(ks, "default.btn.mykit")));
    await tn.close();

    // Reset to a prior member still at epoch 1: active = epoch 1, no archives
    // (they never rotated themselves - they only RECEIVE the rotation, below).
    writeFileSync(join(ks, "default.btn.state"), s1);
    writeFileSync(join(ks, "default.btn.mykit"), k1);
    for (const f of readdirSync(ks)) {
      if (/^default\.btn\.(state|mykit)\.(revoked|previous|retired)\./.test(f)) {
        unlinkSync(join(ks, f));
      }
    }

    tn = await Tn.init(yaml);
    assert.ok(orderIds(tn).has("OLD"), "baseline: a prior member should read its old message");
    // RECEIVE the rotation via a group_keys absorb (the epoch-2 state + kit).
    const rt = (
      tn as unknown as {
        _rt: { _absorbGroupKeys: (m: unknown, b: Map<string, Uint8Array>) => unknown };
      }
    )._rt;
    rt._absorbGroupKeys(
      { kind: "group_keys", fromDid: did, toDid: did },
      new Map([
        ["body/keys/default.btn.state", s2],
        ["body/keys/default.btn.mykit", k2],
      ]),
    );
    await tn.close();

    tn = await Tn.init(yaml);
    const after = orderIds(tn);
    await tn.close();
    assert.ok(
      after.has("OLD"),
      `prior member LOST pre-rotation read access after a synced rotation; saw ${[...after]}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
