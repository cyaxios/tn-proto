// TS parity for the btn rotation promote-crash fix (mirrors the Python
// tests/test_btn_keystore.py + test_rotate_multi_kit.py crash-safety tests).
//
// rotateGroup / _absorbGroupKeys must commit a group's new state+kit through a
// pending->archive->promote dance so a crash mid-rotation never destroys the
// only writable copy. recoverInterruptedPromotes (run on every loadKeystore)
// rolls a surviving .pending pair FORWARD when the active pair is gone, or
// discards it when the active pair is still intact.
import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import {
  commitGroupKeys,
  recoverInterruptedPromotes,
  loadKeystore,
} from "../src/runtime/keystore.js";

test("recoverInterruptedPromotes rolls forward when the active pair is gone", () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-promote-fwd-"));
  try {
    writeFileSync(join(dir, "default.btn.state.pending"), Buffer.from("NEW_STATE"));
    writeFileSync(join(dir, "default.btn.mykit.pending"), Buffer.from("NEW_KIT"));
    // active absent (the crash window: unlinked, pending not yet renamed)
    recoverInterruptedPromotes(dir);
    assert.equal(readFileSync(join(dir, "default.btn.state")).toString(), "NEW_STATE");
    assert.equal(readFileSync(join(dir, "default.btn.mykit")).toString(), "NEW_KIT");
    assert.ok(!existsSync(join(dir, "default.btn.state.pending")));
    assert.ok(!existsSync(join(dir, "default.btn.mykit.pending")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recoverInterruptedPromotes rolls back an orphan pending when active is intact", () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-promote-back-"));
  try {
    writeFileSync(join(dir, "default.btn.state"), Buffer.from("OLD_STATE"));
    writeFileSync(join(dir, "default.btn.mykit"), Buffer.from("OLD_KIT"));
    writeFileSync(join(dir, "default.btn.state.pending"), Buffer.from("ORPHAN"));
    writeFileSync(join(dir, "default.btn.mykit.pending"), Buffer.from("ORPHAN"));
    recoverInterruptedPromotes(dir);
    // Active untouched; orphan pending discarded.
    assert.equal(readFileSync(join(dir, "default.btn.state")).toString(), "OLD_STATE");
    assert.ok(!existsSync(join(dir, "default.btn.state.pending")));
    assert.ok(!existsSync(join(dir, "default.btn.mykit.pending")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recoverInterruptedPromotes lands a surviving half (state renamed, kit not)", () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-promote-half-"));
  try {
    writeFileSync(join(dir, "default.btn.state"), Buffer.from("NEW_STATE"));
    // active kit gone, only the pending kit survives
    writeFileSync(join(dir, "default.btn.mykit.pending"), Buffer.from("NEW_KIT"));
    recoverInterruptedPromotes(dir);
    assert.equal(readFileSync(join(dir, "default.btn.state")).toString(), "NEW_STATE");
    assert.equal(readFileSync(join(dir, "default.btn.mykit")).toString(), "NEW_KIT");
    assert.ok(!existsSync(join(dir, "default.btn.mykit.pending")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("commitGroupKeys stages, archives the old pair, and promotes", () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-commit-"));
  try {
    writeFileSync(join(dir, "default.btn.state"), Buffer.from("OLD_STATE"));
    writeFileSync(join(dir, "default.btn.mykit"), Buffer.from("OLD_KIT"));
    commitGroupKeys(dir, "default", {
      stateBytes: new Uint8Array(Buffer.from("NEW_STATE")),
      selfKit: new Uint8Array(Buffer.from("NEW_KIT")),
      archiveTs: "1700000000",
    });
    // Active is the new generation.
    assert.equal(readFileSync(join(dir, "default.btn.state")).toString(), "NEW_STATE");
    assert.equal(readFileSync(join(dir, "default.btn.mykit")).toString(), "NEW_KIT");
    // No pending left behind.
    assert.ok(!existsSync(join(dir, "default.btn.state.pending")));
    assert.ok(!existsSync(join(dir, "default.btn.mykit.pending")));
    // Old kit archived as a loadable .revoked.<ts> (historical reads survive).
    assert.equal(
      readFileSync(join(dir, "default.btn.mykit.revoked.1700000000")).toString(),
      "OLD_KIT",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadKeystore recovers a mid-promote crash into a writable publisher (e2e)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-rot-crash-"));
  const yaml = join(dir, "tn.yaml");
  try {
    let tn = await Tn.init(yaml);
    tn.info("order.created", { order_id: "OLD" });
    const ks = (tn.config() as { keystorePath: string }).keystorePath;
    await tn.close();

    // Reconstruct a mid-promote crash on disk: the new generation sits in
    // .pending, the active pair has been moved aside, nothing renamed back.
    const stateActive = join(ks, "default.btn.state");
    const kitActive = join(ks, "default.btn.mykit");
    const newState = readFileSync(stateActive);
    const newKit = readFileSync(kitActive);
    writeFileSync(`${stateActive}.pending`, newState);
    writeFileSync(`${kitActive}.pending`, newKit);
    renameSync(stateActive, `${stateActive}.revoked.1700000000`);
    renameSync(kitActive, `${kitActive}.revoked.1700000000`);
    assert.ok(!existsSync(stateActive), "precondition: active state removed");

    // loadKeystore (via Tn.init) must recover - rolling pending forward - so
    // the publisher is writable again (no "not a btn publisher" / decrypt loss).
    tn = await Tn.init(yaml);
    tn.info("order.created", { order_id: "AFTER" });
    const ids = new Set<string>();
    for (const e of tn.read({ allRuns: true })) {
      const ent = e as { event_type?: string; eventType?: string; fields?: Record<string, unknown> };
      if ((ent.event_type ?? ent.eventType) === "order.created") ids.add(String(ent.fields?.order_id));
    }
    await tn.close();
    assert.ok(ids.has("AFTER"), `post-recovery write should land+read; saw ${[...ids]}`);

    // Sanity: the recovered keystore loads with an active state for the group.
    assert.ok(loadKeystore(ks).groups.has("default"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
