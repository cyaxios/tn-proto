// A recipient who held read access from BEFORE a publisher's rotation must
// keep it: the publisher's post-rotation kit_bundle carries the
// rotation-preserved kits alongside the current one (`.btn.mykit` plus
// `.btn.mykit.revoked.<ts>` — see NodeRuntime._buildKitBundleBody), absorb
// installs every member verbatim (displacing the recipient's same-named
// current kit to `.previous.<ts>`, per absorb_replaced_kit_paths.test.ts),
// and Python's read_as_recipient offers EVERY archived kit at decrypt time
// (BtnGroupCipher.load walks current, then `.retired.<epoch>` epoch-desc,
// then legacy `.revoked.<ts>` ts-desc). A TS reader that loads only the
// single current `<group>.btn.mykit` silently degrades every pre-rotation
// row to `$no_read_key` — rows Python still opens. These tests pin the
// multi-kit walk (runtime/keystore.ts loadBtnKits) through the sync and
// async foreign-read paths, across both archive-family names.

import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { readAsRecipient, readAsRecipientAsync } from "../src/read_as_recipient.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { Tn } from "../src/tn.js";

const BOB_DID = "did:key:z6MkBobKeepsPreRotationReadAccess";

/** Publisher side: OLD row → rotate → NEW row → export a kit_bundle (which
 *  carries the rotation-preserved kit). Recipient side: absorb it. Returns
 *  the publisher's log path and the recipient's keystore dir. */
async function rotatedPublisherAbsorbedByBob(root: string): Promise<{
  aliceLog: string;
  bobKeystore: string;
}> {
  const alice = await Tn.init(join(root, "alice", "alice.yaml"), { stdout: false });
  alice.info("order.created", { order_id: "OLD" });
  await alice.admin.rotate("default");
  alice.info("order.created", { order_id: "NEW" });
  const aliceLog = alice.logPath;
  const bundle = join(root, "bob.tnpkg");
  await alice.pkg.export({ kit: { recipientDid: BOB_DID } }, bundle);
  await alice.close();

  const bob = await Tn.init(join(root, "bob", "bob.yaml"), { stdout: false });
  const receipt = await bob.pkg.absorb(bundle);
  const bobKeystore = (bob.config() as CeremonyConfig).keystorePath;
  await bob.close();
  assert.ok(receipt.acceptedCount >= 1, `absorb installed nothing: ${JSON.stringify(receipt)}`);

  // Honesty guards: the scenario only exercises the multi-kit walk if absorb
  // left Bob holding the publisher's current kit PLUS the rotation archive,
  // with Bob's own displaced kit parked under `.previous.<ts>` (a name the
  // btn kit walk intentionally ignores — different ceremony, not an epoch).
  const names = readdirSync(bobKeystore);
  assert.ok(
    names.some((f) => /^default\.btn\.mykit\.revoked\.\d+$/.test(f)),
    `expected the bundle's rotation-preserved kit in ${bobKeystore}; got ${names.join(", ")}`,
  );
  assert.ok(
    names.some((f) => f.startsWith("default.btn.mykit.previous.")),
    `expected Bob's own displaced kit at .previous.<ts>; got ${names.join(", ")}`,
  );
  return { aliceLog, bobKeystore };
}

/** The order_ids whose `default` block actually decrypted (a `$no_read_key`
 *  marker has no order_id, so a lost row simply doesn't show up here). */
function openedOrderIds(aliceLog: string, bobKeystore: string): Set<string> {
  const ids = new Set<string>();
  for (const e of readAsRecipient(aliceLog, bobKeystore, { group: "default" })) {
    if (e.envelope["event_type"] !== "order.created") continue;
    const id = e.plaintext["default"]?.["order_id"];
    if (typeof id === "string") ids.add(id);
  }
  return ids;
}

test("readAsRecipient opens rows sealed before the publisher rotated + re-minted", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-rot-recipient-"));
  try {
    const { aliceLog, bobKeystore } = await rotatedPublisherAbsorbedByBob(root);

    const ids = openedOrderIds(aliceLog, bobKeystore);
    assert.ok(ids.has("NEW"), `post-rotation row should open; saw ${[...ids]}`);
    assert.ok(ids.has("OLD"), `pre-rotation row should open via the archived kit; saw ${[...ids]}`);

    // The modern `.retired.<epoch>` family (what Python's tn.admin.rotate
    // archives, and what a Python-built bundle installs) must flow through
    // the same walk: rename the legacy archive and read again.
    let renamed = 0;
    for (const f of readdirSync(bobKeystore)) {
      if (/^default\.btn\.mykit\.revoked\.\d+$/.test(f)) {
        renameSync(join(bobKeystore, f), join(bobKeystore, "default.btn.mykit.retired.1"));
        renamed += 1;
      }
    }
    assert.equal(renamed, 1, "precondition: exactly one legacy archive to rename");
    const retiredIds = openedOrderIds(aliceLog, bobKeystore);
    assert.ok(
      retiredIds.has("OLD"),
      `pre-rotation row should open via a .retired.<epoch> kit; saw ${[...retiredIds]}`,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("readAsRecipientAsync walks the same archived-kit list", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-rot-recipient-async-"));
  try {
    const { aliceLog, bobKeystore } = await rotatedPublisherAbsorbedByBob(root);
    const ids = new Set<string>();
    for await (const e of readAsRecipientAsync(aliceLog, bobKeystore, { group: "default" })) {
      if (e.envelope["event_type"] !== "order.created") continue;
      const id = e.plaintext["default"]?.["order_id"];
      if (typeof id === "string") ids.add(id);
    }
    assert.ok(ids.has("NEW"), `post-rotation row should open; saw ${[...ids]}`);
    assert.ok(ids.has("OLD"), `pre-rotation row should open via the archived kit; saw ${[...ids]}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
