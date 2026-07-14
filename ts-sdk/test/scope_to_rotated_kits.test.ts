// A scoped reader (tn.scopeTo(did).spawn()) must keep read access to rows
// sealed BEFORE the publisher rotated, exactly like readAsRecipient over the
// same keystore: after absorbing a post-rotation kit_bundle the keystore
// holds the publisher's current kit at `<group>.btn.mykit` PLUS the
// rotation-preserved kit at `.btn.mykit.revoked.<ts>` (legacy family; a
// Python publisher archives as `.retired.<epoch>`). ScopedTn._kits must
// offer every archived kit (runtime/keystore.ts loadBtnKits), not only the
// single current file — otherwise every pre-rotation row silently stays
// sealed on the scoped surface while readAsRecipient opens it.

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, readdirSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import type { ScopeBuilder, ScopedTn } from "../src/scope.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { Tn } from "../src/tn.js";

/** Publisher side: OLD row → rotate → NEW row → export a kit_bundle (which
 *  carries the rotation-preserved kit). Recipient side: absorb it, then hand
 *  back a ScopeBuilder over Bob's own ceremony — Bob's device DID is a
 *  recipient of his `default` group, so the spawned handle may open the
 *  `default` blocks of the handed-in stream. Each read pass spawns a fresh
 *  ScopedTn because the handle memoizes kits per group. */
async function rotatedPublisherScopedForBob(root: string): Promise<{
  aliceLogText: string;
  bobKeystore: string;
  scope: ScopeBuilder;
}> {
  const bob = await Tn.init(join(root, "bob", "bob.yaml"), { stdout: false });
  const alice = await Tn.init(join(root, "alice", "alice.yaml"), { stdout: false });
  alice.info("order.created", { order_id: "OLD" });
  await alice.admin.rotate("default");
  alice.info("order.created", { order_id: "NEW" });
  const aliceLog = alice.logPath;
  const bundle = join(root, "bob.tnpkg");
  await alice.pkg.export({ kit: { recipientDid: bob.did } }, bundle);
  await alice.close();
  const aliceLogText = readFileSync(aliceLog, "utf8");

  const receipt = await bob.pkg.absorb(bundle);
  const bobKeystore = (bob.config() as CeremonyConfig).keystorePath;
  const scope = bob.scopeTo(bob.did);
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
  return { aliceLogText, bobKeystore, scope };
}

/** The order_ids whose `default` block actually decrypted on the scoped
 *  surface (a sealed row contributes no order_id field, so a lost row simply
 *  doesn't show up here). */
function openedOrderIds(scoped: ScopedTn, logText: string): Set<string> {
  const ids = new Set<string>();
  for (const e of scoped.read(logText)) {
    if (e.event_type !== "order.created") continue;
    const id = e.fields["order_id"];
    if (typeof id === "string") ids.add(id);
  }
  return ids;
}

test("scopeTo(...).spawn().read opens rows sealed before the publisher rotated + re-minted", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-rot-scope-"));
  try {
    const { aliceLogText, bobKeystore, scope } = await rotatedPublisherScopedForBob(root);

    const scoped = scope.spawn();
    assert.ok(
      scoped.groups.includes("default"),
      `Bob's DID should entitle 'default'; allowed: ${scoped.groups.join(", ")}`,
    );
    const ids = openedOrderIds(scoped, aliceLogText);
    assert.ok(ids.has("NEW"), `post-rotation row should open; saw ${[...ids]}`);
    assert.ok(ids.has("OLD"), `pre-rotation row should open via the archived kit; saw ${[...ids]}`);

    // The modern `.retired.<epoch>` family (what Python's tn.admin.rotate
    // archives, and what a Python-built bundle installs) must flow through
    // the same walk: rename the legacy archive and read again on a fresh
    // handle (the previous one memoized its kit list).
    let renamed = 0;
    for (const f of readdirSync(bobKeystore)) {
      if (/^default\.btn\.mykit\.revoked\.\d+$/.test(f)) {
        renameSync(join(bobKeystore, f), join(bobKeystore, "default.btn.mykit.retired.1"));
        renamed += 1;
      }
    }
    assert.equal(renamed, 1, "precondition: exactly one legacy archive to rename");
    const retiredIds = openedOrderIds(scope.spawn(), aliceLogText);
    assert.ok(
      retiredIds.has("OLD"),
      `pre-rotation row should open via a .retired.<epoch> kit; saw ${[...retiredIds]}`,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
