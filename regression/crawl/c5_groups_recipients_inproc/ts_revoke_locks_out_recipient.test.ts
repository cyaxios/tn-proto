/**
 * SILO: C5 — Local groups + recipients in-process
 * TEST: a revoked recipient (TS) reads pre-revoke entries but NOT post-revoke.
 *       Revocation is forward-only.
 *
 * TS mirror of Python C5's revoke test. After `revokeRecipient + rotate`,
 * Carol's kit (minted under epoch N) should:
 *   - still unwrap entries written under epoch N (auditability of past),
 *   - fail to unwrap entries written under epoch N+1 (security).
 *
 * Asserts (named):
 *   - "ts-carol-decrypted-pre-revoke-entry"
 *   - "ts-carol-did-not-decrypt-post-revoke-entry"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const CAROL_DID = "did:key:zCarol0123456789abcdefghjkmnpqrstuvw";

test("C5 (TS): revoke + rotate locks Carol out of post-revoke entries", async () => {
  setTestContext({
    silo: "c5",
    test: "c5_ts_revoke_locks_out_recipient::forward_only_revoke",
  });

  const aliceDir = mkdtempSync(join(tmpdir(), "c5-ts-revoke-alice-"));
  const carolDir = mkdtempSync(join(tmpdir(), "c5-ts-revoke-carol-"));
  const cwdBefore = process.cwd();

  // ── Alice: add Carol, bundle her kit BEFORE revoke ─────────────
  process.chdir(aliceDir);
  const alice = await Tn.use("default");
  const aliceLog = alice.logPath;

  const aliceBundleDir = join(aliceDir, "alice_bundles");
  mkdirSync(aliceBundleDir, { recursive: true });

  const carolAdd = await alice.admin.addRecipient("default", {
    recipientDid: CAROL_DID,
  });
  const carolTnpkg = join(aliceBundleDir, "carol.tnpkg");
  await alice.pkg.bundleForRecipient({
    recipientDid: CAROL_DID,
    outPath: carolTnpkg,
    groups: ["default"],
  });

  // Pre-revoke entry — encrypted under epoch N.
  alice.info("c5.ts.pre.revoke", { marker: "visible-to-carol" });

  // Revoke Carol's leaf, then rotate so post-revoke entries land
  // under a new epoch Carol's kit can't unwrap.
  await alice.admin.revokeRecipient("default", { leafIndex: carolAdd.leafIndex });
  await alice.admin.rotate("default");

  // Post-revoke entry — encrypted under epoch N+1. Must land under
  // the rotated keys in-process (no close+reopen workaround); mirrors
  // Python's tn.admin.rotate semantics.
  alice.info("c5.ts.post.revoke", { marker: "should-be-hidden" });
  await alice.close();

  // ── Carol: absorb her kit, read Alice's log ────────────────────
  process.chdir(carolDir);
  let carol: Tn | undefined;
  try {
    carol = await Tn.use("default");
    const carolKeystore = (carol.config() as { keystorePath: string }).keystorePath;
    await carol.pkg.absorb(carolTnpkg);
    await carol.close();
    carol = await Tn.use("default");

    let preVisibleToCarol = false;
    let postVisibleToCarol = false;
    for (const entry of carol.read({
      log: aliceLog,
      asRecipient: carolKeystore,
      group: "default",
    })) {
      const e = entry as unknown as {
        event_type?: string;
        hidden_groups?: string[];
      };
      const hidden = e.hidden_groups ?? [];
      if (e.event_type === "c5.ts.pre.revoke") {
        preVisibleToCarol = !hidden.includes("default");
      } else if (e.event_type === "c5.ts.post.revoke") {
        postVisibleToCarol = !hidden.includes("default");
      }
    }

    assertNamed({
      name: "ts-carol-decrypted-pre-revoke-entry",
      expected: true,
      observed: preVisibleToCarol,
      onMiss:
        "Carol could NOT decrypt the pre-revoke entry. Revocation " +
        "should be forward-only — Carol's kit (minted under epoch N) " +
        "must still unwrap entries written under epoch N. Check the " +
        "wasm BTN cipher's per-epoch state retention.",
    });

    assertNamed({
      name: "ts-carol-did-not-decrypt-post-revoke-entry",
      expected: false,
      observed: postVisibleToCarol,
      onMiss:
        "Carol CAN decrypt the post-revoke entry — that's a " +
        "security hole. After `revokeRecipient + rotate`, Carol's " +
        "epoch-N kit must NOT unwrap epoch-N+1 envelopes. Check the " +
        "wasm rotate path actually bumped the group key.",
    });

    void assert;
  } finally {
    if (carol !== undefined) await carol.close();
    process.chdir(cwdBefore);
  }
});
