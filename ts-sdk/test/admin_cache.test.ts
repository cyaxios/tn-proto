// Tests for AdminStateCache (LKV).
//
// Mirrors `python/tests/test_admin_state_cache.py`. Covers:
//   1. Cold path: matches tn.admin.state() shape.
//   2. Hot path: incremental at_offset advance.
//   3. Persistence across new Tn instances (reads admin.lkv.json).
//   4. Atomicity: stranded `.tmp` is ignored on next startup.
//   5. Revocation-is-terminal: leaf-reuse attempt surfaces.
//   6. Same-coordinate fork detection.
//   7. Idempotent refresh.
//   8. Per-client instance lifecycle.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  AdminStateCache,
  DeviceKey,
  resolveAdminLogPath,
} from "../src/index.js";
import { Tn } from "../src/tn.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { BtnPublisher } from "../src/raw.js";

function makeCeremony(): { yamlPath: string; tmpDir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-cache-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 11 + 19) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 41) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  const yaml = `ceremony:\n  id: cache_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${dk.did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\n- group\n- leaf_index\n- recipient_did\n- kit_sha256\n- cipher\n- ceremony_id\n- vault_did\n- project_id\n- linked_at\n- publisher_did\n- added_at\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - did: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    tmpDir: dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

// 1. Cold path
test("AdminStateCache cold path matches client.adminState()", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default_bob.btn.mykit"), recipientDid: "did:key:zBob" });

    const cached = tn.admin.cache().state();
    const expected = tn.admin.state();

    const cachedRecs = cached.recipients
      .map((r) => `${r.group}|${r.leafIndex}|${r.activeStatus}`)
      .sort();
    const expectedRecs = expected.recipients
      .map((r) => `${r.group}|${r.leafIndex}|${r.activeStatus}`)
      .sort();
    assert.deepEqual(cachedRecs, expectedRecs);

    await tn.close();
  } finally {
    cleanup();
  }
});

// 2. Hot path
test("AdminStateCache hot path advances at_offset by 1 per emit", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });

    // Prime
    const cache = tn.admin.cache();
    const s1 = cache.state();
    const offset1 = cache.atOffset;
    const n1 = s1.recipients.length;

    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default_bob.btn.mykit"), recipientDid: "did:key:zBob" });
    const s2 = cache.state();
    const offset2 = cache.atOffset;
    assert.equal(s2.recipients.length, n1 + 1);
    assert.equal(offset2, offset1 + 1);

    await tn.close();
  } finally {
    cleanup();
  }
});

// 3. Persistence across new instances
test("AdminStateCache persists to disk and reloads on a new instance", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    const cache = tn.admin.cache();
    const preState = cache.state();
    const preOffset = cache.atOffset;
    assert.ok(preOffset > 0);

    const lkvPath = join(tmpDir, ".tn/admin", "admin.lkv.json");
    assert.ok(existsSync(lkvPath), "cache must write admin.lkv.json");
    await tn.close();

    // Re-init on a fresh instance.
    const tn2 = await Tn.init(yamlPath);
    const cache2 = tn2.admin.cache();
    const postState = cache2.state();
    const postOffset = cache2.atOffset;
    assert.equal(postOffset, preOffset);
    const preRecs = preState.recipients.map((r) => `${r.group}|${r.leafIndex}`).sort();
    const postRecs = postState.recipients.map((r) => `${r.group}|${r.leafIndex}`).sort();
    assert.deepEqual(postRecs, preRecs);

    await tn2.close();
  } finally {
    cleanup();
  }
});

// 4. Atomic: orphan .tmp ignored
test("AdminStateCache ignores a stranded .tmp file on startup", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    tn.admin.cache().state(); // write the LKV
    await tn.close();

    const lkvPath = join(tmpDir, ".tn/admin", "admin.lkv.json");
    writeFileSync(`${lkvPath}.tmp`, "{not valid json", "utf8");

    const tn2 = await Tn.init(yamlPath);
    const s = tn2.admin.cache().state();
    assert.ok(
      s.recipients.some((r) => r.recipientDid === "did:key:zAlice"),
      "alice must still be present after orphan .tmp",
    );
    await tn2.close();
  } finally {
    cleanup();
  }
});

// 5. Revocation is terminal
test("AdminStateCache flags leaf reuse on add(L) → revoke(L) → add(L)", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    const resA = await tn.admin.addRecipient(
      "default",
      { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" },
    );
    const leaf = resA.leafIndex;
    const cache = tn.admin.cache();
    cache.state(); // prime

    await tn.admin.revokeRecipient("default", { leafIndex: leaf, recipientDid: "did:key:zAlice" });
    const s1 = cache.state();
    const r1 = s1.recipients.find((r) => r.leafIndex === leaf && r.group === "default");
    assert.ok(r1);
    assert.equal(r1!.activeStatus, "revoked");

    // Forge a third add by emitting directly.
    const cfg = (tn.config() as CeremonyConfig);
    tn.emit("info", "tn.recipient.added", {
      ceremony_id: cfg.ceremonyId,
      group: "default",
      leaf_index: leaf,
      recipient_did: "did:key:zForged",
      kit_sha256: "sha256:" + "0".repeat(64),
      cipher: "btn",
    });
    cache.refresh();

    const matching = cache
      .state()
      .recipients.filter((r) => r.leafIndex === leaf && r.group === "default");
    assert.equal(matching.length, 1, "only the original (now-revoked) row remains");
    assert.equal(matching[0]!.activeStatus, "revoked");

    const reuses = cache.headConflicts.filter((c) => c.type === "leaf_reuse_attempt");
    assert.ok(reuses.length >= 1, "leaf_reuse_attempt must surface in headConflicts");
    await tn.close();
  } finally {
    cleanup();
  }
});

// 6. Same-coordinate fork
test("AdminStateCache flags same-coordinate fork on duplicate (did, et, seq)", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    const cache = tn.admin.cache();
    cache.state(); // prime

    // Find an existing add envelope.
    const cfg = (tn.config() as CeremonyConfig);
    const adminLog = resolveAdminLogPath(cfg);
    let target: Record<string, unknown> | null = null;
    const sourcePath = existsSync(adminLog) ? adminLog : cfg.logPath;
    for (const line of readFileSync(sourcePath, "utf8").split(/\r?\n/)) {
      if (!line) continue;
      try {
        const env = JSON.parse(line) as Record<string, unknown>;
        if (env["event_type"] === "tn.recipient.added") {
          target = env;
          break;
        }
      } catch {
        /* skip */
      }
    }
    assert.ok(target, "must have an existing add to fork");

    // Forge a sibling envelope at the same sequence with a different
    // row_hash. We don't need crypto-valid signatures for the cache —
    // it derives from envelopes regardless of signature validity (the
    // cache trusts the local log; signature verification happens at
    // absorb time).
    const forged = {
      did: target!["did"],
      timestamp: new Date().toISOString(),
      event_id: "forged-coord",
      event_type: "tn.recipient.added",
      level: "info",
      sequence: target!["sequence"],
      prev_hash: target!["prev_hash"],
      row_hash: "sha256:" + "9".repeat(64),
      signature: target!["signature"],
      ceremony_id: cfg.ceremonyId,
      group: "default",
      leaf_index: 99,
      recipient_did: "did:key:zEvilTwin",
      kit_sha256: "sha256:" + "9".repeat(64),
      cipher: "btn",
    };
    appendFileSync(sourcePath, JSON.stringify(forged) + "\n");

    cache.refresh();
    assert.equal(cache.diverged(), true);
    const forks = cache.headConflicts.filter((c) => c.type === "same_coordinate_fork");
    assert.ok(forks.length >= 1, "same_coordinate_fork must surface");
    await tn.close();
  } finally {
    cleanup();
  }
});

// 7. Idempotent refresh
test("AdminStateCache.refresh() is idempotent (second call returns 0)", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });

    const cache = tn.admin.cache();
    cache.refresh();
    const second = cache.refresh();
    assert.equal(second, 0, "second consecutive refresh must ingest 0 envelopes");
    await tn.close();
  } finally {
    cleanup();
  }
});

// 8. Lifecycle: same instance returns same singleton
test("AdminStateCache is per-client singleton", async () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const a = tn.admin.cache();
    const b = tn.admin.cache();
    assert.equal(a, b, "same Tn → same AdminStateCache instance");
    await tn.close();
  } finally {
    cleanup();
  }
});

// 9. Direct instantiation with CeremonyConfig
test("AdminStateCache can be instantiated directly with CeremonyConfig", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    // AdminStateCache constructor now takes CeremonyConfig directly.
    const cfg = (tn.config() as CeremonyConfig);
    const cache = new AdminStateCache(cfg);
    const s = cache.state();
    assert.ok(s.recipients.some((r) => r.recipientDid === "did:key:zAlice"));
    await tn.close();
  } finally {
    cleanup();
  }
});
