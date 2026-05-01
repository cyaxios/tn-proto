// Tests for AdminStateCache (LKV).
//
// Mirrors `python/tests/test_admin_state_cache.py`. Covers:
//   1. Cold path: matches client.adminState() shape.
//   2. Hot path: incremental at_offset advance.
//   3. Persistence across new TNClient instances (reads admin.lkv.json).
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
  TNClient,
  resolveAdminLogPath,
} from "../src/index.js";
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
test("AdminStateCache cold path matches client.adminState()", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    client.adminAddRecipient("default", join(kitsDir, "default.btn.mykit"), "did:key:zAlice");
    client.adminAddRecipient("default", join(kitsDir, "default_bob.btn.mykit"), "did:key:zBob");

    const cached = client.adminCache().state();
    const expected = client.adminState();

    const cachedRecs = cached.recipients
      .map((r) => `${r.group}|${r.leafIndex}|${r.activeStatus}`)
      .sort();
    const expectedRecs = expected.recipients
      .map((r) => `${r.group}|${r.leafIndex}|${r.activeStatus}`)
      .sort();
    assert.deepEqual(cachedRecs, expectedRecs);

    client.close();
  } finally {
    cleanup();
  }
});

// 2. Hot path
test("AdminStateCache hot path advances at_offset by 1 per emit", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    client.adminAddRecipient("default", join(kitsDir, "default.btn.mykit"), "did:key:zAlice");

    // Prime
    const cache = client.adminCache();
    const s1 = cache.state();
    const offset1 = cache.atOffset;
    const n1 = s1.recipients.length;

    client.adminAddRecipient("default", join(kitsDir, "default_bob.btn.mykit"), "did:key:zBob");
    const s2 = cache.state();
    const offset2 = cache.atOffset;
    assert.equal(s2.recipients.length, n1 + 1);
    assert.equal(offset2, offset1 + 1);

    client.close();
  } finally {
    cleanup();
  }
});

// 3. Persistence across new TNClient instances
test("AdminStateCache persists to disk and reloads on a new instance", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    client.adminAddRecipient("default", join(kitsDir, "default.btn.mykit"), "did:key:zAlice");
    const cache = client.adminCache();
    const preState = cache.state();
    const preOffset = cache.atOffset;
    assert.ok(preOffset > 0);

    const lkvPath = join(tmpDir, ".tn/admin", "admin.lkv.json");
    assert.ok(existsSync(lkvPath), "cache must write admin.lkv.json");
    client.close();

    // Re-init on a fresh client.
    const client2 = TNClient.init(yamlPath);
    const cache2 = client2.adminCache();
    const postState = cache2.state();
    const postOffset = cache2.atOffset;
    assert.equal(postOffset, preOffset);
    const preRecs = preState.recipients.map((r) => `${r.group}|${r.leafIndex}`).sort();
    const postRecs = postState.recipients.map((r) => `${r.group}|${r.leafIndex}`).sort();
    assert.deepEqual(postRecs, preRecs);

    client2.close();
  } finally {
    cleanup();
  }
});

// 4. Atomic: orphan .tmp ignored
test("AdminStateCache ignores a stranded .tmp file on startup", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    client.adminAddRecipient("default", join(kitsDir, "default.btn.mykit"), "did:key:zAlice");
    client.adminCache().state(); // write the LKV
    client.close();

    const lkvPath = join(tmpDir, ".tn/admin", "admin.lkv.json");
    writeFileSync(`${lkvPath}.tmp`, "{not valid json", "utf8");

    const client2 = TNClient.init(yamlPath);
    const s = client2.adminCache().state();
    assert.ok(
      s.recipients.some((r) => r.recipientDid === "did:key:zAlice"),
      "alice must still be present after orphan .tmp",
    );
    client2.close();
  } finally {
    cleanup();
  }
});

// 5. Revocation is terminal
test("AdminStateCache flags leaf reuse on add(L) → revoke(L) → add(L)", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    const leaf = client.adminAddRecipient(
      "default",
      join(kitsDir, "default.btn.mykit"),
      "did:key:zAlice",
    );
    const cache = client.adminCache();
    cache.state(); // prime

    client.adminRevokeRecipient("default", leaf, "did:key:zAlice");
    const s1 = cache.state();
    const r1 = s1.recipients.find((r) => r.leafIndex === leaf && r.group === "default");
    assert.ok(r1);
    assert.equal(r1!.activeStatus, "revoked");

    // Forge a third add by emitting directly.
    client.emit("info", "tn.recipient.added", {
      ceremony_id: client.runtime.config.ceremonyId,
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
    client.close();
  } finally {
    cleanup();
  }
});

// 6. Same-coordinate fork
test("AdminStateCache flags same-coordinate fork on duplicate (did, et, seq)", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    client.adminAddRecipient("default", join(kitsDir, "default.btn.mykit"), "did:key:zAlice");
    const cache = client.adminCache();
    cache.state(); // prime

    // Find an existing add envelope.
    const adminLog = resolveAdminLogPath(client.runtime.config);
    let target: Record<string, unknown> | null = null;
    const sourcePath = existsSync(adminLog) ? adminLog : client.runtime.config.logPath;
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
      ceremony_id: client.runtime.config.ceremonyId,
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
    client.close();
  } finally {
    cleanup();
  }
});

// 7. Idempotent refresh
test("AdminStateCache.refresh() is idempotent (second call returns 0)", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    client.adminAddRecipient("default", join(kitsDir, "default.btn.mykit"), "did:key:zAlice");

    const cache = client.adminCache();
    cache.refresh();
    const second = cache.refresh();
    assert.equal(second, 0, "second consecutive refresh must ingest 0 envelopes");
    client.close();
  } finally {
    cleanup();
  }
});

// 8. Lifecycle: same instance returns same singleton
test("AdminStateCache is per-client singleton", () => {
  const { yamlPath, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const a = client.adminCache();
    const b = client.adminCache();
    assert.equal(a, b, "same TNClient → same AdminStateCache instance");
    client.close();
  } finally {
    cleanup();
  }
});

// 9. Direct instantiation (multi-cfg shape)
test("AdminStateCache can be instantiated directly per TNClient", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpDir, "kits-"));
    client.adminAddRecipient("default", join(kitsDir, "default.btn.mykit"), "did:key:zAlice");
    const cache = new AdminStateCache(client);
    const s = cache.state();
    assert.ok(s.recipients.some((r) => r.recipientDid === "did:key:zAlice"));
    client.close();
  } finally {
    cleanup();
  }
});
