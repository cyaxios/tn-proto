// Characterization tests for AdminStateCache._loadFromDisk (the CC-58 LKV
// deserializer in src/admin/cache.ts). Written BEFORE decomposing it into
// per-section parsers so the extracted helpers must preserve every branch:
//   - early returns: missing file, corrupt JSON, version mismatch, ceremony
//     mismatch
//   - happy-path parsing of state / clock / head_conflicts / at_offset /
//     head_row_hash
//   - malformed-entry tolerance (non-numeric clock seq skipped, partial state)
//   - round-trip of the three private maps (_revoked_leaves, _rotations_seen,
//     _coord_to_row_hash) through save+load.
//
// Drives the public surface only. With no admin/main log on disk the cache's
// refresh-if-advanced check is a no-op (0 envelopes <= loaded at_offset), so
// state()/clock()/headConflicts return exactly what _loadFromDisk produced.
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { AdminStateCache, lkvPathFor } from "../src/admin/cache.js";
import { loadConfig } from "../src/runtime/config.js";

const CER = "cache_load_test";

function setup(): { cfg: ReturnType<typeof loadConfig>; lkvPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-cacheload-"));
  const yaml =
    `ceremony:\n  id: ${CER}\n  mode: local\n  cipher: btn\n` +
    "device:\n  device_identity: did:key:zDEV\n" +
    "groups:\n  default:\n    policy: private\n    cipher: btn\n";
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");
  const cfg = loadConfig(yamlPath);
  const lkvPath = lkvPathFor(cfg);
  return { cfg, lkvPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function writeLkv(lkvPath: string, doc: unknown): void {
  mkdirSync(dirname(lkvPath), { recursive: true });
  writeFileSync(lkvPath, JSON.stringify(doc, null, 2), "utf8");
}

// A fully-populated, valid LKV doc for the current ceremony.
function fullDoc(): Record<string, unknown> {
  return {
    version: 1,
    ceremony_id: CER,
    clock: { "did:key:zDEV": { "tn.recipient.added": 4, "tn.group.added": 1 } },
    head_row_hash: "rh-head",
    at_offset: 5,
    state: {
      ceremony: { ceremonyId: CER, cipher: "btn", deviceDid: "did:key:zDEV", createdAt: "t0" },
      groups: [{ group: "default", cipher: "btn", publisherDid: "did:key:zDEV", addedAt: "t1" }],
      recipients: [
        {
          group: "default",
          leafIndex: 0,
          recipientDid: "did:key:zAlice",
          kitSha256: "kitA",
          mintedAt: "t2",
          activeStatus: "active",
          revokedAt: null,
          retiredAt: null,
        },
      ],
      rotations: [
        { group: "default", cipher: "btn", generation: 1, previousKitSha256: "kitA", rotatedAt: "t3" },
      ],
      coupons: [{ group: "default", slot: 1, toDid: "did:key:zB", issuedTo: "bob", issuedAt: "t4" }],
      enrolments: [
        { group: "default", peerDid: "did:key:zP", packageSha256: "pkg", status: "absorbed", compiledAt: null, absorbedAt: "t5" },
      ],
      vaultLinks: [{ vaultDid: "did:key:zV", projectId: "p1", linkedAt: "t6", unlinkedAt: null }],
    },
    head_conflicts: [
      { type: "rotation_conflict", group: "default", generation: 1, previousKitSha256A: "kitA", previousKitSha256B: "kitB" },
    ],
    _row_hashes: ["rh1", "rh2", "rh3", "rh4", "rh5"],
    _revoked_leaves: [{ group: "default", leaf_index: 7, row_hash: "revrh" }],
    _rotations_seen: [{ group: "default", generation: 1, previous_kit_sha256: "kitA" }],
    _coord_to_row_hash: [
      { did: "did:key:zDEV", event_type: "tn.recipient.added", sequence: 3, row_hash: "rh3" },
    ],
  };
}

test("missing LKV file leaves the cache empty", () => {
  const { cfg, cleanup } = setup();
  try {
    const cache = new AdminStateCache(cfg);
    assert.equal(cache.state().recipients.length, 0);
    assert.equal(cache.atOffset, 0);
    assert.equal(cache.headConflicts.length, 0);
  } finally {
    cleanup();
  }
});

test("corrupt JSON is swallowed (empty cache, no throw)", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    mkdirSync(dirname(lkvPath), { recursive: true });
    writeFileSync(lkvPath, "{ this is not json", "utf8");
    const cache = new AdminStateCache(cfg);
    assert.equal(cache.state().recipients.length, 0);
    assert.equal(cache.atOffset, 0);
  } finally {
    cleanup();
  }
});

test("version mismatch is ignored", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    writeLkv(lkvPath, { ...fullDoc(), version: 999 });
    const cache = new AdminStateCache(cfg);
    assert.equal(cache.state().recipients.length, 0);
    assert.equal(cache.atOffset, 0);
  } finally {
    cleanup();
  }
});

test("ceremony_id mismatch is ignored", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    writeLkv(lkvPath, { ...fullDoc(), ceremony_id: "some_other_ceremony" });
    const cache = new AdminStateCache(cfg);
    assert.equal(cache.state().recipients.length, 0);
    assert.equal(cache.atOffset, 0);
  } finally {
    cleanup();
  }
});

test("happy path loads every state sub-section", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    writeLkv(lkvPath, fullDoc());
    const cache = new AdminStateCache(cfg);
    const s = cache.state();
    assert.equal(s.ceremony?.ceremonyId, CER);
    assert.equal(s.groups.length, 1);
    assert.equal(s.recipients.length, 1);
    assert.equal(s.recipients[0]!.recipientDid, "did:key:zAlice");
    assert.equal(s.rotations.length, 1);
    assert.equal(s.coupons.length, 1);
    assert.equal(s.enrolments.length, 1);
    assert.equal(s.vaultLinks.length, 1);
    assert.equal(cache.atOffset, 5);
    assert.equal(cache.headRowHash, "rh-head");
    assert.equal(cache.headConflicts.length, 1);
    assert.equal(cache.headConflicts[0]!.type, "rotation_conflict");
  } finally {
    cleanup();
  }
});

// recipients() row shape parity with Python `tn.admin.recipients()`:
//   - the recipient field is keyed `recipient_identity` (NOT `recipientDid`)
//   - revoked_at carries `revoked_at` OR `retired_at` so retired recipients
//     keep a timestamp (Python maps both into one field).
test("recipients() keys the recipient field as recipient_identity", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    writeLkv(lkvPath, fullDoc());
    const cache = new AdminStateCache(cfg);
    const rows = cache.recipients("default", { includeRevoked: true });
    assert.equal(rows.length, 1);
    const row = rows[0]!;
    assert.equal(row.recipient_identity, "did:key:zAlice");
    // The legacy DID-named key must be gone.
    assert.equal(
      (row as Record<string, unknown>)["recipientDid"],
      undefined,
      "recipients() must not expose the legacy recipientDid key",
    );
  } finally {
    cleanup();
  }
});

test("recipients() maps retiredAt into revokedAt when revokedAt is null", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    const doc = fullDoc();
    // A retired (not revoked) recipient: revokedAt null, retiredAt stamped.
    (doc.state as Record<string, unknown>).recipients = [
      {
        group: "default",
        leafIndex: 0,
        recipientDid: "did:key:zRetiree",
        kitSha256: "kitR",
        mintedAt: "t2",
        activeStatus: "retired",
        revokedAt: null,
        retiredAt: "2026-01-02T03:04:05Z",
      },
    ];
    writeLkv(lkvPath, doc);
    const cache = new AdminStateCache(cfg);
    const rows = cache.recipients("default", { includeRevoked: true });
    assert.equal(rows.length, 1);
    const row = rows[0]!;
    assert.equal(row.recipient_identity, "did:key:zRetiree");
    assert.equal(row.revoked, true, "retired recipients count as revoked in the row contract");
    assert.equal(
      row.revokedAt,
      "2026-01-02T03:04:05Z",
      "retiredAt must surface as revokedAt so the timestamp is not dropped",
    );
  } finally {
    cleanup();
  }
});

test("recipients() prefers revokedAt over retiredAt when both are present", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    const doc = fullDoc();
    (doc.state as Record<string, unknown>).recipients = [
      {
        group: "default",
        leafIndex: 0,
        recipientDid: "did:key:zBoth",
        kitSha256: "kitB",
        mintedAt: "t2",
        activeStatus: "revoked",
        revokedAt: "2026-02-02T02:02:02Z",
        retiredAt: "2026-01-01T01:01:01Z",
      },
    ];
    writeLkv(lkvPath, doc);
    const cache = new AdminStateCache(cfg);
    const rows = cache.recipients("default", { includeRevoked: true });
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.revokedAt, "2026-02-02T02:02:02Z");
  } finally {
    cleanup();
  }
});

test("clock is reconstructed as did -> event_type -> seq", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    writeLkv(lkvPath, fullDoc());
    const cache = new AdminStateCache(cfg);
    const clk = cache.clock();
    assert.equal(clk["did:key:zDEV"]!["tn.recipient.added"], 4);
    assert.equal(clk["did:key:zDEV"]!["tn.group.added"], 1);
  } finally {
    cleanup();
  }
});

test("non-numeric clock entries are skipped, numeric kept", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    const doc = fullDoc();
    doc.clock = { "did:key:zDEV": { "tn.recipient.added": "not-a-number", "tn.group.added": 2 } };
    writeLkv(lkvPath, doc);
    const cache = new AdminStateCache(cfg);
    const clk = cache.clock();
    assert.equal(clk["did:key:zDEV"]?.["tn.recipient.added"], undefined);
    assert.equal(clk["did:key:zDEV"]!["tn.group.added"], 2);
  } finally {
    cleanup();
  }
});

test("a partial state object (only recipients) is tolerated", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    const doc = fullDoc();
    doc.state = {
      recipients: [
        {
          group: "default",
          leafIndex: 0,
          recipientDid: "did:key:zSolo",
          kitSha256: "k",
          mintedAt: null,
          activeStatus: "active",
          revokedAt: null,
          retiredAt: null,
        },
      ],
    };
    writeLkv(lkvPath, doc);
    const cache = new AdminStateCache(cfg);
    const s = cache.state();
    assert.equal(s.recipients.length, 1);
    assert.equal(s.groups.length, 0);
    assert.equal(s.ceremony, null);
  } finally {
    cleanup();
  }
});

test("private maps (_revoked_leaves/_rotations_seen/_coord_to_row_hash) survive save+load", () => {
  const { cfg, lkvPath, cleanup } = setup();
  try {
    writeLkv(lkvPath, fullDoc());
    const cache = new AdminStateCache(cfg);
    // No log on disk -> refresh ingests 0 but re-serializes the loaded maps.
    cache.refresh();
    const reloaded = JSON.parse(readFileSync(lkvPath, "utf8")) as Record<string, unknown>;
    assert.deepEqual(reloaded["_revoked_leaves"], [
      { group: "default", leaf_index: 7, row_hash: "revrh" },
    ]);
    assert.deepEqual(reloaded["_rotations_seen"], [
      { group: "default", generation: 1, previous_kit_sha256: "kitA" },
    ]);
    assert.deepEqual(reloaded["_coord_to_row_hash"], [
      { did: "did:key:zDEV", event_type: "tn.recipient.added", sequence: 3, row_hash: "rh3" },
    ]);
  } finally {
    cleanup();
  }
});
