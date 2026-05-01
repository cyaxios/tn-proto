// Tests for `tnpkg`, `TNClient.export`, and `TNClient.absorb`.
//
// Mirrors the Python coverage in
// `tn-protocol/python/tests/test_export_absorb.py` and the parts of
// `tnpkg.py` that round-trip the manifest.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DeviceKey,
  TNClient,
  isManifestSignatureValid,
  newManifest,
  readTnpkg,
  signManifest,
  verifyManifest,
  writeTnpkg,
} from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";

function makeCeremony(): { yamlPath: string; tmpDir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-tnpkg-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 13 + 17) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 23) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  const yaml = `ceremony:\n  id: tnpkg_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\nme:\n  did: ${dk.did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\n- group\n- leaf_index\n- recipient_did\n- kit_sha256\n- cipher\n- vault_did\n- project_id\n- linked_at\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - did: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    tmpDir: dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

// ---- manifest ---------------------------------------------------------

test("manifest sign + verify round-trip", () => {
  const dk = DeviceKey.generate();
  const m = newManifest({
    kind: "admin_log_snapshot",
    fromDid: dk.did,
    ceremonyId: "test-ceremony",
  });
  m.eventCount = 3;
  m.headRowHash = "sha256:" + "a".repeat(64);
  m.clock = { [dk.did]: { "tn.recipient.added": 2 } };
  signManifest(m, dk);
  assert.ok(m.manifestSignatureB64, "signature must be populated");
  assert.equal(isManifestSignatureValid(m), true);
});

test("tampered manifest fails signature verification", () => {
  const dk = DeviceKey.generate();
  const m = newManifest({
    kind: "admin_log_snapshot",
    fromDid: dk.did,
    ceremonyId: "test-ceremony",
  });
  signManifest(m, dk);
  // Tamper.
  m.eventCount = 999;
  assert.equal(isManifestSignatureValid(m), false);
  assert.throws(() => verifyManifest(m), /signature does not verify/);
});

test("zip round-trip preserves manifest fields and body bytes", () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const client = TNClient.init(yamlPath);
    const dk = client.runtime.keystore.device;
    const m = newManifest({
      kind: "admin_log_snapshot",
      fromDid: dk.did,
      ceremonyId: client.runtime.config.ceremonyId,
      toDid: "did:key:zRecipient",
    });
    m.eventCount = 1;
    m.clock = { [dk.did]: { "tn.recipient.added": 1 } };
    m.headRowHash = "sha256:" + "b".repeat(64);
    signManifest(m, dk);

    const out = join(tmpDir, "round.tnpkg");
    writeTnpkg(out, m, {
      "body/admin.ndjson": new TextEncoder().encode("hello world\n"),
    });
    assert.ok(existsSync(out));

    const { manifest, body } = readTnpkg(out);
    assert.equal(manifest.kind, "admin_log_snapshot");
    assert.equal(manifest.toDid, "did:key:zRecipient");
    assert.equal(manifest.eventCount, 1);
    assert.equal(manifest.headRowHash, "sha256:" + "b".repeat(64));
    assert.equal(manifest.fromDid, dk.did);
    assert.equal(manifest.clock[dk.did]!["tn.recipient.added"], 1);
    assert.equal(isManifestSignatureValid(manifest), true);

    const ndjson = body.get("body/admin.ndjson");
    assert.ok(ndjson, "body must contain admin.ndjson");
    assert.equal(new TextDecoder("utf-8").decode(ndjson!), "hello world\n");
    client.close();
  } finally {
    cleanup();
  }
});

// ---- export / absorb full round-trip ----------------------------------

test("export(admin_log_snapshot) → absorb on a fresh peer applies envelopes", () => {
  // Producer ceremony.
  const a = makeCeremony();
  // Consumer ceremony.
  const b = makeCeremony();
  try {
    const producer = TNClient.init(a.yamlPath);
    const consumer = TNClient.init(b.yamlPath);

    const kitsDir = mkdtempSync(join(tmpdir(), "tnpkg-kits-"));
    try {
      producer.adminAddRecipient(
        "default",
        join(kitsDir, "default.btn.mykit"),
        "did:key:zAlice",
      );
      producer.adminAddRecipient(
        "default",
        join(kitsDir, "default_bob.btn.mykit"),
        "did:key:zBob",
      );

      const pkgPath = join(a.tmpDir, "snapshot.tnpkg");
      producer.export({ kind: "admin_log_snapshot" }, pkgPath);
      assert.ok(existsSync(pkgPath));

      // First absorb: applies new envelopes.
      const r1 = consumer.absorb(pkgPath);
      assert.equal(r1.kind, "admin_log_snapshot");
      assert.ok(r1.acceptedCount >= 2, `expected ≥2 accepted, got ${r1.acceptedCount}`);
      assert.equal(r1.noop, false);

      // Second absorb: noop (clock dominates).
      const r2 = consumer.absorb(pkgPath);
      assert.equal(r2.noop, true);
      assert.equal(r2.acceptedCount, 0);

      producer.close();
      consumer.close();
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

// ---- equivocation -----------------------------------------------------

test("absorb surfaces leaf reuse when add(L) → revoke(L) → add(L)", () => {
  const a = makeCeremony();
  const b = makeCeremony();
  try {
    const producer = TNClient.init(a.yamlPath);
    const consumer = TNClient.init(b.yamlPath);

    const kitsDir = mkdtempSync(join(tmpdir(), "tnpkg-equiv-"));
    try {
      const leaf = producer.adminAddRecipient(
        "default",
        join(kitsDir, "default.btn.mykit"),
        "did:key:zAlice",
      );
      producer.adminRevokeRecipient("default", leaf, "did:key:zAlice");

      // Forge a third "added" for the same (group, leaf) by appending
      // directly to the producer's main log. We sign with the producer's
      // device key so the envelope passes signature verification — the
      // reducer is what flags the reuse.
      const mainLog = producer.runtime.config.logPath;
      const lines = readFileSync(mainLog, "utf8").split(/\r?\n/);
      let lastAddRow: string | null = null;
      for (const ln of lines) {
        if (!ln) continue;
        try {
          const env = JSON.parse(ln) as Record<string, unknown>;
          if (env["event_type"] === "tn.recipient.added") {
            lastAddRow = String(env["row_hash"]);
          }
        } catch {
          /* skip */
        }
      }
      assert.ok(lastAddRow, "producer log must have an existing add to chain off");

      const dk = producer.runtime.keystore.device;
      const ts = new Date().toISOString();
      const evtId = "forged-" + ts.replace(/[:.]/g, "");
      const publicFields = {
        ceremony_id: producer.runtime.config.ceremonyId,
        group: "default",
        leaf_index: leaf,
        recipient_did: "did:key:zForged",
        kit_sha256: "sha256:" + "0".repeat(64),
        cipher: "btn",
      };
      // We don't need to recompute row_hash here — the absorb side
      // will verify the signature; for the leaf-reuse code path, the
      // envelope just needs to have a row_hash + signature that pass.
      // Use the existing forge approach: emit via the producer client.
      // Easiest: emit a fresh recipient.added directly via the runtime
      // and post-edit the leaf_index to collide.
      const receipt = producer.emit("info", "tn.recipient.added", {
        ...publicFields,
        leaf_index: leaf,
      });
      assert.ok(receipt.rowHash, "emit must produce a row_hash");
      void dk;
      void evtId;

      // Now export an admin snapshot that contains add+revoke+forged-add
      // and absorb it on the consumer.
      const pkgPath = join(a.tmpDir, "equiv.tnpkg");
      producer.export({ kind: "admin_log_snapshot" }, pkgPath);
      const r = consumer.absorb(pkgPath);
      assert.equal(r.kind, "admin_log_snapshot");
      const reuses = r.conflicts.filter((c) => c.type === "leaf_reuse_attempt");
      assert.ok(
        reuses.length >= 1,
        `expected at least one leaf_reuse_attempt, got ${JSON.stringify(r.conflicts)}`,
      );

      producer.close();
      consumer.close();
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

// ---- secrets guard ----------------------------------------------------

test("export(full_keystore) without confirmIncludesSecrets throws", () => {
  const a = makeCeremony();
  try {
    const client = TNClient.init(a.yamlPath);
    const out = join(a.tmpDir, "full.tnpkg");
    assert.throws(
      () => client.export({ kind: "full_keystore" }, out),
      /confirmIncludesSecrets/,
    );
    client.close();
  } finally {
    a.cleanup();
  }
});

test("export(full_keystore, confirmIncludesSecrets=true) bundles private material", () => {
  const a = makeCeremony();
  try {
    const client = TNClient.init(a.yamlPath);
    const out = join(a.tmpDir, "full.tnpkg");
    client.export({ kind: "full_keystore", confirmIncludesSecrets: true }, out);
    const { manifest, body } = readTnpkg(out);
    assert.equal(manifest.kind, "full_keystore");
    assert.ok(body.has("body/local.private"), "private seed must be bundled");
    assert.ok(body.has("body/index_master.key"));
    assert.ok(body.has("body/WARNING_CONTAINS_PRIVATE_KEYS"));
    client.close();
  } finally {
    a.cleanup();
  }
});

test("export(kit_bundle) round-trips reader kits without private material", () => {
  const a = makeCeremony();
  try {
    const client = TNClient.init(a.yamlPath);
    const out = join(a.tmpDir, "kits.tnpkg");
    client.export({ kind: "kit_bundle" }, out);
    const { manifest, body } = readTnpkg(out);
    assert.equal(manifest.kind, "kit_bundle");
    // Find the .mykit entry.
    let kitFound = false;
    for (const name of body.keys()) {
      if (name.endsWith(".btn.mykit")) kitFound = true;
      if (name === "body/local.private") {
        throw new Error("kit_bundle must NOT contain local.private");
      }
    }
    assert.ok(kitFound, "kit_bundle must include at least one .btn.mykit");
    client.close();
  } finally {
    a.cleanup();
  }
});

// ---- absorb error paths -----------------------------------------------

// ---- cross-language byte-compare --------------------------------------

test("Python-produced .tnpkg parses + signature verifies in TS", () => {
  const fixturePath = join(
    new URL(".", import.meta.url).pathname.replace(/^\//, ""),
    "fixtures",
    "python_admin_snapshot.tnpkg",
  );
  if (!existsSync(fixturePath)) {
    // Fixture is generated by `build_python_fixture.py`; if it's
    // missing, skip rather than fail (CI without Python installed
    // shouldn't break TS-only checks).
    return;
  }
  const { manifest, body } = readTnpkg(fixturePath);
  assert.equal(manifest.kind, "admin_log_snapshot");
  assert.equal(isManifestSignatureValid(manifest), true, "Python signature must verify in TS");
  assert.ok(body.has("body/admin.ndjson"), "body/admin.ndjson must be present");
  // Manifest carries clock + at least one recipient_added envelope.
  assert.ok(manifest.eventCount >= 1, "Python fixture should contain ≥1 admin envelope");
});

test("absorb rejects a tampered manifest", () => {
  const a = makeCeremony();
  const b = makeCeremony();
  try {
    const producer = TNClient.init(a.yamlPath);
    const consumer = TNClient.init(b.yamlPath);
    const out = join(a.tmpDir, "snapshot.tnpkg");
    producer.export({ kind: "admin_log_snapshot" }, out);

    // Open the zip, mutate the manifest event_count, repack with the
    // same manifest signature → signature should fail.
    const { manifest, body } = readTnpkg(out);
    manifest.eventCount = 9999; // tamper without re-signing
    const tampered = join(a.tmpDir, "tampered.tnpkg");
    const bodyDict: Record<string, Uint8Array> = {};
    for (const [k, v] of body) bodyDict[k] = v;
    writeTnpkg(tampered, manifest, bodyDict);

    const r = consumer.absorb(tampered);
    assert.match(r.rejectedReason ?? "", /signature does not verify/);
    producer.close();
    consumer.close();
  } finally {
    a.cleanup();
    b.cleanup();
  }
});
