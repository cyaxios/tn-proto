// Tests for `tnpkg`, `NodeRuntime.exportPkg`, and `NodeRuntime.absorbPkg`.
//
// Mirrors the Python coverage in
// `tn_proto/python/tests/test_export_absorb.py` and the parts of
// `tnpkg.py` that round-trip the manifest.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";

import {
  DeviceKey,
  isManifestSignatureValid,
  iterLogFiles,
  newManifest,
  readTnpkg,
  signManifest,
  signManifestWithBody,
  verifyManifest,
  writeTnpkg,
} from "../src/index.js";
import { Tn } from "../src/tn.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
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

  const yaml = `ceremony:\n  id: tnpkg_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\ndevice:\n  device_identity: ${dk.did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\n- group\n- leaf_index\n- recipient_identity\n- kit_sha256\n- cipher\n- vault_identity\n- project_id\n- linked_at\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - recipient_identity: ${dk.did}\nfields: {}\n`;
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

test("zip round-trip preserves manifest fields and body bytes", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dk = (tn as any)._rt.keystore.device as DeviceKey;
    const cfg = tn.config() as CeremonyConfig;
    const m = newManifest({
      kind: "admin_log_snapshot",
      fromDid: dk.did,
      ceremonyId: cfg.ceremonyId,
      toDid: "did:key:zRecipient",
    });
    m.eventCount = 1;
    m.clock = { [dk.did]: { "tn.recipient.added": 1 } };
    m.headRowHash = "sha256:" + "b".repeat(64);
    const roundBody = {
      "body/admin.ndjson": new TextEncoder().encode("hello world\n"),
    };
    signManifestWithBody(m, roundBody, dk);

    const out = join(tmpDir, "round.tnpkg");
    writeTnpkg(out, m, roundBody);
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
    await tn.close();
  } finally {
    cleanup();
  }
});

test("admin_log_snapshot absorb rejects when body/admin.ndjson is missing", async () => {
  const b = makeCeremony();
  try {
    const consumer = await Tn.init(b.yamlPath);
    const dk = DeviceKey.generate();
    const cfg = consumer.config() as CeremonyConfig;
    const m = newManifest({
      kind: "admin_log_snapshot",
      fromDid: dk.did,
      ceremonyId: cfg.ceremonyId,
      toDid: "did:key:zRecipient",
    });
    // Non-empty clock so a fresh consumer does NOT dominate it — we reach
    // the body-presence check instead of the noop short-circuit.
    m.clock = { [dk.did]: { "tn.recipient.added": 1 } };
    signManifestWithBody(m, {}, dk);

    const out = join(b.tmpDir, "nobody.tnpkg");
    writeTnpkg(out, m, {}); // pack the signed manifest with NO body member
    const r = await consumer.pkg.absorb(out);
    assert.equal(r.kind, "admin_log_snapshot");
    assert.match(r.rejectedReason ?? "", /body missing `body\/admin\.ndjson`/);
    assert.equal(r.acceptedCount, 0);
    assert.equal(r.noop, false);
    await consumer.close();
  } finally {
    b.cleanup();
  }
});

// ---- export / absorb full round-trip ----------------------------------

test("export(admin_log_snapshot) → absorb on a fresh peer applies envelopes", async () => {
  // Producer ceremony.
  const a = makeCeremony();
  // Consumer ceremony.
  const b = makeCeremony();
  try {
    const producer = await Tn.init(a.yamlPath);
    const consumer = await Tn.init(b.yamlPath);

    const kitsDir = mkdtempSync(join(tmpdir(), "tnpkg-kits-"));
    try {
      await producer.admin.addRecipient("default", {
        outKitPath: join(kitsDir, "default.btn.mykit"),
        recipientDid: "did:key:zAlice",
      });
      await producer.admin.addRecipient("default", {
        outKitPath: join(kitsDir, "default_bob.btn.mykit"),
        recipientDid: "did:key:zBob",
      });

      const pkgPath = join(a.tmpDir, "snapshot.tnpkg");
      await producer.pkg.export({ adminLogSnapshot: { outPath: pkgPath } }, pkgPath);
      assert.ok(existsSync(pkgPath));

      // First absorb: applies new envelopes.
      const r1 = await consumer.pkg.absorb(pkgPath);
      assert.equal(r1.kind, "admin_log_snapshot");
      assert.ok(r1.acceptedCount >= 2, `expected ≥2 accepted, got ${r1.acceptedCount}`);
      assert.equal(r1.noop, false);

      // Second absorb: noop (clock dominates).
      const r2 = await consumer.pkg.absorb(pkgPath);
      assert.equal(r2.noop, true);
      assert.equal(r2.acceptedCount, 0);

      await producer.close();
      await consumer.close();
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

// ---- equivocation -----------------------------------------------------

test("absorb surfaces leaf reuse when add(L) → revoke(L) → add(L)", async () => {
  const a = makeCeremony();
  const b = makeCeremony();
  try {
    const producer = await Tn.init(a.yamlPath);
    const consumer = await Tn.init(b.yamlPath);

    const kitsDir = mkdtempSync(join(tmpdir(), "tnpkg-equiv-"));
    try {
      const resA = await producer.admin.addRecipient("default", {
        outKitPath: join(kitsDir, "default.btn.mykit"),
        recipientDid: "did:key:zAlice",
      });
      const leaf = resA.leafIndex;
      await producer.admin.revokeRecipient("default", {
        leafIndex: leaf,
        recipientDid: "did:key:zAlice",
      });

      // Forge a third "added" for the same (group, leaf) by appending
      // directly to the producer's main log. We sign with the producer's
      // device key so the envelope passes signature verification — the
      // reducer is what flags the reuse.
      const cfg = producer.config() as CeremonyConfig;
      // Walk the full PEL tree, not just the main log — wasm-routed
      // tn.* events land in the protocol_events_location, not in
      // logs.path. Python's read_all() does the same merge.
      let lastAddRow: string | null = null;
      for (const path of iterLogFiles(cfg)) {
        if (!existsSync(path)) continue;
        const lines = readFileSync(path, "utf8").split(/\r?\n/);
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
      }
      assert.ok(lastAddRow, "producer log must have an existing add to chain off");

      const publicFields = {
        ceremony_id: cfg.ceremonyId,
        group: "default",
        leaf_index: leaf,
        recipient_identity: "did:key:zForged",
        kit_sha256: "sha256:" + "0".repeat(64),
        cipher: "btn",
      };
      // Easiest: emit a fresh recipient.added directly via the Tn instance
      // and post-edit the leaf_index to collide.
      const receipt = producer.emit("info", "tn.recipient.added", {
        ...publicFields,
        leaf_index: leaf,
      });
      assert.ok(receipt.rowHash, "emit must produce a row_hash");

      // Now export an admin snapshot that contains add+revoke+forged-add
      // and absorb it on the consumer.
      const pkgPath = join(a.tmpDir, "equiv.tnpkg");
      await producer.pkg.export({ adminLogSnapshot: { outPath: pkgPath } }, pkgPath);
      const r = await consumer.pkg.absorb(pkgPath);
      assert.equal(r.kind, "admin_log_snapshot");
      const reuses = r.conflicts.filter((c) => c.type === "leaf_reuse_attempt");
      assert.ok(
        reuses.length >= 1,
        `expected at least one leaf_reuse_attempt, got ${JSON.stringify(r.conflicts)}`,
      );

      await producer.close();
      await consumer.close();
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

// ---- secrets guard ----------------------------------------------------

test("export(full_keystore) without confirmIncludesSecrets throws", async () => {
  const a = makeCeremony();
  try {
    const tn = await Tn.init(a.yamlPath);
    const out = join(a.tmpDir, "full.tnpkg");
    // NodeRuntime.exportPkg enforces the secrets guard directly.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rt = (tn as any)._rt;
    assert.throws(() => rt.exportPkg({ kind: "full_keystore" }, out), /confirmIncludesSecrets/);
    await tn.close();
  } finally {
    a.cleanup();
  }
});

test("export(project_seed) without confirmIncludesSecrets throws", async () => {
  const a = makeCeremony();
  try {
    const tn = await Tn.init(a.yamlPath);
    const out = join(a.tmpDir, "project.tnpkg");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rt = (tn as any)._rt;
    assert.throws(() => rt.exportPkg({ kind: "project_seed" }, out), /confirmIncludesSecrets/);
    await tn.close();
  } finally {
    a.cleanup();
  }
});

test("export(full_keystore, confirmIncludesSecrets=true) bundles private material", async () => {
  const a = makeCeremony();
  try {
    const tn = await Tn.init(a.yamlPath);
    const out = join(a.tmpDir, "full.tnpkg");
    await tn.pkg.export({ selfKit: { outPath: out } }, out);
    const { manifest, body } = readTnpkg(out);
    assert.equal(manifest.kind, "full_keystore");
    assert.ok(body.has("body/local.private"), "private seed must be bundled");
    assert.ok(body.has("body/index_master.key"));
    assert.ok(body.has("body/WARNING_CONTAINS_PRIVATE_KEYS"));
    await tn.close();
  } finally {
    a.cleanup();
  }
});

test("export(project_seed) nests project control state and excludes application logs", async () => {
  const a = makeCeremony();
  try {
    writeFileSync(join(a.tmpDir, ".tn/logs/tn.ndjson"), '{"event_type":"app.secret"}\n');
    writeFileSync(join(a.tmpDir, ".tn/logs/tn.ndjson.1"), '{"event_type":"rotated.secret"}\n');

    const tn = await Tn.init(a.yamlPath);
    const out = join(a.tmpDir, "project.tnpkg");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (tn as any)._rt.exportPkg({ kind: "project_seed", confirmIncludesSecrets: true }, out);

    const { manifest, body } = readTnpkg(out);
    assert.equal(manifest.kind, "project_seed");
    assert.equal(manifest.toDid, manifest.fromDid);
    assert.equal(manifest.scope, "project");
    assert.ok(isManifestSignatureValid(manifest));
    assert.ok(body.has("body/tn.yaml"));
    assert.ok(body.has("body/keys/local.private"));
    assert.ok(body.has("body/keys/local.public"));
    assert.ok(body.has("body/keys/default.btn.state"));
    assert.ok(body.has("body/keys/default.btn.mykit"));
    assert.ok(body.has("body/WARNING_CONTAINS_PRIVATE_KEYS"));
    for (const name of body.keys()) {
      assert.ok(!name.includes("/logs/"), `project_seed must not include app log member ${name}`);
      assert.ok(!name.endsWith(".ndjson"), `project_seed must not include app log member ${name}`);
    }
    await tn.close();
  } finally {
    a.cleanup();
  }
});

test("absorb(project_seed) adopts empty vault project id without overwriting", async () => {
  const a = makeCeremony();
  try {
    const emptyYaml = readFileSync(a.yamlPath, "utf8").replace(
      "  mode: local\n  cipher: btn\n",
      [
        "  mode: linked",
        "  cipher: btn",
        "  linked_vault: https://vault.example",
        "  linked_project_id: ''",
        "vault:",
        "  enabled: true",
        "  url: https://vault.example",
        "  linked_project_id: ''",
        "  autosync: true",
        "  sync_interval_seconds: 600",
        "",
      ].join("\n"),
    );
    writeFileSync(a.yamlPath, emptyYaml, "utf8");

    const tn = await Tn.init(a.yamlPath);
    const basePkg = join(a.tmpDir, "project-empty.tnpkg");
    const linkedPkg = join(a.tmpDir, "project-linked.tnpkg");
    const otherPkg = join(a.tmpDir, "project-other.tnpkg");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (tn as any)._rt.exportPkg({ kind: "project_seed", confirmIncludesSecrets: true }, basePkg);

    const { manifest, body } = readTnpkg(basePkg);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const signingKey = (tn as any)._rt.keystore.device as DeviceKey;
    const linkedBody = new Map(body);
    linkedBody.set(
      "body/tn.yaml",
      new TextEncoder().encode(
        emptyYaml.replaceAll("linked_project_id: ''", "linked_project_id: proj_remote"),
      ),
    );
    const linkedContents = Object.fromEntries(linkedBody);
    signManifestWithBody(manifest, linkedContents, signingKey);
    writeTnpkg(linkedPkg, manifest, linkedContents);
    const otherBody = new Map(body);
    otherBody.set(
      "body/tn.yaml",
      new TextEncoder().encode(
        emptyYaml.replaceAll("linked_project_id: ''", "linked_project_id: proj_other"),
      ),
    );
    const otherContents = Object.fromEntries(otherBody);
    signManifestWithBody(manifest, otherContents, signingKey);
    writeTnpkg(otherPkg, manifest, otherContents);

    writeFileSync(join(a.tmpDir, ".tn/logs/tn.ndjson"), '{"event_type":"app.event"}\n');

    const adopted = await tn.pkg.absorb(linkedPkg);
    assert.equal(adopted.rejectedReason, undefined);
    let doc = parseYaml(readFileSync(a.yamlPath, "utf8")) as {
      ceremony: Record<string, unknown>;
      vault: Record<string, unknown>;
    };
    assert.equal(doc.vault.linked_project_id, "proj_remote");
    assert.equal(doc.ceremony.linked_project_id, "proj_remote");

    const ignored = await tn.pkg.absorb(otherPkg);
    assert.equal(ignored.rejectedReason, undefined);
    doc = parseYaml(readFileSync(a.yamlPath, "utf8")) as {
      ceremony: Record<string, unknown>;
      vault: Record<string, unknown>;
    };
    assert.equal(doc.vault.linked_project_id, "proj_remote");
    assert.equal(doc.ceremony.linked_project_id, "proj_remote");
    await tn.close();
  } finally {
    a.cleanup();
  }
});

test("export(kit_bundle) round-trips reader kits without private material", async () => {
  const a = makeCeremony();
  try {
    const tn = await Tn.init(a.yamlPath);
    const out = join(a.tmpDir, "kits.tnpkg");
    // kit_bundle without a toDid — call NodeRuntime.exportPkg directly.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (tn as any)._rt.exportPkg({ kind: "kit_bundle" }, out);
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
    await tn.close();
  } finally {
    a.cleanup();
  }
});

test("absorb rejects a counterpart kit_bundle carrying JWE private material", async () => {
  const target = makeCeremony();
  try {
    const reader = await Tn.init(target.yamlPath);
    const publisher = DeviceKey.generate();
    const body = { "body/default.jwe.mykey": new Uint8Array(32).fill(0x5a) };
    const manifest = newManifest({
      kind: "kit_bundle",
      fromDid: publisher.did,
      toDid: reader.did,
      ceremonyId: "malicious-kit",
      scope: "kit_bundle",
    });
    signManifestWithBody(manifest, body, publisher);
    const bundle = join(target.tmpDir, "malicious-kit.tnpkg");
    writeTnpkg(bundle, manifest, body);

    const receipt = await reader.pkg.absorb(bundle);
    assert.match(receipt.rejectedReason ?? "", /not permitted in a reader kit/i);
    const config = reader.config() as CeremonyConfig;
    assert.equal(existsSync(join(config.keystorePath, "default.jwe.mykey")), false);
    await reader.close();
  } finally {
    target.cleanup();
  }
});

test("absorb rejects a full_keystore self-addressed to a different DID", async () => {
  const target = makeCeremony();
  try {
    const reader = await Tn.init(target.yamlPath);
    const config = reader.config() as CeremonyConfig;
    const localPrivate = join(config.keystorePath, "local.private");
    const before = readFileSync(localPrivate);
    const foreign = DeviceKey.generate();
    const body = {
      "body/local.private": foreign.seed,
      "body/local.public": new TextEncoder().encode(foreign.did),
    };
    const manifest = newManifest({
      kind: "full_keystore",
      fromDid: foreign.did,
      toDid: foreign.did,
      ceremonyId: "foreign-backup",
      scope: "full",
    });
    signManifestWithBody(manifest, body, foreign);
    const bundle = join(target.tmpDir, "foreign-full.tnpkg");
    writeTnpkg(bundle, manifest, body);

    const receipt = await reader.pkg.absorb(bundle);
    assert.match(receipt.rejectedReason ?? "", /full_keystore.*this device/i);
    assert.deepEqual(readFileSync(localPrivate), before);
    await reader.close();
  } finally {
    target.cleanup();
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

test("absorb rejects a tampered manifest", async () => {
  const a = makeCeremony();
  const b = makeCeremony();
  try {
    const producer = await Tn.init(a.yamlPath);
    const consumer = await Tn.init(b.yamlPath);
    const out = join(a.tmpDir, "snapshot.tnpkg");
    await producer.pkg.export({ adminLogSnapshot: { outPath: out } }, out);

    // Open the zip, mutate the manifest event_count, repack with the
    // same manifest signature → signature should fail.
    const { manifest, body } = readTnpkg(out);
    manifest.eventCount = 9999; // tamper without re-signing
    const tampered = join(a.tmpDir, "tampered.tnpkg");
    const bodyDict: Record<string, Uint8Array> = {};
    for (const [k, v] of body) bodyDict[k] = v;
    writeTnpkg(tampered, manifest, bodyDict);

    const r = await consumer.pkg.absorb(tampered);
    assert.match(r.rejectedReason ?? "", /signature does not verify/);
    await producer.close();
    await consumer.close();
  } finally {
    a.cleanup();
    b.cleanup();
  }
});
