// Tests for the TS `fs.drop` handler.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DeviceKey,
  FsDropHandler,
  makeTNClientSnapshotBuilder,
  formatFilename,
  readTnpkg,
} from "../src/index.js";
import { Tn } from "../src/tn.js";

/** Thin adapter: wraps a Tn instance as the interface makeTNClientSnapshotBuilder expects. */
function tnAsExporter(tn: Tn): { export: (opts: { kind: string; scope?: string }, outPath: string) => string } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rt = (tn as any)._rt;
  return { export: (opts, outPath) => rt.exportPkg(opts, outPath) };
}
import { BtnPublisher } from "../src/raw.js";

function makeCeremony(): { yamlPath: string; tmpDir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-fsdrop-"));
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

  const yaml =
    `ceremony:\n  id: fsdrop_test\n  mode: local\n  cipher: btn\n` +
    `logs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\n` +
    `me:\n  did: ${dk.did}\n` +
    `public_fields:\n- timestamp\n- event_id\n- event_type\n- level\n` +
    `- group\n- leaf_index\n- recipient_did\n- kit_sha256\n- cipher\n` +
    `default_policy: private\n` +
    `groups:\n  default:\n    policy: private\n    cipher: btn\n` +
    `    recipients:\n    - did: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");
  return { yamlPath, tmpDir: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("fs.drop writes a signed snapshot when an admin event is emitted", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    // Produce an admin event so the snapshot has content.
    const kitsDir = mkdtempSync(join(tmpdir(), "fsdrop-kits-"));
    try {
      await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
    const outDir = join(tmpDir, "outbox");
    const h = new FsDropHandler("fd", {
      outDir,
      builder: makeTNClientSnapshotBuilder(tnAsExporter(tn)),
    });
    h.emit({ event_type: "tn.recipient.added" }, "");
    const files = readdirSync(outDir).filter((n) => n.endsWith(".tnpkg"));
    assert.equal(files.length, 1, `expected 1 file, got ${files.length}`);
    const bytes = readFileSync(join(outDir, files[0]!));
    const { manifest } = readTnpkg(bytes);
    assert.equal(manifest.kind, "admin_log_snapshot");
    assert.ok(manifest.headRowHash, "head_row_hash should be set");
    await tn.close();
  } finally {
    cleanup();
  }
});

test("fs.drop is idempotent when head_row_hash hasn't advanced", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const kitsDir = mkdtempSync(join(tmpdir(), "fsdrop-kits-"));
    try {
      await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zA" });
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
    const outDir = join(tmpDir, "outbox");
    const h = new FsDropHandler("fd", {
      outDir,
      builder: makeTNClientSnapshotBuilder(tnAsExporter(tn)),
    });
    h.emit({ event_type: "tn.recipient.added" }, "");
    h.emit({ event_type: "tn.recipient.added" }, "");
    const files = readdirSync(outDir).filter((n) => n.endsWith(".tnpkg"));
    assert.equal(files.length, 1, "second drop with unchanged head should noop");
    await tn.close();
  } finally {
    cleanup();
  }
});

test("fs.drop allowlist filters event types", async () => {
  const { yamlPath, tmpDir, cleanup } = makeCeremony();
  try {
    const tn = await Tn.init(yamlPath);
    const outDir = join(tmpDir, "outbox");
    const h = new FsDropHandler("fd", {
      outDir,
      builder: makeTNClientSnapshotBuilder(tnAsExporter(tn)),
      on: ["tn.recipient.added"],
    });
    assert.equal(h.accepts({ event_type: "tn.recipient.added" }), true);
    assert.equal(h.accepts({ event_type: "tn.recipient.revoked" }), false);
    assert.equal(h.accepts({ event_type: "user.signup" }), false);
    if (existsSync(outDir)) {
      const stale = readdirSync(outDir);
      assert.equal(stale.length, 0, "no files should have been written");
    }
    await tn.close();
  } finally {
    cleanup();
  }
});

test("fs.drop filename template substitutes placeholders", () => {
  const name = formatFilename(
    "snap_{ceremony_id}_{head_row_hash:short}.tnpkg",
    "cer1",
    "sha256:deadbeefcafebabe1234",
    "did:key:zABC",
  );
  assert.match(name, /^snap_cer1_deadbeefcafe\.tnpkg$/);
});
