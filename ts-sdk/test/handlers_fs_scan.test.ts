// Tests for the TS `fs.scan` handler.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DeviceKey,
  FsScanHandler,
  makeTNClientAbsorber,
} from "../src/index.js";
import { Tn } from "../src/tn.js";

/** Thin adapter: wraps a Tn instance as the interface makeTNClientAbsorber expects. */
function tnAsAbsorber(tn: Tn): { absorb: (source: string) => { rejectedReason?: string | null } } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rt = (tn as any)._rt;
  return { absorb: (source: string) => rt.absorbPkg(source) };
}
import { BtnPublisher } from "../src/raw.js";

function makeCeremony(prefix: string): { yamlPath: string; tmpDir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  // Use prefix bits to differentiate sender vs receiver seeds so their
  // ceremonies are independent.
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 13 + prefix.length * 31) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 7 + prefix.length) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + prefix.length * 11) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  const yaml =
    `ceremony:\n  id: ${prefix}\n  mode: local\n  cipher: btn\n` +
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

test("fs.scan absorbs a dropped snapshot and archives it", async () => {
  const sender = makeCeremony("tn-fsscan-tx-");
  const receiver = makeCeremony("tn-fsscan-rx-");
  const inbox = mkdtempSync(join(tmpdir(), "tn-fsscan-inbox-"));
  try {
    const producer = await Tn.init(sender.yamlPath);
    const consumer = await Tn.init(receiver.yamlPath);
    const kitsDir = mkdtempSync(join(tmpdir(), "fsscan-kits-"));
    try {
      await producer.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
    const snapPath = join(inbox, "snap.tnpkg");
    await producer.pkg.export({ adminLogSnapshot: { outPath: snapPath } }, snapPath);

    const h = new FsScanHandler("fs", {
      inDir: inbox,
      absorber: makeTNClientAbsorber(tnAsAbsorber(consumer)),
      autostart: false,
    });
    const n = h.tickOnce();
    assert.equal(n, 1, "expected one absorbed file");
    const remaining = readdirSync(inbox).filter((p) => p.endsWith(".tnpkg"));
    assert.equal(remaining.length, 0, "inbox should be empty after archive");
    const archive = readdirSync(join(inbox, ".processed"));
    assert.equal(archive.length, 1);
    h.close();
    await producer.close();
    await consumer.close();
  } finally {
    sender.cleanup();
    receiver.cleanup();
    rmSync(inbox, { recursive: true, force: true });
  }
});

test("fs.scan ignores non-tnpkg files", async () => {
  const receiver = makeCeremony("tn-fsscan-rx-skip-");
  const inbox = mkdtempSync(join(tmpdir(), "tn-fsscan-skip-"));
  try {
    writeFileSync(join(inbox, "junk.txt"), "noise");
    const consumer = await Tn.init(receiver.yamlPath);
    const h = new FsScanHandler("fs", {
      inDir: inbox,
      absorber: makeTNClientAbsorber(tnAsAbsorber(consumer)),
      autostart: false,
    });
    assert.equal(h.tickOnce(), 0);
    assert.ok(existsSync(join(inbox, "junk.txt")), "non-tnpkg file should be left alone");
    await consumer.close();
  } finally {
    receiver.cleanup();
    rmSync(inbox, { recursive: true, force: true });
  }
});

test("fs.scan returns 0 when in_dir does not exist", async () => {
  const receiver = makeCeremony("tn-fsscan-rx-missing-");
  try {
    const consumer = await Tn.init(receiver.yamlPath);
    const h = new FsScanHandler("fs", {
      inDir: join(receiver.tmpDir, "does_not_exist"),
      absorber: makeTNClientAbsorber(tnAsAbsorber(consumer)),
      autostart: false,
    });
    assert.equal(h.tickOnce(), 0);
    await consumer.close();
  } finally {
    receiver.cleanup();
  }
});
