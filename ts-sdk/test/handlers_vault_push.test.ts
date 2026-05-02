// Tests for the TS `vault.push` handler — uses node:http to stand up
// a local mock vault and verifies the handler POSTs the right URL +
// body shape, plus the `head_row_hash` idempotency guard.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DeviceKey,
  VaultPushHandler,
  makeFetchVaultPostClient,
  makeTNClientSnapshotBuilder,
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

interface RecordedRequest {
  method: string;
  url: string;
  body: Buffer;
}

function startMockVault(): Promise<{ baseUrl: string; calls: RecordedRequest[]; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const calls: RecordedRequest[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        calls.push({
          method: req.method ?? "",
          url: req.url ?? "",
          body: Buffer.concat(chunks),
        });
        res.statusCode = 204;
        res.end();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        calls,
        close: () =>
          new Promise<void>((r) =>
            server.close(() => {
              r();
            }),
          ),
      });
    });
  });
}

function makeCeremony(): { yamlPath: string; tmpDir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-vpush-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 13 + 17) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const idx = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) idx[i] = (i * 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(idx));
  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 23) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));
  const yaml =
    `ceremony:\n  id: vpush_test\n  mode: local\n  cipher: btn\n` +
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

test("vault.push POSTs a signed snapshot to the mock endpoint", async () => {
  const cer = makeCeremony();
  const vault = await startMockVault();
  try {
    const tn = await Tn.init(cer.yamlPath);
    const kitsDir = mkdtempSync(join(tmpdir(), "vpush-kits-"));
    try {
      await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
    const httpClient = makeFetchVaultPostClient({ baseUrl: vault.baseUrl });
    const h = new VaultPushHandler("push", {
      endpoint: vault.baseUrl,
      projectId: "proj_xxx",
      builder: makeTNClientSnapshotBuilder(tnAsExporter(tn)),
      client: httpClient,
      outboxDir: join(cer.tmpDir, ".tn/admin", "outbox"),
      trigger: "on_emit",
      autostart: false,
    });

    const pushed = await h.pushSnapshot();
    assert.equal(pushed, true, "first push should ship");
    assert.equal(vault.calls.length, 1);
    const call = vault.calls[0]!;
    assert.equal(call.method, "POST");
    assert.match(call.url, /^\/api\/v1\/inbox\/[^/]+\/snapshots\/[^/]+\/[^/]+\.tnpkg(\?|$)/);
    assert.match(call.url, /head_row_hash=/);
    // Body parses as a valid signed manifest of kind admin_log_snapshot.
    const { manifest } = readTnpkg(new Uint8Array(call.body));
    assert.equal(manifest.kind, "admin_log_snapshot");
    assert.equal(manifest.fromDid, tn.did);

    h.close();
    await tn.close();
  } finally {
    await vault.close();
    cer.cleanup();
  }
});

test("vault.push is idempotent when head_row_hash is unchanged", async () => {
  const cer = makeCeremony();
  const vault = await startMockVault();
  try {
    const tn = await Tn.init(cer.yamlPath);
    const kitsDir = mkdtempSync(join(tmpdir(), "vpush-kits-"));
    try {
      await tn.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zA" });
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
    const httpClient = makeFetchVaultPostClient({ baseUrl: vault.baseUrl });
    const h = new VaultPushHandler("push", {
      endpoint: vault.baseUrl,
      projectId: "proj_xxx",
      builder: makeTNClientSnapshotBuilder(tnAsExporter(tn)),
      client: httpClient,
      outboxDir: join(cer.tmpDir, ".tn/admin", "outbox"),
      trigger: "on_emit",
      autostart: false,
    });
    const a = await h.pushSnapshot();
    const b = await h.pushSnapshot();
    assert.equal(a, true);
    assert.equal(b, false, "second push should noop");
    assert.equal(vault.calls.length, 1);
    h.close();
    await tn.close();
  } finally {
    await vault.close();
    cer.cleanup();
  }
});
