// Tests for the TS `vault.pull` handler — uses node:http to stand up
// a local mock vault that serves listIncoming + download, then verifies
// the handler absorbs the snapshot and persists a cursor at
// `<cursorDir>/vault_pull.cursor.json`.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
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
  DeviceKey,
  VaultPullHandler,
  makeFetchVaultInboxClient,
  type VaultInboxItem,
  type VaultPullAbsorber,
} from "../src/index.js";
import { Tn } from "../src/tn.js";

/** Thin adapter: wraps a Tn instance as the interface NodeRuntime.absorbPkg expects. */
function tnAsAbsorber(tn: Tn): { absorb: (source: string | Uint8Array) => { rejectedReason?: string | null } } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rt = (tn as any)._rt;
  return { absorb: (source: string | Uint8Array) => rt.absorbPkg(source) };
}
import { BtnPublisher } from "../src/raw.js";

interface MockVault {
  baseUrl: string;
  setItems: (items: VaultInboxItem[], bodyByPath: Map<string, Buffer>) => void;
  listedSince: string[];
  close: () => Promise<void>;
}

function startMockVault(): Promise<MockVault> {
  return new Promise((resolve) => {
    let items: VaultInboxItem[] = [];
    let bodies: Map<string, Buffer> = new Map();
    const listedSince: string[] = [];
    const server = createServer((req, res) => {
      const url = req.url ?? "";
      if (url.startsWith("/api/v1/inbox/") && url.includes("/incoming")) {
        const u = new URL(url, "http://x");
        const since = u.searchParams.get("since");
        listedSince.push(since ?? "<none>");
        const filtered = items.filter((it) => {
          if (since === null) return true;
          // Mirror server semantics (per spec §4.1): when items carry
          // since_marker, filter by it; otherwise fall back to
          // received_at. Lets tests assert which field the SDK uses.
          const key = it.since_marker ?? it.received_at;
          if (key == null) return true;
          return key > since;
        });
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ items: filtered }));
        return;
      }
      // Otherwise treat as a download.
      const body = bodies.get(url);
      if (body !== undefined) {
        res.statusCode = 200;
        res.setHeader("content-type", "application/octet-stream");
        res.end(body);
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        setItems(newItems, newBodies) {
          items = newItems;
          bodies = newBodies;
        },
        listedSince,
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

function makeCeremony(prefix: string): { yamlPath: string; tmpDir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 13 + prefix.length * 31) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const idx = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) idx[i] = (i * 7 + prefix.length) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(idx));
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

test("vault.pull absorbs a mock-served snapshot and persists a cursor", async () => {
  const sender = makeCeremony("tn-vpull-tx-");
  const receiver = makeCeremony("tn-vpull-rx-");
  const vault = await startMockVault();
  try {
    // Producer makes a real signed snapshot.
    const producer = await Tn.init(sender.yamlPath);
    const kitsDir = mkdtempSync(join(tmpdir(), "vpull-kits-"));
    try {
      await producer.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zAlice" });
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
    const snapPath = join(sender.tmpDir, "snap.tnpkg");
    await producer.pkg.export({ adminLogSnapshot: { outPath: snapPath } }, snapPath);
    const snapBytes = readFileSync(snapPath);
    await producer.close();

    const inboxItem: VaultInboxItem = {
      path: "/api/v1/inbox/abc/snapshots/cer/2026.tnpkg",
      head_row_hash: "sha256:dummy",
      received_at: "2026-04-21T12:00:01.000000Z",
    };
    vault.setItems([inboxItem], new Map([[inboxItem.path, snapBytes]]));

    const consumer = await Tn.init(receiver.yamlPath);
    const absorber: VaultPullAbsorber = {
      absorb(bytes) {
        const r = tnAsAbsorber(consumer).absorb(bytes);
        return { rejectedReason: r.rejectedReason ?? null };
      },
    };
    const cursorDir = join(receiver.tmpDir, ".tn/admin");
    const httpClient = makeFetchVaultInboxClient({ baseUrl: vault.baseUrl });
    const h = new VaultPullHandler("pull", {
      endpoint: vault.baseUrl,
      projectId: "proj_xxx",
      did: consumer.did,
      client: httpClient,
      absorber,
      cursorDir,
      autostart: false,
    });
    const n = await h.tickOnce();
    assert.equal(n, 1, "expected one absorbed");
    const cursorFile = join(cursorDir, "vault_pull.cursor.json");
    assert.ok(existsSync(cursorFile), "cursor file should exist");
    const cursor = JSON.parse(readFileSync(cursorFile, "utf8")) as { last_seen?: string };
    assert.equal(cursor.last_seen, inboxItem.received_at);

    // Second tick — the mock filters by `since`; should noop.
    const m = await h.tickOnce();
    assert.equal(m, 0);
    assert.equal(vault.listedSince.length, 2);
    assert.equal(vault.listedSince[1], inboxItem.received_at);

    h.close();
    await consumer.close();
  } finally {
    await vault.close();
    sender.cleanup();
    receiver.cleanup();
  }
});

test("vault.pull empty inbox does not create cursor", async () => {
  const receiver = makeCeremony("tn-vpull-rx-empty-");
  const vault = await startMockVault();
  try {
    vault.setItems([], new Map());
    const consumer = await Tn.init(receiver.yamlPath);
    const absorber: VaultPullAbsorber = {
      absorb: () => ({ rejectedReason: null }),
    };
    const cursorDir = join(receiver.tmpDir, ".tn/admin");
    const httpClient = makeFetchVaultInboxClient({ baseUrl: vault.baseUrl });
    const h = new VaultPullHandler("pull", {
      endpoint: vault.baseUrl,
      projectId: "proj_xxx",
      did: consumer.did,
      client: httpClient,
      absorber,
      cursorDir,
      autostart: false,
    });
    const n = await h.tickOnce();
    assert.equal(n, 0);
    const cursorFile = join(cursorDir, "vault_pull.cursor.json");
    assert.ok(!existsSync(cursorFile));
    h.close();
    await consumer.close();
  } finally {
    await vault.close();
    receiver.cleanup();
  }
});

test("vault.pull cursor advances by since_marker when present (§4.1)", async () => {
  const sender = makeCeremony("tn-vpull-marker-tx-");
  const receiver = makeCeremony("tn-vpull-marker-rx-");
  const vault = await startMockVault();
  try {
    // Producer makes a real signed snapshot.
    const producer = await Tn.init(sender.yamlPath);
    const kitsDir = mkdtempSync(join(tmpdir(), "vpull-marker-kits-"));
    try {
      await producer.admin.addRecipient("default", { outKitPath: join(kitsDir, "default.btn.mykit"), recipientDid: "did:key:zMarker" });
    } finally {
      rmSync(kitsDir, { recursive: true, force: true });
    }
    const snapPath = join(sender.tmpDir, "snap.tnpkg");
    await producer.pkg.export({ adminLogSnapshot: { outPath: snapPath } }, snapPath);
    const snapBytes = readFileSync(snapPath);
    await producer.close();

    // since_marker is intentionally distinct from received_at so the
    // next-poll cursor reveals which field the SDK trusts.
    const inboxItem: VaultInboxItem = {
      path: "/api/v1/inbox/abc/snapshots/cer/marker.tnpkg",
      head_row_hash: "sha256:dummy",
      received_at: "2026-04-21T12:00:01.000000Z",
      since_marker: "opaque-cursor-002",
    };
    vault.setItems([inboxItem], new Map([[inboxItem.path, snapBytes]]));

    const consumer = await Tn.init(receiver.yamlPath);
    const absorber: VaultPullAbsorber = {
      absorb(bytes) {
        const r = tnAsAbsorber(consumer).absorb(bytes);
        return { rejectedReason: r.rejectedReason ?? null };
      },
    };
    const cursorDir = join(receiver.tmpDir, ".tn/admin");
    const httpClient = makeFetchVaultInboxClient({ baseUrl: vault.baseUrl });
    const h = new VaultPullHandler("pull", {
      endpoint: vault.baseUrl,
      projectId: "proj_xxx",
      did: consumer.did,
      client: httpClient,
      absorber,
      cursorDir,
      autostart: false,
    });
    const n = await h.tickOnce();
    assert.equal(n, 1, "expected one absorbed");
    // Cursor file should hold since_marker, not received_at.
    const cursorFile = join(cursorDir, "vault_pull.cursor.json");
    const cursor = JSON.parse(readFileSync(cursorFile, "utf8")) as { last_seen?: string };
    assert.equal(
      cursor.last_seen,
      "opaque-cursor-002",
      `§4.1: cursor should advance by since_marker, got ${cursor.last_seen ?? "(null)"}`,
    );

    // Second tick — the mock filters by since_marker; should noop.
    const m = await h.tickOnce();
    assert.equal(m, 0);
    assert.equal(
      vault.listedSince[1],
      "opaque-cursor-002",
      `§4.1: ?since= should be since_marker, got ${vault.listedSince[1] ?? "(none)"}`,
    );

    h.close();
    await consumer.close();
  } finally {
    await vault.close();
    sender.cleanup();
    receiver.cleanup();
  }
});
