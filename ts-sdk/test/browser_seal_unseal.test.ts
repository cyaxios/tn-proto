// Browser-entry tn.seal / tn.unseal: the portable-object verbs on the
// wasm-backed browser ceremony, plus the ceremony-less unseal walk and
// the jwe recipient surface the docs' browser examples run on.
//
// Runs under node, but every SDK import here is the browser entry's own
// module graph — the same one the CDN bundle wraps (tn-wasm resolves to
// the node pkg here, pkg-web in the bundle; same core either way).
//
// The browser has no filesystem, so `asRecipient` takes the browser
// analog of "a directory holding key files": a storage adapter or a
// plain {filename -> bytes} bag using the same keystore filenames the
// Node side walks (`<group>.btn.mykit`, `<group>.jwe.mykey`, ...).
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  Tn as BrowserTn,
  memoryStorageAdapter,
  unseal as unsealBrowser,
  SealedObject,
  VerifyError,
  jweSeal,
  jweDecrypt,
  okpPrivateJwk,
  generateX25519KeyPair,
  type SealedTriple,
} from "../src/index.browser.js";
import type { Entry } from "../src/Entry.js";
import { Tn as NodeTn } from "../src/tn.js";
import { unsealWithRuntime } from "../src/seal.js";
import type { MemoryStorageAdapter } from "../src/runtime/storage_memory.js";

/** tn.* events route to the admin/protocol-events log (a dedicated
 * file, not the main ceremony log) — read that storage slot raw. */
function adminReceipts(store: MemoryStorageAdapter): Array<Record<string, unknown>> {
  const path = "/v/.tn/tn/admin/default.ndjson";
  if (!store.exists(path)) return [];
  return new TextDecoder()
    .decode(store.read(path))
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((env) => env["event_type"] === "tn.object.sealed");
}

test("browser seal -> unseal round-trips on the wasm ceremony with a receipt", async () => {
  const store = memoryStorageAdapter();
  const t = await BrowserTn.init({ storage: store, console: false });
  try {
    const sealed = await t.seal("obj.invoice.v1", { amount: 42, memo: "q3 plan" });
    assert.ok(sealed instanceof SealedObject);
    assert.equal(sealed.envelope["tn_sealed"], 1);
    assert.equal(sealed.envelope["sequence"], 0);
    assert.equal(sealed.envelope["prev_hash"], "");
    assert.equal(sealed.deviceIdentity, t.did());

    const entry = (await t.unseal(sealed)) as Entry;
    assert.deepEqual(entry.fields, { amount: 42, memo: "q3 plan" });

    const triple = (await t.unseal(sealed, { raw: true })) as SealedTriple;
    assert.equal(triple.valid.signature, true);
    assert.equal(triple.valid.row_hash, true);
    assert.deepEqual(triple.plaintext["default"], { amount: 42, memo: "q3 plan" });

    // The receipt row chained through the live wasm write path, landing
    // on the admin/protocol-events surface like every tn.* event.
    const receipts = adminReceipts(store);
    assert.equal(receipts.length, 1);
  } finally {
    await t.close();
  }
});

test("browser seal with receipt: false writes no receipt row", async () => {
  const store = memoryStorageAdapter();
  const t = await BrowserTn.init({ storage: store, console: false });
  try {
    await t.seal("obj.doc.v1", { note: "quiet" }, { receipt: false });
    assert.equal(adminReceipts(store).length, 0);
  } finally {
    await t.close();
  }
});

test("browser unseal raises VerifyError on a tampered public field", async () => {
  const t = await BrowserTn.init({ storage: memoryStorageAdapter(), console: false });
  try {
    const sealed = await t.seal("obj.doc.v1", { note: "x" }, { receipt: false });
    const env = JSON.parse(sealed.rawJson) as Record<string, unknown>;
    env["injected"] = "oops";
    await assert.rejects(t.unseal(env), VerifyError);
  } finally {
    await t.close();
  }
});

test("a node-sealed jwe object opens in the browser as a bag recipient", async () => {
  const base = mkdtempSync(join(tmpdir(), "tn-browser-jwe-"));
  const node = await NodeTn.init(join(base, "tn.yaml"), { cipher: "jwe", stdout: false });
  try {
    const pair = generateX25519KeyPair();
    await node.admin.addRecipient("default", {
      recipientDid: "did:key:z6MkBrowserBagRecipient00000000000000000000",
      publicKey: pair.publicKey,
      unsafeUnverified: true, // raw DID-plus-key path (no enrollment proof)
    });
    const sealed = await node.seal("obj.kyc.v1", { body: "sealed for the browser" });

    // Browser side: no ceremony at all — verify + open with a key bag.
    const entry = (await unsealBrowser(sealed.rawJson, {
      asRecipient: { "default.jwe.mykey": pair.privateKey },
      group: "default",
    })) as Entry;
    assert.deepEqual(entry.fields, { body: "sealed for the browser" });

    const triple = (await unsealBrowser(sealed.rawJson, {
      asRecipient: { "default.jwe.mykey": pair.privateKey },
      group: "default",
      raw: true,
    })) as SealedTriple;
    assert.equal(triple.valid.signature, true);
    assert.equal(triple.valid.row_hash, true);
  } finally {
    await node.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("a browser-sealed object opens in node via asRecipient (btn kit)", async () => {
  const store = memoryStorageAdapter();
  const t = await BrowserTn.init({ storage: store, console: false });
  const sealed = await t.seal("obj.note.v1", { body: "from the browser" }, { receipt: false });
  await t.close();

  // Export the browser ceremony's own btn reader kit into a directory
  // the Node walk understands.
  const base = mkdtempSync(join(tmpdir(), "tn-browser-kit-"));
  try {
    const kitDir = join(base, "keys");
    mkdirSync(kitDir, { recursive: true });
    writeFileSync(
      join(kitDir, "default.btn.mykit"),
      store.read("/v/.tn/tn/keys/default.btn.mykit"),
    );
    const entry = (await unsealWithRuntime(null, sealed.rawJson, {
      asRecipient: kitDir,
      group: "default",
    })) as Entry;
    assert.deepEqual(entry.fields, { body: "from the browser" });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("the browser entry exposes the raw jwe cipher (jweSeal / jweDecrypt)", async () => {
  const a = generateX25519KeyPair();
  const b = generateX25519KeyPair();
  const pt = new TextEncoder().encode(JSON.stringify({ ssn: "123-45-6789" }));

  const blob = await jweSeal([a.publicKey, b.publicKey], pt);
  const opened = await jweDecrypt(okpPrivateJwk(b.publicKey, b.privateKey), blob);
  assert.ok(opened, "enrolled recipient could not open the jwe blob");
  assert.deepEqual(JSON.parse(new TextDecoder().decode(opened)), { ssn: "123-45-6789" });

  const stranger = generateX25519KeyPair();
  assert.equal(
    await jweDecrypt(okpPrivateJwk(stranger.publicKey, stranger.privateKey), blob),
    null,
    "a non-recipient key must not open the blob",
  );
});
