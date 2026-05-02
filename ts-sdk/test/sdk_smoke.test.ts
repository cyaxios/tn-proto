import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  DeviceKey,
  ZERO_HASH,
  admin,
  asDid,
  buildEnvelopeLine,
  canonicalize,
  canonicalizeToString,
  deriveGroupKey,
  didFromPublicKey,
  indexTokenFor,
  rowHash,
  signatureB64,
  verify,
} from "../src/index.js";

test("canonicalize sorts keys and matches expected bytes", () => {
  assert.equal(canonicalizeToString({ b: 2, a: 1 }), '{"a":1,"b":2}');
  const bytes = canonicalize({ a: 1 });
  assert.equal(Buffer.from(bytes).toString("utf8"), '{"a":1}');
});

test("DeviceKey from deterministic seed has stable DID", () => {
  const seed = new Uint8Array(32);
  const dk = DeviceKey.fromSeed(seed);
  assert.equal(dk.seed.length, 32);
  assert.equal(dk.publicKey.length, 32);
  assert.ok(dk.did.startsWith("did:key:z"));
  assert.equal(didFromPublicKey(dk.publicKey), dk.did);
});

test("sign then verify roundtrips", () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = i;
  const dk = DeviceKey.fromSeed(seed);
  const msg = new Uint8Array(Buffer.from("hello world"));
  const sig = dk.sign(msg);
  assert.equal(sig.length, 64);
  assert.ok(verify(dk.did, msg, sig));

  const tampered = new Uint8Array(Buffer.from("hello WORLD"));
  assert.ok(!verify(dk.did, tampered, sig));
});

test("deriveGroupKey and indexToken are deterministic", () => {
  const master = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) master[i] = i * 3;
  const gk = deriveGroupKey(master, "c1", "default", 0);
  assert.equal(gk.length, 32);

  const a = indexTokenFor(gk, "order_id", "ORD-1");
  const b = indexTokenFor(gk, "order_id", "ORD-1");
  assert.equal(a, b);
  assert.ok(a.startsWith("hmac-sha256:v1:"));

  const c = indexTokenFor(gk, "order_id", "ORD-2");
  assert.notEqual(a, c);
});

test("rowHash + buildEnvelopeLine round-trip a public-only entry", () => {
  const seed = new Uint8Array(32);
  const dk = DeviceKey.fromSeed(seed);
  const rh = rowHash({
    did: dk.did,
    timestamp: "2026-04-23T12:00:00Z",
    eventId: "11111111-2222-3333-4444-555555555555",
    eventType: "order.created",
    level: "info",
    prevHash: ZERO_HASH(),
    publicFields: { amount: 100, status: "paid" },
  });
  assert.ok(/^sha256:[0-9a-f]{64}$/.test(rh));

  const sig = dk.sign(new Uint8Array(Buffer.from(rh, "utf8")));
  const line = buildEnvelopeLine({
    did: dk.did,
    timestamp: "2026-04-23T12:00:00Z",
    eventId: "11111111-2222-3333-4444-555555555555",
    eventType: "order.created",
    level: "info",
    sequence: 1,
    prevHash: ZERO_HASH(),
    rowHash: rh,
    signatureB64: signatureB64(sig),
    publicFields: { amount: 100, status: "paid" },
  });

  assert.ok(line.endsWith("\n"));
  const envelope = JSON.parse(line);
  assert.equal(envelope.event_type, "order.created");
  assert.equal(envelope.row_hash, rh);
  assert.equal(envelope.amount, 100);
});

test("admin.reduce turns a recipient.added envelope into a typed delta", () => {
  const envelope = {
    event_type: "tn.recipient.added",
    did: "did:key:z6Mktest",
    timestamp: "2026-04-23T12:00:00Z",
    group: "default",
    leaf_index: 3,
    recipient_did: "did:key:z6Mkbob",
    kit_sha256: "a".repeat(64),
    cipher: "btn",
  };
  const delta = admin.reduce(envelope);
  assert.equal(delta.kind, "recipient_added");
  assert.equal((delta as Record<string, unknown>).group, "default");
});

test("admin.catalogKinds lists 10 kinds", () => {
  const kinds = admin.catalogKinds();
  assert.ok(kinds.length >= 10);
  for (const k of kinds) {
    assert.ok(k.event_type.startsWith("tn."));
  }
});

test("asDid rejects non-DID strings", () => {
  assert.throws(() => asDid("hello"));
});
