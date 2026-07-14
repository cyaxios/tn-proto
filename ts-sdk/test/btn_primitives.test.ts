import { strict as assert } from "node:assert";
import { test } from "node:test";

import * as btn from "../src/btn.js";
import { LimitExceededError, MalformedError, NotEntitledError } from "../src/primitive_errors.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

test("BTN producer and subscriber share the byte-oriented flow", () => {
  const producer = btn.setup();
  const kit = producer.mint();
  const ciphertext = producer.encrypt(bytes("hello"));

  assert.deepEqual(producer.decrypt(ciphertext), bytes("hello"));
  assert.deepEqual(btn.subscribe([kit]).decrypt(ciphertext), bytes("hello"));
  assert.equal(producer.issuedCount(), 1);
  assert.equal(producer.revokedCount(), 0);
  assert.equal(producer.publisherId().length, 32);
  assert.equal(typeof producer.epoch, "number");
});

test("BTN producer decrypt uses master state without minting a hidden kit", () => {
  const producer = btn.setup();
  const ciphertext = producer.encrypt(bytes("producer-only"));

  assert.equal(producer.issuedCount(), 0);
  assert.deepEqual(producer.decrypt(ciphertext), bytes("producer-only"));
  assert.equal(producer.issuedCount(), 0);
});

test("BTN authenticates optional AAD for producer and subscriber decrypt", () => {
  const producer = btn.setup();
  const kit = producer.mint();
  const aad = bytes("record-header");
  const ciphertext = producer.encrypt(bytes("bound"), aad);

  assert.deepEqual(producer.decrypt(ciphertext, aad), bytes("bound"));
  assert.deepEqual(btn.subscribe([kit]).decrypt(ciphertext, aad), bytes("bound"));
  assert.throws(() => producer.decrypt(ciphertext, bytes("changed")), NotEntitledError);
  assert.throws(() => btn.subscribe([kit]).decrypt(ciphertext), NotEntitledError);
});

test("BTN producer state restores with its metadata and reader entitlement", () => {
  const producer = btn.setup();
  const kit = producer.mint();
  const restored = btn.Producer.fromBytes(producer.toBytes());
  const ciphertext = restored.encrypt(bytes("restored"));

  assert.deepEqual(restored.publisherId(), producer.publisherId());
  assert.equal(restored.epoch, producer.epoch);
  assert.equal(restored.issuedCount(), producer.issuedCount());
  assert.deepEqual(restored.decrypt(ciphertext), bytes("restored"));
  assert.deepEqual(btn.subscribe([kit]).decrypt(ciphertext), bytes("restored"));
});

test("BTN subscriber tries a later entitled kit and validates added kits", () => {
  const otherProducer = btn.setup();
  const wrongKit = otherProducer.mint();
  const producer = btn.setup();
  const rightKit = producer.mint();
  const subscriber = btn.subscribe([wrongKit]);
  subscriber.addKey(rightKit);

  assert.deepEqual(subscriber.decrypt(producer.encrypt(bytes("later"))), bytes("later"));
  assert.throws(() => subscriber.addKey(Uint8Array.of(0xde, 0xad)), MalformedError);
});

test("BTN rejects empty subscriptions and malformed kits before storage", () => {
  assert.throws(() => btn.subscribe([]), MalformedError);
  assert.throws(() => new btn.Subscriber([]), MalformedError);
  assert.throws(() => new btn.Subscriber([Uint8Array.of(0xde, 0xad)]), MalformedError);
  assert.throws(
    () => btn.subscribe([Uint8Array.of(0xde, 0xad)]),
    (error: unknown) => {
      assert.ok(error instanceof MalformedError);
      assert.doesNotMatch(error.message, /dead/i);
      return true;
    },
  );
});

test("BTN rejects malformed ciphertext before trying held kits", () => {
  const producer = btn.setup();
  const subscriber = btn.subscribe([producer.mint()]);

  assert.throws(
    () => subscriber.decrypt(Uint8Array.of(0xca, 0xfe)),
    (error: unknown) => {
      assert.ok(error instanceof MalformedError);
      assert.doesNotMatch(error.message, /cafe/i);
      return true;
    },
  );
  assert.throws(() => btn.Producer.fromBytes(Uint8Array.of(0xba, 0xad)), MalformedError);
});

test("BTN revocation affects future ciphertext but not earlier ciphertext", () => {
  const producer = btn.setup();
  const firstKit = producer.mint();
  const secondKit = producer.mint();
  const firstReader = btn.subscribe([firstKit]);
  const secondReader = btn.subscribe([secondKit]);
  const before = producer.encrypt(bytes("before"));

  producer.revoke(firstKit);
  const afterFirstRevocation = producer.encrypt(bytes("after-first"));
  assert.deepEqual(firstReader.decrypt(before), bytes("before"));
  assert.throws(() => firstReader.decrypt(afterFirstRevocation), NotEntitledError);
  assert.deepEqual(secondReader.decrypt(afterFirstRevocation), bytes("after-first"));

  producer.revokeByLeaf(1n);
  const afterSecondRevocation = producer.encrypt(bytes("after-second"));
  assert.throws(() => secondReader.decrypt(afterSecondRevocation), NotEntitledError);
  assert.equal(producer.issuedCount(), 0);
  assert.equal(producer.revokedCount(), 2);
});

test("BTN maps reader-tree exhaustion to LimitExceeded", () => {
  const producer = btn.setup();
  for (let leaf = 0; leaf < 256; leaf += 1) producer.mint();

  assert.throws(() => producer.mint(), LimitExceededError);
});
