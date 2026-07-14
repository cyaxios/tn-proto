import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  jweDecryptDetailedSync,
  jweDecryptManyDetailedSync,
  jweDecryptSync,
  jweSeal,
  jweSealSync,
  okpPrivateJwk,
} from "../src/core/jwe.js";
import { decryptGroup, decryptGroupAsync } from "../src/core/decrypt.js";
import * as jwe from "../src/jwe.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

test("JWE byte facade has synchronous primitives with compatible async delegates", async () => {
  const reader = jwe.keygen();
  const aad = bytes("policy");
  const ciphertext = jwe.encryptSync(bytes("secret"), [reader.publicKey], aad);
  const subscriber = jwe.subscribe([reader.privateKey]);

  assert.deepEqual(subscriber.decryptSync(ciphertext, aad), bytes("secret"));
  assert.deepEqual(await subscriber.decrypt(ciphertext, aad), bytes("secret"));
  assert.deepEqual(
    subscriber.decryptSync(await jwe.encrypt(bytes("async delegate"), [reader.publicKey])),
    bytes("async delegate"),
  );
});

test("core JWE sync surface preserves RFC7516, AAD, recipients, and outcomes", async () => {
  const first = jwe.keygen();
  const second = jwe.keygen();
  const stranger = jwe.keygen();
  const aad = bytes("record aad");
  const plaintext = bytes('{"value":42}');
  const ciphertext = jweSealSync([first.publicKey, second.publicKey], plaintext, aad);
  const wire = JSON.parse(new TextDecoder().decode(ciphertext)) as {
    aad?: string;
    recipients: unknown[];
  };

  assert.equal(wire.recipients.length, 2);
  assert.equal(typeof wire.aad, "string");
  assert.deepEqual(
    jweDecryptSync(okpPrivateJwk(first.publicKey, first.privateKey), ciphertext, aad),
    plaintext,
  );
  assert.deepEqual(
    jweDecryptSync(okpPrivateJwk(second.publicKey, second.privateKey), ciphertext, aad),
    plaintext,
  );
  assert.deepEqual(
    jweDecryptManyDetailedSync(
      [
        okpPrivateJwk(stranger.publicKey, stranger.privateKey),
        okpPrivateJwk(second.publicKey, second.privateKey),
      ],
      ciphertext,
      aad,
    ),
    { status: "opened", plaintext },
  );
  assert.equal(
    jweDecryptSync(okpPrivateJwk(stranger.publicKey, stranger.privateKey), ciphertext, aad),
    null,
  );
  assert.deepEqual(
    jweDecryptDetailedSync(
      okpPrivateJwk(first.publicKey, first.privateKey),
      ciphertext,
      bytes("wrong"),
    ),
    { status: "authentication_failed" },
  );
  assert.deepEqual(
    jweDecryptDetailedSync(okpPrivateJwk(first.publicKey, first.privateKey), bytes("bad")),
    {
      status: "malformed",
    },
  );

  const asyncCiphertext = await jweSeal([first.publicKey], plaintext);
  assert.deepEqual(
    jweDecryptSync(okpPrivateJwk(first.publicKey, first.privateKey), asyncCiphertext),
    plaintext,
  );
});

test("decryptGroup opens JWE synchronously and async delegates to the same result", async () => {
  const reader = jwe.keygen();
  const aad = bytes("group aad");
  const ciphertext = jweSealSync([reader.publicKey], bytes('{"message":"opened"}'), aad);
  const kits = { cipher: "jwe" as const, kits: [reader.privateKey] };

  const opened = decryptGroup({ ct: ciphertext, aad }, kits);
  assert.deepEqual(opened, { message: "opened" });
  assert.deepEqual(await decryptGroupAsync({ ct: ciphertext, aad }, kits), opened);
});
