import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import type { JWK } from "jose";

import {
  JWE_ALG,
  JWE_ENC,
  jweDecrypt,
  jweDecryptDetailed,
  jweDecryptManyDetailed,
  okpPrivateJwk,
} from "../src/core/jwe.js";
import * as jwe from "../src/jwe.js";
import {
  AuthenticationFailedError,
  LimitExceededError,
  MalformedError,
  NotEntitledError,
} from "../src/primitive_errors.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

interface WireHeader {
  alg?: unknown;
  enc?: unknown;
  epk?: Record<string, unknown> | null;
  [key: string]: unknown;
}

interface WireRecipient {
  encrypted_key?: unknown;
  header?: WireHeader | null;
  [key: string]: unknown;
}

interface WireJwe {
  aad?: unknown;
  ciphertext: unknown;
  iv: unknown;
  protected: string;
  recipients: WireRecipient[];
  tag: unknown;
  unprotected?: WireHeader | null;
  [key: string]: unknown;
}

function parseWire(ciphertext: Uint8Array): WireJwe {
  return JSON.parse(new TextDecoder().decode(ciphertext)) as WireJwe;
}

function rewriteWire(ciphertext: Uint8Array, mutate: (wire: WireJwe) => void): Uint8Array {
  const wire = parseWire(ciphertext);
  mutate(wire);
  return bytes(JSON.stringify(wire));
}

function protectedHeader(wire: WireJwe): WireHeader {
  return JSON.parse(Buffer.from(wire.protected, "base64url").toString("utf8")) as WireHeader;
}

function setProtectedHeader(wire: WireJwe, header: WireHeader): void {
  wire.protected = Buffer.from(JSON.stringify(header)).toString("base64url");
}

function guardedInfinite(value: Uint8Array): {
  iterable: Iterable<Uint8Array>;
  pulls: () => number;
} {
  let pulls = 0;
  return {
    iterable: {
      *[Symbol.iterator]() {
        while (true) {
          pulls += 1;
          if (pulls > 1_025) throw new Error("iterable was consumed past its bound");
          yield value;
        }
      },
    },
    pulls: () => pulls,
  };
}

class OversizedCiphertext extends Uint8Array {
  override get length(): number {
    return 128 * 1024 * 1024 + 1;
  }
}

test("JWE facade encrypts and decrypts for one subscriber", async () => {
  const keys = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("hello"), [keys.publicKey]);
  const reader = jwe.subscribe([keys.privateKey]);

  assert.deepEqual(await reader.decrypt(ciphertext), bytes("hello"));
});

test("detailed decrypt outcomes preserve the legacy null-returning API", async () => {
  const keys = jwe.keygen();
  const stranger = jwe.keygen();
  const aad = bytes("policy");
  const ciphertext = await jwe.encrypt(bytes("hello"), [keys.publicKey], aad);
  const readerJwk = okpPrivateJwk(keys.publicKey, keys.privateKey);
  const strangerJwk = okpPrivateJwk(stranger.publicKey, stranger.privateKey);

  const opened = await jweDecryptDetailed(readerJwk, ciphertext, aad);
  assert.equal(opened.status, "opened");
  if (opened.status === "opened") assert.deepEqual(opened.plaintext, bytes("hello"));
  assert.deepEqual(await jweDecrypt(readerJwk, ciphertext, aad), bytes("hello"));

  assert.deepEqual(await jweDecryptDetailed(readerJwk, ciphertext, bytes("wrong")), {
    status: "authentication_failed",
  });
  assert.deepEqual(await jweDecryptDetailed(strangerJwk, ciphertext, aad), {
    status: "not_entitled",
  });
  assert.deepEqual(await jweDecryptDetailed(readerJwk, bytes("not json")), {
    status: "malformed",
  });
  assert.equal(await jweDecrypt(readerJwk, ciphertext, bytes("wrong")), null);
});

test("keygen and encryption emit the RFC 7516 TN profile for every recipient", async () => {
  const first = jwe.keygen();
  const second = jwe.keygen();
  assert.equal(first.publicKey.length, 32);
  assert.equal(first.privateKey.length, 32);

  const ciphertext = await jwe.encrypt(bytes("profile"), [first.publicKey, second.publicKey]);
  const wire = parseWire(ciphertext);
  assert.deepEqual(protectedHeader(wire), { enc: JWE_ENC });
  assert.equal(typeof wire.iv, "string");
  assert.equal(typeof wire.ciphertext, "string");
  assert.equal(typeof wire.tag, "string");
  assert.equal(wire.recipients.length, 2);
  for (const recipient of wire.recipients) {
    assert.equal(recipient.header?.alg, JWE_ALG);
    assert.deepEqual(
      {
        crv: recipient.header?.epk?.crv,
        kty: recipient.header?.epk?.kty,
      },
      { crv: "X25519", kty: "OKP" },
    );
    assert.equal(typeof recipient.header?.epk?.x, "string");
    assert.equal(typeof recipient.encrypted_key, "string");
  }
});

test("multiple recipients and a later subscriber key can open ciphertext", async () => {
  const first = jwe.keygen();
  const second = jwe.keygen();
  const stranger = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("many"), [first.publicKey, second.publicKey]);

  assert.deepEqual(await jwe.subscribe([first.privateKey]).decrypt(ciphertext), bytes("many"));
  assert.deepEqual(
    await jwe.subscribe([stranger.privateKey, second.privateKey]).decrypt(ciphertext),
    bytes("many"),
  );
});

test("multi-key detailed decrypt parses and validates ciphertext only once", async () => {
  const intended = jwe.keygen();
  const stranger = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("parse once"), [intended.publicKey]);
  const strangerJwk = okpPrivateJwk(stranger.publicKey, stranger.privateKey);
  const mutatingStranger: JWK = {
    ...strangerJwk,
    get kty() {
      ciphertext.fill(0);
      return strangerJwk.kty;
    },
  };

  const outcome = await jweDecryptManyDetailed(
    [mutatingStranger, okpPrivateJwk(intended.publicKey, intended.privateKey)],
    ciphertext,
  );
  assert.equal(outcome.status, "opened");
  if (outcome.status === "opened") assert.deepEqual(outcome.plaintext, bytes("parse once"));
});

test("subscriber maps AAD mismatch and missing entitlement to stable errors", async () => {
  const keys = jwe.keygen();
  const stranger = jwe.keygen();
  const aad = bytes("expected aad");
  const ciphertext = await jwe.encrypt(bytes("secret"), [keys.publicKey], aad);
  const reader = jwe.subscribe([keys.privateKey]);

  assert.deepEqual(await reader.decrypt(ciphertext, aad), bytes("secret"));
  await assert.rejects(reader.decrypt(ciphertext, bytes("changed aad")), AuthenticationFailedError);
  await assert.rejects(reader.decrypt(ciphertext), AuthenticationFailedError);
  await assert.rejects(
    jwe.subscribe([stranger.privateKey]).decrypt(ciphertext, aad),
    NotEntitledError,
  );
  await assert.rejects(
    jwe.subscribe([stranger.privateKey]).decrypt(ciphertext, bytes("changed aad")),
    AuthenticationFailedError,
  );
});

test("malformed JSON, profiles, and later recipient entries fail closed", async () => {
  const keys = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("secret"), [keys.publicKey]);
  const reader = jwe.subscribe([keys.privateKey]);

  await assert.rejects(reader.decrypt(bytes("not json")), MalformedError);
  await assert.rejects(
    reader.decrypt(
      rewriteWire(ciphertext, (wire) => {
        wire.recipients[0]!.header!.alg = "dir";
      }),
    ),
    MalformedError,
  );
  await assert.rejects(
    reader.decrypt(
      rewriteWire(ciphertext, (wire) => {
        wire.recipients.push({ encrypted_key: "", header: { alg: JWE_ALG } });
      }),
    ),
    MalformedError,
  );
});

test("strict profile rejects duplicate, null, and unsupported JOSE members", async () => {
  const keys = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("secret"), [keys.publicKey]);
  const reader = jwe.subscribe([keys.privateKey]);
  const invalid: [string, Uint8Array][] = [
    [
      "unsupported protected member",
      rewriteWire(ciphertext, (wire) => {
        const header = protectedHeader(wire);
        header.zip = "DEF";
        setProtectedHeader(wire, header);
      }),
    ],
    [
      "duplicated alg",
      rewriteWire(ciphertext, (wire) => {
        const header = protectedHeader(wire);
        header.alg = JWE_ALG;
        setProtectedHeader(wire, header);
      }),
    ],
    [
      "explicit null shared header",
      rewriteWire(ciphertext, (wire) => {
        wire.unprotected = null;
      }),
    ],
    [
      "unsupported recipient member",
      rewriteWire(ciphertext, (wire) => {
        wire.recipients[0]!.header!.kid = "reader";
      }),
    ],
    [
      "unsupported top-level member",
      rewriteWire(ciphertext, (wire) => {
        wire.kid = "reader";
      }),
    ],
  ];

  for (const [label, blob] of invalid) {
    await assert.rejects(reader.decrypt(blob), MalformedError, label);
  }
});

test("a low-order epk in a later recipient makes the whole profile malformed", async () => {
  const first = jwe.keygen();
  const second = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("secret"), [first.publicKey, second.publicKey]);
  const malformed = rewriteWire(ciphertext, (wire) => {
    wire.recipients[1]!.header!.epk!.x = Buffer.alloc(32).toString("base64url");
  });

  await assert.rejects(jwe.subscribe([first.privateKey]).decrypt(malformed), MalformedError);
});

test("empty and non-32-byte key collections are malformed", async () => {
  await assert.rejects(jwe.encrypt(bytes("secret"), []), MalformedError);
  assert.throws(() => jwe.subscribe([]), MalformedError);
  await assert.rejects(jwe.encrypt(bytes("secret"), [new Uint8Array(32)]), MalformedError);

  for (const length of [31, 33]) {
    await assert.rejects(jwe.encrypt(bytes("secret"), [new Uint8Array(length)]), MalformedError);
    assert.throws(() => jwe.subscribe([new Uint8Array(length)]), MalformedError);
  }
});

test("recipient and private-key iterables stop at the 1,025th item", async () => {
  const keys = jwe.keygen();
  const recipients = guardedInfinite(keys.publicKey);
  const readers = guardedInfinite(keys.privateKey);

  await assert.rejects(jwe.encrypt(bytes("secret"), recipients.iterable), LimitExceededError);
  assert.equal(recipients.pulls(), 1_025);
  assert.throws(() => jwe.subscribe(readers.iterable), LimitExceededError);
  assert.equal(readers.pulls(), 1_025);
});

test("encrypt rejects non-byte payloads and oversized plaintext or AAD", async () => {
  const keys = jwe.keygen();
  await assert.rejects(
    jwe.encrypt("secret" as unknown as Uint8Array, [keys.publicKey]),
    MalformedError,
  );
  await assert.rejects(
    jwe.encrypt(bytes("secret"), [keys.publicKey], "aad" as unknown as Uint8Array),
    MalformedError,
  );
  await assert.rejects(
    jwe.encrypt(bytes("secret"), [keys.publicKey], new Uint8Array(64 * 1024 + 1)),
    LimitExceededError,
  );
  await assert.rejects(
    jwe.encrypt(new Uint8Array(64 * 1024 * 1024 + 1), [keys.publicKey]),
    LimitExceededError,
  );
});

test("decrypt rejects non-byte ciphertext and AAD before trying subscriber keys", async () => {
  const keys = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("secret"), [keys.publicKey]);
  const reader = jwe.subscribe([keys.privateKey]);

  await assert.rejects(reader.decrypt(ciphertext, "aad" as unknown as Uint8Array), MalformedError);
  await assert.rejects(
    reader.decrypt(ciphertext, new Uint8Array(64 * 1024 + 1)),
    LimitExceededError,
  );
  await assert.rejects(reader.decrypt(new OversizedCiphertext()), LimitExceededError);
  await assert.rejects(reader.decrypt("ciphertext" as unknown as Uint8Array), MalformedError);
});

test("legacy invalid-reader import errors are sanitized and retain their cause", async () => {
  const keys = jwe.keygen();
  const ciphertext = await jwe.encrypt(bytes("secret"), [keys.publicKey]);
  const invalidReader = {
    kty: "OKP",
    crv: "X25519",
    x: "not-base64url",
    d: "not-base64url",
  };

  await assert.rejects(jweDecrypt(invalidReader, ciphertext), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, "jwe: failed to import reader key for TN profile");
    assert.ok(error.cause instanceof Error);
    return true;
  });
});
