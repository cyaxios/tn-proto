import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { BrowserRuntime } from "../src/browser/runtime.js";
import { memoryStorageAdapter } from "../src/runtime/storage_memory.js";
import { deviceKeyFromSeed, jweKeygen } from "../src/raw.js";

test("BrowserRuntime exposes Rust/WASM JWE seal and unseal", () => {
  const storage = memoryStorageAdapter();
  const seed = new Uint8Array(32).fill(7);
  const device = deviceKeyFromSeed(seed);
  const reader = jweKeygen() as { publicKey: Uint8Array; privateKey: Uint8Array };
  const publicKeyB64 = Buffer.from(reader.publicKey).toString("base64");

  storage.write("/v/keys/local.private", seed);
  storage.write("/v/keys/index_master.key", new Uint8Array(32).fill(11));
  storage.write("/v/keys/default.jwe.mykey", reader.privateKey);
  storage.write(
    "/v/keys/default.jwe.recipients",
    new TextEncoder().encode(
      JSON.stringify([{ recipient_identity: device.did, pub_b64: publicKeyB64 }]),
    ),
  );
  storage.write(
    "/v/tn.yaml",
    new TextEncoder()
      .encode(`ceremony: {id: cer_browser_jwe, mode: local, cipher: jwe, protocol_events_location: main_log}
keystore: {path: /v/keys}
device: {device_identity: "${device.did}"}
public_fields: []
default_policy: private
groups:
  default:
    policy: private
    cipher: jwe
    recipients:
      - {recipient_identity: "${device.did}", pub_b64: "${publicKeyB64}"}
    index_epoch: 0
fields: {}
llm_classifier: {enabled: false, provider: "", model: ""}
`),
  );

  const runtime = BrowserRuntime.init({ storage, yamlPath: "/v/tn.yaml", console: false });
  try {
    const sealed = runtime.seal(
      "case.created",
      { amount: 42, note: "sealed in Rust" },
      { receipt: false, aad: { tenant: "acme" } },
    );
    assert.deepEqual(sealed.envelope, JSON.parse(sealed.wire));

    const block = sealed.envelope["default"] as { ciphertext: string };
    const jwe = JSON.parse(Buffer.from(block.ciphertext, "base64").toString("utf8")) as {
      protected: string;
      recipients: Array<{ header: { alg: string } }>;
    };
    assert.equal(jwe.recipients[0]?.header.alg, "ECDH-ES+A256KW");
    assert.deepEqual(JSON.parse(Buffer.from(jwe.protected, "base64url").toString("utf8")), {
      enc: "A256GCM",
    });

    const opened = runtime.unseal(sealed.wire, { verify: true });
    assert.deepEqual(opened.plaintext["default"], {
      amount: 42,
      note: "sealed in Rust",
    });
    assert.deepEqual(opened.hidden_groups, []);
    assert.deepEqual(opened.valid, { signature: true, row_hash: true });
  } finally {
    void runtime.close();
  }
});
