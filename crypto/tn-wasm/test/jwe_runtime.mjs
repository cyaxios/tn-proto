import assert from "node:assert/strict";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { deviceKeyFromSeed, jweKeygen, WasmRuntime } from "../pkg/tn_wasm.js";

function storage() {
  return {
    read: (path) => new Uint8Array(readFileSync(path)),
    write(path, data) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data);
    },
    append(path, data) {
      mkdirSync(dirname(path), { recursive: true });
      appendFileSync(path, data);
    },
    exists: existsSync,
    list: (path) => readdirSync(path).map((name) => join(path, name)),
    rename: renameSync,
    remove: unlinkSync,
    createDirAll: (path) => mkdirSync(path, { recursive: true }),
    casWrite(path, prior, data) {
      const current = existsSync(path) ? new Uint8Array(readFileSync(path)) : null;
      assert.deepEqual(current, prior);
      writeFileSync(path, data);
    },
  };
}

const root = mkdtempSync(join(tmpdir(), "tn-wasm-jwe-"));
const keys = join(root, ".tn", "keys");
mkdirSync(keys, { recursive: true });

const seed = new Uint8Array(32).fill(7);
const device = deviceKeyFromSeed(seed);
const reader = jweKeygen();
writeFileSync(join(keys, "local.private"), seed);
writeFileSync(join(keys, "index_master.key"), new Uint8Array(32).fill(11));
writeFileSync(join(keys, "default.jwe.mykey"), reader.privateKey);
writeFileSync(
  join(keys, "default.jwe.recipients"),
  JSON.stringify([
    {
      recipient_identity: device.did,
      pub_b64: Buffer.from(reader.publicKey).toString("base64"),
    },
  ]),
);

const yamlPath = join(root, "tn.yaml");
writeFileSync(
  yamlPath,
  `ceremony: {id: cer_wasm_jwe, mode: local, cipher: jwe, protocol_events_location: main_log}
keystore: {path: ./.tn/keys}
device: {device_identity: "${device.did}"}
public_fields: []
default_policy: private
groups:
  default:
    policy: private
    cipher: jwe
    recipients:
      - {recipient_identity: "${device.did}", pub_b64: "${Buffer.from(reader.publicKey).toString("base64")}"}
    index_epoch: 0
fields: {}
llm_classifier: {enabled: false, provider: "", model: ""}
`,
);

const runtime = WasmRuntime.initWith(yamlPath, storage(), {
  skipCeremonyInitEmit: true,
  skipPolicyPublishedEmit: true,
});

try {
  const sealed = runtime.seal(
    "case.created",
    { amount: 42, note: "sealed in Rust" },
    { receipt: false, aad: { tenant: "acme" } },
  );
  const envelope = JSON.parse(sealed.wire);
  const jwe = JSON.parse(Buffer.from(envelope.default.ciphertext, "base64").toString());
  assert.equal(jwe.recipients.length, 1);
  assert.equal(jwe.recipients[0].header.alg, "ECDH-ES+A256KW");

  const opened = runtime.unseal(sealed.wire, { verify: true });
  assert.deepEqual(opened.plaintext.default, { amount: 42, note: "sealed in Rust" });
  assert.deepEqual(opened.hidden_groups, []);

  runtime.emit("info", "case.logged", { amount: 7, note: "read in Rust" });
  const row = runtime.read().find((entry) => entry.event_type === "case.logged");
  assert.equal(row.amount, 7);
  assert.equal(row.note, "read in Rust");
} finally {
  runtime.close();
  rmSync(root, { recursive: true, force: true });
}

console.log("tn-wasm JWE runtime seal/unseal/read: ok");
