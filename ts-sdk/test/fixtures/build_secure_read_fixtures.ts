// Generate the TS-produced cross-language byte-compare fixtures for the
// new `tn.read()` flat shape, `client.secureRead()` output, and
// `tn.agents` group pre-encryption canonical bytes.
//
// Spec: docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md
// section 5.4 (cross-language byte-identity).
//
// Two fixtures are emitted (mirrored byte-for-byte by the Python + Rust
// builders):
//
//     secure_read_canonical.json
//         Canonical JSON of `flattenRawEntry(...) + attachInstructions(...)`
//         applied to the canonical scenario raw entries — the dict shape
//         `client.secureRead()` hands to the LLM. Same envelope +
//         plaintext input must produce byte-identical canonical-JSON
//         output across Python / Rust / TS.
//
//     tn_agents_pre_encryption.json
//         Canonical bytes of the six-field policy splice payload for
//         `payment.completed`. This is the cipher's input; random AEAD
//         nonces make the post-encryption ciphertext diverge per row,
//         but the canonical PRE-encryption bytes (what gets passed to
//         `cipher.encrypt(...)`) must agree across languages, byte for
//         byte.
//
// Run with:
//
//     cd tn-protocol/ts-sdk
//     node --import tsx test/fixtures/build_secure_read_fixtures.ts
//
// Re-running overwrites the fixtures.

import { Buffer } from "node:buffer";
import { statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAdminEventsCanonical,
  buildSecureReadCanonical,
  buildTnAgentsPreEncryption,
  canonicalJsonBytes,
} from "./secure_read_canonical_scenario.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function writeFixture(name: string, value: unknown): number {
  const raw = canonicalJsonBytes(value);
  const path = resolve(__dirname, name);
  writeFileSync(path, Buffer.from(raw));
  return statSync(path).size;
}

function main(): void {
  const secNbytes = writeFixture(
    "secure_read_canonical.json",
    buildSecureReadCanonical(),
  );
  // eslint-disable-next-line no-console
  console.log(
    `wrote ${resolve(__dirname, "secure_read_canonical.json")} (${secNbytes} bytes)`,
  );

  const preNbytes = writeFixture(
    "tn_agents_pre_encryption.json",
    buildTnAgentsPreEncryption(),
  );
  // eslint-disable-next-line no-console
  console.log(
    `wrote ${resolve(__dirname, "tn_agents_pre_encryption.json")} (${preNbytes} bytes)`,
  );

  const adminNbytes = writeFixture(
    "admin_events_canonical.json",
    buildAdminEventsCanonical(),
  );
  // eslint-disable-next-line no-console
  console.log(
    `wrote ${resolve(__dirname, "admin_events_canonical.json")} (${adminNbytes} bytes)`,
  );
}

main();
