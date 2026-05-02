// Alice s07 — route fields into pii / ops / finance groups.
//
// Python original: python/scenarios/alice/s07_field_routing.py
//
// Previously skipped on a WRONG diagnosis ("TS admin API gap"). The TS SDK
// supports yaml-driven multi-group ceremonies. We set up the ceremony by
// writing a tn.yaml (with three groups + field routing) and loading it via
// Tn.init(yamlPath) — same pattern as test/multi_group_routing.test.ts.
//
// Verification:
//   - 100 user.signup events emitted with email, ip, amount, country, latency_ms.
//   - pii  group:     email, ip
//   - ops  group:     latency_ms, country
//   - finance group:  amount
//   - Each entry's plaintext buckets decode to the expected values.

import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { DeviceKey, NodeRuntime } from "../../../src/index.js";
import { BtnPublisher } from "../../../src/raw.js";

const GROUP_NAMES = ["default", "pii", "ops", "finance"];

function makeS07Ceremony(): {
  yamlPath: string;
  dir: string;
  cleanup: () => void;
} {
  const dir = mkdtempSync(join(tmpdir(), "tn-s07-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  // Device key.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 7;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");

  // Index master.
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i++) indexMaster[i] = (i * 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  // One BtnPublisher per group.
  for (let g = 0; g < GROUP_NAMES.length; g++) {
    const gname = GROUP_NAMES[g]!;
    const btnSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) btnSeed[i] = (i * 11 + 3 + g * 17) & 0xff;
    const pub = new BtnPublisher(btnSeed);
    const kit = pub.mint();
    writeFileSync(join(keys, `${gname}.btn.state`), Buffer.from(pub.toBytes()));
    writeFileSync(join(keys, `${gname}.btn.mykit`), Buffer.from(kit));
  }

  const did = dk.did;
  const yaml = [
    "ceremony:",
    "  id: s07_field_routing",
    "  mode: local",
    "  cipher: btn",
    `logs:`,
    `  path: ./.tn/logs/tn.ndjson`,
    `keystore:`,
    `  path: ./.tn/keys`,
    `me:`,
    `  did: ${did}`,
    "public_fields:",
    "- timestamp",
    "- event_id",
    "- event_type",
    "- level",
    "default_policy: private",
    "groups:",
    "  default:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${did}`,
    "  pii:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${did}`,
    "    fields:",
    "    - email",
    "    - ip",
    "  ops:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${did}`,
    "    fields:",
    "    - latency_ms",
    "    - country",
    "  finance:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `    - did: ${did}`,
    "    fields:",
    "    - amount",
    "fields: {}",
    "",
  ].join("\n");

  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("alice/s07_field_routing — yaml-driven groups + field routing, 100 user.signup events", () => {
  const ceremony = makeS07Ceremony();
  try {
    const rt = NodeRuntime.init(ceremony.yamlPath);

    // Emit 100 user.signup events.
    for (let i = 0; i < 100; i++) {
      rt.emit("info", "user.signup", {
        email: `u${i}@ex.com`,
        ip: "10.0.0.1",
        amount: 1000 + i,
        country: "ES",
        latency_ms: 42,
      });
    }

    const entries = Array.from(rt.read()).filter(
      (e) => e.envelope["event_type"] === "user.signup",
    );

    assert.equal(entries.length, 100, `expected 100 user.signup entries, got ${entries.length}`);

    let piiOk = true;
    let opsOk = true;
    let finOk = true;
    let chainOk = true;
    let sigOk = true;

    for (let idx = 0; idx < entries.length; idx++) {
      const e = entries[idx]!;

      chainOk = chainOk && Boolean(e.valid.chain);
      sigOk = sigOk && Boolean(e.valid.signature);

      const pii = (e.plaintext["pii"] ?? {}) as Record<string, unknown>;
      const ops = (e.plaintext["ops"] ?? {}) as Record<string, unknown>;
      const fin = (e.plaintext["finance"] ?? {}) as Record<string, unknown>;

      // pii group: email + ip
      if (pii["email"] !== `u${idx}@ex.com` || pii["ip"] !== "10.0.0.1") {
        piiOk = false;
      }

      // ops group: latency_ms + country
      if (ops["latency_ms"] !== 42 || ops["country"] !== "ES") {
        opsOk = false;
      }

      // finance group: amount
      if (fin["amount"] !== 1000 + idx) {
        finOk = false;
      }

      // default group should NOT contain the routed fields
      const def = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
      assert.ok(
        !("email" in def),
        `email should NOT appear in default group at idx=${idx}`,
      );
      assert.ok(
        !("amount" in def),
        `amount should NOT appear in default group at idx=${idx}`,
      );
    }

    assert.ok(chainOk, "chain integrity failed for one or more entries");
    assert.ok(sigOk, "signature verification failed for one or more entries");
    assert.ok(
      piiOk,
      "pii group decryption mismatch (email or ip wrong for some entry)",
    );
    assert.ok(
      opsOk,
      "ops group decryption mismatch (latency_ms or country wrong for some entry)",
    );
    assert.ok(
      finOk,
      "finance group decryption mismatch (amount wrong for some entry)",
    );
  } finally {
    ceremony.cleanup();
  }
});
