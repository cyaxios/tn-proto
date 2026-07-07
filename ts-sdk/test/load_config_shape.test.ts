// Characterization tests for loadConfig (the CC-62 yaml loader in
// src/runtime/config.ts). Written BEFORE decomposing it into helpers so the
// extracted pieces must preserve every branch's observable behavior:
//   - legacy `me:` rejection
//   - reserved `tn.*` group-name rejection (tn.agents allowed)
//   - per-group `fields:` routing vs the legacy flat `fields:` block (+ warn)
//   - routed-to-unknown-group and public/group-overlap validation errors
//   - non-string field-entry rejection
//   - cipher inheritance, recipient tolerant-read, handlers passthrough,
//     default-group injection, deterministic group-list sort, log_level.
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadConfig } from "../src/runtime/config.js";

function withConfig<T>(yaml: string, fn: (path: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "tn-cfg-shape-"));
  try {
    const yamlPath = join(dir, "tn.yaml");
    writeFileSync(yamlPath, yaml, "utf8");
    return fn(yamlPath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const BASE =
  "ceremony:\n" +
  "  id: cer-1\n" +
  "  mode: local\n" +
  "  cipher: btn\n" +
  "device:\n" +
  "  device_identity: did:key:zDEV\n";

test("minimal config exposes core scalars and injects a default group", () => {
  withConfig(BASE, (p) => {
    const cfg = loadConfig(p);
    assert.equal(cfg.ceremonyId, "cer-1");
    assert.equal(cfg.mode, "local");
    assert.equal(cfg.cipher, "btn");
    assert.equal(cfg.device.device_identity, "did:key:zDEV");
    assert.equal(cfg.defaultPolicy, "private");
    assert.ok(cfg.groups.has("default"), "default group auto-injected");
    // default group recipient is the device identity when present
    assert.equal(cfg.groups.get("default")!.recipients[0]!.did, "did:key:zDEV");
  });
});

test("legacy `me:` top-level block (without device) is rejected", () => {
  const yaml = "ceremony:\n  id: c\n  cipher: btn\nme:\n  did: did:key:zOLD\n";
  withConfig(yaml, (p) => {
    assert.throws(
      () => loadConfig(p),
      (e: Error) => e.message.includes("legacy") && e.message.includes("me:"),
    );
  });
});

test("reserved tn.* group name is rejected", () => {
  const yaml = BASE + "groups:\n  tn.secrets:\n    policy: private\n";
  withConfig(yaml, (p) => {
    assert.throws(
      () => loadConfig(p),
      (e: Error) => e.message.includes("reserved group name") && e.message.includes("tn.secrets"),
    );
  });
});

test("tn.agents is the one allowed reserved group", () => {
  const yaml = BASE + "groups:\n  tn.agents:\n    policy: private\n";
  withConfig(yaml, (p) => {
    const cfg = loadConfig(p);
    assert.ok(cfg.groups.has("tn.agents"));
  });
});

test("per-group fields: block populates fieldToGroups (no deprecation warn)", () => {
  const yaml =
    BASE +
    "groups:\n" +
    "  payments:\n" +
    "    policy: private\n" +
    "    fields: [amount, account]\n";
  withConfig(yaml, (p) => {
    const warns: string[] = [];
    const orig = console.warn;
    console.warn = (m?: unknown) => warns.push(String(m));
    try {
      const cfg = loadConfig(p);
      assert.deepEqual(cfg.fieldToGroups.get("amount"), ["payments"]);
      assert.deepEqual(cfg.fieldToGroups.get("account"), ["payments"]);
      assert.equal(warns.length, 0, "per-group form must not warn");
    } finally {
      console.warn = orig;
    }
  });
});

test("legacy flat fields: block routes and emits a deprecation warning", () => {
  const yaml =
    BASE +
    "groups:\n  payments:\n    policy: private\n" +
    "fields:\n  amount: payments\n";
  withConfig(yaml, (p) => {
    const warns: string[] = [];
    const orig = console.warn;
    console.warn = (m?: unknown) => warns.push(String(m));
    try {
      const cfg = loadConfig(p);
      assert.deepEqual(cfg.fieldToGroups.get("amount"), ["payments"]);
      assert.ok(
        warns.some((w) => w.includes("deprecated")),
        "flat fields: block must warn",
      );
    } finally {
      console.warn = orig;
    }
  });
});

test("flat fields: {group: name} object form is accepted", () => {
  const yaml =
    BASE +
    "groups:\n  payments:\n    policy: private\n" +
    "fields:\n  amount:\n    group: payments\n";
  withConfig(yaml, (p) => {
    const cfg = loadConfig(p);
    assert.deepEqual(cfg.fieldToGroups.get("amount"), ["payments"]);
  });
});

test("field routed to an unknown group throws", () => {
  const yaml =
    BASE +
    "groups:\n  payments:\n    policy: private\n" +
    "fields:\n  amount: nonexistent\n";
  withConfig(yaml, (p) => {
    assert.throws(
      () => loadConfig(p),
      (e: Error) => e.message.includes("unknown") && e.message.includes("nonexistent"),
    );
  });
});

test("a field both public and group-routed throws", () => {
  const yaml =
    BASE +
    "groups:\n  payments:\n    policy: private\n    fields: [amount]\n" +
    "public_fields: [amount]\n";
  withConfig(yaml, (p) => {
    assert.throws(
      () => loadConfig(p),
      (e: Error) => e.message.includes("both") && e.message.includes("amount"),
    );
  });
});

test("non-string entry in a group's fields: list throws", () => {
  const yaml =
    BASE + "groups:\n  payments:\n    policy: private\n    fields: [123]\n";
  withConfig(yaml, (p) => {
    assert.throws(
      () => loadConfig(p),
      (e: Error) => e.message.includes("must be strings"),
    );
  });
});

test("group without an explicit cipher inherits ceremony.cipher", () => {
  // "jwe" (not the "btn" default) proves inheritance actually happened.
  // Cipher names are validated at load since the hibe wiring (mirroring
  // Python config.py: expected 'jwe', 'btn', or 'hibe'), so a fabricated
  // name is no longer a usable probe here — see the companion test below.
  const yaml =
    "ceremony:\n  id: c\n  cipher: jwe\n" +
    "device:\n  device_identity: did:key:zDEV\n" +
    "groups:\n  g:\n    policy: private\n";
  withConfig(yaml, (p) => {
    const cfg = loadConfig(p);
    assert.equal(cfg.groups.get("g")!.cipher, "jwe");
  });
});

test("unknown cipher names are rejected at load (Python parity)", () => {
  const yaml =
    "ceremony:\n  id: c\n  cipher: aesgcm\n" +
    "device:\n  device_identity: did:key:zDEV\n" +
    "groups:\n  g:\n    policy: private\n";
  withConfig(yaml, (p) => {
    assert.throws(
      () => loadConfig(p),
      (e: Error) => e.message.includes("expected 'jwe', 'btn', or 'hibe'"),
    );
  });
});

test("recipients accept both recipient_identity and legacy did", () => {
  const yaml =
    BASE +
    "groups:\n" +
    "  g:\n" +
    "    policy: private\n" +
    "    recipients:\n" +
    "      - recipient_identity: did:key:zNEW\n" +
    "      - did: did:key:zLEGACY\n";
  withConfig(yaml, (p) => {
    const cfg = loadConfig(p);
    const dids = cfg.groups.get("g")!.recipients.map((r) => r.did);
    assert.deepEqual(dids, ["did:key:zNEW", "did:key:zLEGACY"]);
  });
});

test("handlers passthrough filters out non-object entries", () => {
  const yaml =
    BASE +
    "handlers:\n" +
    "  - type: stdout\n" +
    "  - just-a-string\n";
  withConfig(yaml, (p) => {
    const cfg = loadConfig(p);
    assert.equal(cfg.handlers.length, 1);
    assert.equal((cfg.handlers[0] as Record<string, unknown>).type, "stdout");
  });
});

test("a field shared across two groups is sorted deterministically", () => {
  const yaml =
    BASE +
    "groups:\n" +
    "  bravo:\n    policy: private\n    fields: [shared]\n" +
    "  alpha:\n    policy: private\n    fields: [shared]\n";
  withConfig(yaml, (p) => {
    const cfg = loadConfig(p);
    assert.deepEqual(cfg.fieldToGroups.get("shared"), ["alpha", "bravo"]);
  });
});

test("log_level is set on the config only when present and non-empty", () => {
  const withLevel = BASE.replace("  cipher: btn\n", "  cipher: btn\n  log_level: debug\n");
  withConfig(withLevel, (p) => {
    assert.equal(loadConfig(p).logLevel, "debug");
  });
  withConfig(BASE, (p) => {
    assert.equal(loadConfig(p).logLevel, undefined);
  });
});
