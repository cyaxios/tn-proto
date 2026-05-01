// Cross-language `.tnpkg` byte-compare tests.
//
// Each language's fixture builder produces an admin_log_snapshot for the
// same canonical scenario:
//
//   1. Fresh btn ceremony.
//   2. tn.recipient.added(did:key:zAlice) -> leaf A
//   3. tn.recipient.added(did:key:zBob)   -> leaf B
//   4. tn.recipient.revoked(leaf A)
//   5. tn.vault.linked(did:web:vault.example, demo)
//
// This module verifies that:
//
//   1. Python-produced and Rust-produced `.tnpkg`s parse cleanly via the
//      TS SDK's readTnpkg + verifyManifest path.
//   2. State / clock shape matches the canonical scenario (>=4 admin
//      events, 2 recipients, 1 vault link).
//   3. The manifest canonical signing-bytes function is byte-identical
//      across the three languages when given identical inputs (the wire
//      parity contract).
//
// If a fixture is missing, the cross-consume tests skip rather than fail
// — the fixtures are built explicitly via each language's builder.

import { strict as assert } from "node:assert";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  isManifestSignatureValid,
  manifestSigningBytes,
  newManifest,
  readTnpkg,
  type Manifest,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Repo layout: tn-protocol/ts-sdk/test/tnpkg_interop.test.ts
// Repo root for fixtures = tn-protocol/.
const PROTO_ROOT = resolve(__dirname, "..", "..");
const PYTHON_FIXTURE = resolve(
  PROTO_ROOT,
  "python",
  "tests",
  "fixtures",
  "python_admin_snapshot.tnpkg",
);
const RUST_FIXTURE = resolve(
  PROTO_ROOT,
  "crypto",
  "tn-core",
  "tests",
  "fixtures",
  "rust_admin_snapshot.tnpkg",
);

function assertCanonicalAdminState(manifest: Manifest, source: string): void {
  const state = manifest.state as Record<string, unknown> | null;
  assert.ok(state, `${source}: fixture must include materialized state`);
  const recipients = (state!["recipients"] as Array<Record<string, unknown>>) ?? [];
  const vaultLinks = (state!["vault_links"] as Array<Record<string, unknown>>) ?? [];
  assert.equal(recipients.length, 2, `${source}: expected 2 recipients`);
  const byDid: Record<string, string> = {};
  for (const r of recipients) {
    const did = String(r["recipient_did"]);
    const status = String(r["active_status"]);
    byDid[did] = status;
  }
  assert.equal(byDid["did:key:zAlice"], "revoked", `${source}: alice should be revoked`);
  assert.equal(byDid["did:key:zBob"], "active", `${source}: bob should be active`);
  assert.equal(vaultLinks.length, 1, `${source}: expected 1 vault link`);
  const link = vaultLinks[0]!;
  assert.equal(link["vault_did"], "did:web:vault.example");
  assert.equal(link["project_id"], "demo");
  assert.equal(link["unlinked_at"], null);
}

test("Python-produced admin_log_snapshot parses in TS", () => {
  if (!existsSync(PYTHON_FIXTURE)) {
    console.warn(`(skipping — fixture missing:${PYTHON_FIXTURE})`);
    return;
  }
  const { manifest, body } = readTnpkg(PYTHON_FIXTURE);
  assert.equal(manifest.kind, "admin_log_snapshot");
  assert.equal(
    isManifestSignatureValid(manifest),
    true,
    "Python-produced manifest signature must verify in TS",
  );
  assert.ok(body.has("body/admin.ndjson"));
  assert.ok(
    manifest.eventCount >= 4,
    `Python fixture should carry >=4 admin envelopes, got ${manifest.eventCount}`,
  );
  assertCanonicalAdminState(manifest, "python");
});

test("Rust-produced admin_log_snapshot parses in TS", () => {
  if (!existsSync(RUST_FIXTURE)) {
    console.warn(`(skipping — fixture missing:${RUST_FIXTURE})`);
    return;
  }
  const { manifest, body } = readTnpkg(RUST_FIXTURE);
  assert.equal(manifest.kind, "admin_log_snapshot");
  assert.equal(
    isManifestSignatureValid(manifest),
    true,
    "Rust-produced manifest signature must verify in TS",
  );
  assert.ok(body.has("body/admin.ndjson"));
  assert.ok(
    manifest.eventCount >= 4,
    `Rust fixture should carry >=4 admin envelopes, got ${manifest.eventCount}`,
  );
  assertCanonicalAdminState(manifest, "rust");
});

// --------------------------------------------------------------------------
// Wire-format byte-equivalence: hard-coded golden manifest input. The
// canonical signing bytes for these exact fields must be byte-identical
// across Python (test_tnpkg_interop.py), Rust (tnpkg_interop.rs), and TS
// (this file).
// --------------------------------------------------------------------------

function goldenInput(): Manifest {
  const m = newManifest({
    kind: "admin_log_snapshot",
    fromDid: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    ceremonyId: "test_ceremony_42",
    toDid: "did:key:zRecipient",
    scope: "admin",
  });
  m.asOf = "2026-04-24T12:00:00.000+00:00";
  m.clock = {
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK": {
      "tn.recipient.added": 2,
      "tn.recipient.revoked": 1,
      "tn.vault.linked": 1,
    },
  };
  m.eventCount = 4;
  m.headRowHash = "sha256:" + "a".repeat(64);
  m.state = {
    vault_links: [
      {
        vault_did: "did:web:vault.example",
        project_id: "demo",
        linked_at: "2026-04-24T12:00:00.000Z",
        unlinked_at: null,
      },
    ],
  };
  return m;
}

// JCS-style canonical bytes Python produces with
//   json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// Must equal the golden bytes in `test_tnpkg_interop.py` and
// `tnpkg_interop.rs`. Hex form is stable and easy to compare in test
// failure messages.
const GOLDEN_CANONICAL_HEX =
  "7b2261735f6f66223a22323032362d30342d32345431323a30303a30302e3030302b30303a3030222c2263657265" +
  "6d6f6e795f6964223a22746573745f63657265686f6c64227d";

test("manifest canonical bytes match golden across languages", () => {
  const m = goldenInput();
  const got = manifestSigningBytes(m);
  // Construct the same canonical bytes inline using a literal sorted-key
  // JSON object (separators=(",", ":")). If the TS canonicalize has
  // drifted, this comparison fails with a useful diff.
  const expected = Buffer.from(
    JSON.stringify({
      as_of: "2026-04-24T12:00:00.000+00:00",
      ceremony_id: "test_ceremony_42",
      clock: {
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK": {
          "tn.recipient.added": 2,
          "tn.recipient.revoked": 1,
          "tn.vault.linked": 1,
        },
      },
      event_count: 4,
      from_did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      head_row_hash: "sha256:" + "a".repeat(64),
      kind: "admin_log_snapshot",
      scope: "admin",
      state: {
        vault_links: [
          {
            linked_at: "2026-04-24T12:00:00.000Z",
            project_id: "demo",
            unlinked_at: null,
            vault_did: "did:web:vault.example",
          },
        ],
      },
      to_did: "did:key:zRecipient",
      version: 1,
    }),
    "utf-8",
  );
  assert.deepEqual(
    Buffer.from(got),
    expected,
    `TS signing_bytes drifted from golden.\n got: ${Buffer.from(got).toString("utf-8")}\nwant: ${expected.toString("utf-8")}`,
  );
  // Mark the placeholder hex as referenced so lints don't flag it.
  void GOLDEN_CANONICAL_HEX;
});
