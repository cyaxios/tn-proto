// Characterization tests for absorbSealedBootstrap (the CC-42 sealed-bundle
// absorb entry in src/runtime/absorb_bootstrap.ts). Written BEFORE decomposing
// it so the extracted helpers must preserve every rejection/branch:
//   - malformed zip -> kind "" rejection
//   - bad seed length
//   - tampered manifest signature
//   - wraps present but none addressed to us (candidates empty)
//   - matching candidate but unseal fails (bek stays null)
//   - body_encryption declared but body/encrypted.bin missing
//   - unsupported kind (not identity_seed/project_seed)
//   - happy path: valid project_seed seals + installs
//
// Bundle recipe mirrors scripts/_sealed_absorb_smoke.mjs.
import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DeviceKey,
  absorbSealedBootstrap,
  encryptBodyBlob,
  manifestAadForWrap,
  packTnpkg,
  sealBekForRecipient,
  signManifest,
  toWireDict,
} from "../src/index.js";
import { fromWireDict, newManifest } from "../src/core/tnpkg.js";

interface BuildOpts {
  kind?: string;
  wrapRecipientDid?: string; // who the wrap is sealed FOR (defaults to bearer)
  relabelWrapTo?: string; // override recipient_identity after sealing
  omitEncrypted?: boolean;
  tamperCeremonyId?: boolean; // mutate manifest after signing -> bad signature
}

// Build a sealed project_seed (or other-kind) tnpkg addressed to `bearer`.
async function buildSealed(
  publisher: DeviceKey,
  bearer: DeviceKey,
  opts: BuildOpts = {},
): Promise<Uint8Array> {
  const kind = opts.kind ?? "project_seed";
  const yamlText =
    `ceremony:\n  id: smoke_test\n  mode: linked\nkeystore:\n  path: ./.tn/keys\n` +
    `logs:\n  path: ./.tn/logs/tn.ndjson\ndevice:\n  device_identity: ${publisher.did}\n`;
  const bodyMap = new Map<string, Uint8Array>();
  bodyMap.set("body/tn.yaml", new TextEncoder().encode(yamlText));
  bodyMap.set("body/keys/local.private", publisher.seed);
  bodyMap.set("body/keys/local.public", new TextEncoder().encode(publisher.did));

  const bek = new Uint8Array(32);
  crypto.getRandomValues(bek);
  const encrypted = await encryptBodyBlob(bodyMap, bek);

  const baseManifest = newManifest({
    kind,
    fromDid: publisher.did,
    ceremonyId: "smoke_test",
    scope: "admin",
    toDid: publisher.did,
  });
  const ctHash =
    "sha256:" +
    Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encrypted)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  baseManifest.state = {
    body_encryption: {
      cipher_suite: "aes-256-gcm",
      nonce_bytes: 12,
      frame: "tn-encrypted-body-v2-zip",
      ciphertext_sha256: ctHash,
    },
  };

  const manifestSkeleton = toWireDict(baseManifest, false) as Record<string, unknown>;
  const aad = manifestAadForWrap(manifestSkeleton);
  const wrapFor = opts.wrapRecipientDid ?? bearer.did;
  const wrap = (await sealBekForRecipient(bek, wrapFor, aad)) as Record<string, unknown>;
  if (opts.relabelWrapTo !== undefined) wrap["recipient_identity"] = opts.relabelWrapTo;

  const wire = JSON.parse(JSON.stringify(manifestSkeleton)) as Record<string, unknown>;
  const wbe = (wire["state"] as Record<string, unknown>)["body_encryption"] as Record<string, unknown>;
  wbe["recipient_wraps"] = [wrap];
  wbe["recipient_wrap"] = wrap;

  const signed = signManifest(fromWireDict(wire), publisher);
  const signedWire = toWireDict(signed, true) as Record<string, unknown>;
  if (opts.tamperCeremonyId) signedWire["ceremony_id"] = "tampered_ceremony";

  const manifestJson =
    JSON.stringify(
      signedWire,
      (_key, value) => {
        if (value && typeof value === "object" && !Array.isArray(value)) {
          const sorted: Record<string, unknown> = {};
          for (const k of Object.keys(value).sort()) sorted[k] = value[k];
          return sorted;
        }
        return value;
      },
      2,
    ) + "\n";

  const members = [
    { name: "manifest.json", data: new TextEncoder().encode(manifestJson) },
  ];
  if (!opts.omitEncrypted) members.push({ name: "body/encrypted.bin", data: encrypted });
  return packTnpkg(members);
}

function withCwd<T>(fn: (cwd: string) => Promise<T>): Promise<T> {
  const cwd = mkdtempSync(join(tmpdir(), "tn-sealed-abs-"));
  return fn(cwd).finally(() => rmSync(cwd, { recursive: true, force: true }));
}

test("happy path: valid project_seed seals + installs", async () => {
  const publisher = DeviceKey.generate();
  const bearer = DeviceKey.generate();
  const pkg = await buildSealed(publisher, bearer);
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(pkg, { seed: bearer.seed, cwd });
    assert.equal(r.rejectedReason, undefined);
    assert.ok(r.acceptedCount > 0, `acceptedCount > 0 (got ${r.acceptedCount})`);
    let foundPrivate = false;
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name === "local.private") {
          foundPrivate = true;
          assert.equal(new Uint8Array(readFileSync(p)).length, 32);
        }
      }
    };
    walk(cwd);
    assert.ok(foundPrivate, "local.private landed on disk");
  });
});

test("malformed zip -> kind '' rejection", async () => {
  const garbage = new TextEncoder().encode("not a zip at all");
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(garbage, { seed: new Uint8Array(32), cwd });
    assert.equal(r.kind, "");
    assert.match(r.rejectedReason ?? "", /absorbSealedBootstrap:/);
    assert.equal(r.acceptedCount, 0);
  });
});

test("bad seed length is rejected before unwrap", async () => {
  const publisher = DeviceKey.generate();
  const bearer = DeviceKey.generate();
  const pkg = await buildSealed(publisher, bearer);
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(pkg, { seed: new Uint8Array(16), cwd });
    assert.match(r.rejectedReason ?? "", /seed must be 32 bytes/);
  });
});

test("tampered manifest -> signature does not verify", async () => {
  const publisher = DeviceKey.generate();
  const bearer = DeviceKey.generate();
  const pkg = await buildSealed(publisher, bearer, { tamperCeremonyId: true });
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(pkg, { seed: bearer.seed, cwd });
    assert.match(r.rejectedReason ?? "", /signature does not verify/);
  });
});

test("wraps present but none addressed to us", async () => {
  const publisher = DeviceKey.generate();
  const bearer = DeviceKey.generate();
  const stranger = DeviceKey.generate();
  // Seal for stranger, label as stranger; bearer tries to absorb.
  const pkg = await buildSealed(publisher, bearer, { wrapRecipientDid: stranger.did });
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(pkg, { seed: bearer.seed, cwd });
    assert.match(r.rejectedReason ?? "", /Refusing to attempt unwrap/);
  });
});

test("matching candidate but unseal fails -> sealed-box unwrap failed", async () => {
  const publisher = DeviceKey.generate();
  const bearer = DeviceKey.generate();
  const stranger = DeviceKey.generate();
  // Seal FOR stranger but relabel the wrap as bearer so it becomes a
  // candidate; bearer's seed cannot unseal it.
  const pkg = await buildSealed(publisher, bearer, {
    wrapRecipientDid: stranger.did,
    relabelWrapTo: bearer.did,
  });
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(pkg, { seed: bearer.seed, cwd });
    assert.match(r.rejectedReason ?? "", /sealed-box unwrap failed/);
  });
});

test("body_encryption declared but body/encrypted.bin missing", async () => {
  const publisher = DeviceKey.generate();
  const bearer = DeviceKey.generate();
  const pkg = await buildSealed(publisher, bearer, { omitEncrypted: true });
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(pkg, { seed: bearer.seed, cwd });
    assert.match(r.rejectedReason ?? "", /body\/encrypted\.bin is missing/);
  });
});

test("unsupported kind is rejected after a successful unwrap", async () => {
  const publisher = DeviceKey.generate();
  const bearer = DeviceKey.generate();
  const pkg = await buildSealed(publisher, bearer, { kind: "full_keystore" });
  await withCwd(async (cwd) => {
    const r = await absorbSealedBootstrap(pkg, { seed: bearer.seed, cwd });
    assert.match(r.rejectedReason ?? "", /not a bootstrap kind/);
  });
});
