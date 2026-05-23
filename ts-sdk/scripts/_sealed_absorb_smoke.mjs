// Self-loop smoke for the sealed-bundle absorb path.
//
// 1. Mint two device keys: a publisher and a bearer (the API-key
//    holder).
// 2. Build the unsealed body (yaml + local.private + local.public for
//    the publisher).
// 3. Generate a random BEK, AES-GCM-encrypt the body into a STORED zip
//    plaintext.
// 4. Build the recipient wrap addressed to the bearer's DID.
// 5. Build + sign a project_seed manifest with state.body_encryption.
//    recipient_wraps[].
// 6. packTnpkg the result.
// 7. Run absorbSealedBootstrap with the bearer's seed against a temp
//    cwd. Verify local.private + tn.yaml landed and decoded correctly.
//
// This exercises the same code path bootstrapFromApiKey takes after
// fetching the bundle from the vault, so we don't need a real vault
// to prove the unseal+install bridge works.

import { readFileSync, existsSync, readdirSync, mkdtempSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve as pathResolve, join } from "node:path";
import { tmpdir } from "node:os";
import { initSync } from "tn-wasm";

const __here = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(
  pathResolve(__here, "..", "..", "crypto", "tn-wasm", "pkg", "tn_wasm_bg.wasm"),
);
initSync({ module: wasmBytes });

const {
  DeviceKey,
  encryptBodyBlob,
  sealBekForRecipient,
  manifestAadForWrap,
  signManifest,
  packTnpkg,
  toWireDict,
  absorbSealedBootstrap,
} = await import("../dist/index.js");

const { newManifest } = await import("../dist/core/tnpkg.js");

let failures = 0;
function assert(cond, msg) {
  if (cond) {
    console.log(`  PASS  ${msg}`);
  } else {
    console.log(`  FAIL  ${msg}`);
    failures += 1;
  }
}

// ----- Step 1: mint publisher + bearer keys --------------------------

const publisher = DeviceKey.generate();
const bearer = DeviceKey.generate();
console.log("step 1: mint publisher + bearer");
console.log(`  publisher.did = ${publisher.did}`);
console.log(`  bearer.did    = ${bearer.did}`);

// ----- Step 2: build the unsealed body --------------------------------

const yamlText =
  `ceremony:\n  id: smoke_test\n  mode: linked\nkeystore:\n  path: ./.tn/keys\nlogs:\n  path: ./.tn/logs/tn.ndjson\ndevice:\n  device_identity: ${publisher.did}\n`;
const bodyMap = new Map();
bodyMap.set("body/tn.yaml", new TextEncoder().encode(yamlText));
bodyMap.set("body/keys/local.private", publisher.seed);
bodyMap.set("body/keys/local.public", new TextEncoder().encode(publisher.did));
console.log("step 2: body members:");
for (const [k, v] of bodyMap) console.log(`  ${k} (${v.length}B)`);

// ----- Step 3: encrypt the body under a fresh BEK ---------------------

const bek = new Uint8Array(32);
crypto.getRandomValues(bek);
const encrypted = await encryptBodyBlob(bodyMap, bek);
assert(encrypted.length > 12 + 16, `encrypted body is non-trivial (${encrypted.length}B)`);

// ----- Step 4: build the recipient wrap + signed manifest -------------
//
// buildRecipientWraps wants a manifest SKELETON without signature and
// without recipient_wraps yet. It returns the manifest with wraps
// injected; we then sign and pack.

// project_seed integrity rule: fromDid === toDid (both name the
// publisher whose keys live in the body). The recipient wrap addresses
// the bearer separately via state.body_encryption.recipient_wraps —
// the wrap and the manifest's to-field are different roles. Mirrors
// _absorb_project_seed in src/runtime/absorb_bootstrap.ts:355.
const baseManifest = newManifest({
  kind: "project_seed",
  fromDid: publisher.did,
  ceremonyId: "smoke_test",
  scope: "admin",
  toDid: publisher.did,
});
// Stamp the cipher params into state.body_encryption so AAD covers them
// (the consumer's manifestAadForWrap strips ONLY recipient_wrap and
// recipient_wraps; everything else stays bound).
baseManifest.state = {
  body_encryption: {
    cipher_suite: "aes-256-gcm",
    nonce_bytes: 12,
    frame: "tn-encrypted-body-v2-zip",
    // Hash of the encrypted blob — matches Python's record at
    // python/tn/export.py:_encrypt_body_in_place.
    ciphertext_sha256:
      "sha256:" +
      Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encrypted)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  },
};

// Convert to wire shape for the recipient_seal helpers.
const manifestSkeleton = toWireDict(baseManifest, false);

// Build the wrap manually so we control the AAD precisely. The shipped
// buildRecipientWraps unconditionally overwrites recipient_identity to
// the wrap target, which would set toDid=bearer in this manifest. The
// project_seed integrity rule says fromDid===toDid===publisher — the
// wrap addresses the bearer via state.body_encryption, not via the
// manifest's top-level recipient_identity. So we seal with our own
// AAD computed on a publisher-addressed skeleton.
const aad = manifestAadForWrap(manifestSkeleton);
const wrap = await sealBekForRecipient(bek, bearer.did, aad);
console.log(`step 4: built recipient wrap (frame=${wrap.frame})`);
assert(wrap.recipient_identity === bearer.did, "wrap addresses bearer DID");

// Inject the wrap into state.body_encryption and re-import to a TS
// Manifest before signing. The consumer's manifestAadForWrap strips
// recipient_wrap[s] before recomputing AAD, so byte-equality between
// producer- and consumer-side AADs is guaranteed.
const manifestWithWrapsWire = JSON.parse(JSON.stringify(manifestSkeleton));
manifestWithWrapsWire.state.body_encryption.recipient_wraps = [wrap];
manifestWithWrapsWire.state.body_encryption.recipient_wrap = wrap;

const { fromWireDict } = await import("../dist/core/tnpkg.js");
const manifestWithWraps = fromWireDict(manifestWithWrapsWire);

// Sign with the publisher's device key.
const signed = signManifest(manifestWithWraps, publisher);
assert(typeof signed.manifestSignatureB64 === "string" && signed.manifestSignatureB64.length > 0,
  "manifest signed");

// ----- Step 5: pack the tnpkg -----------------------------------------

const manifestJson = JSON.stringify(
  toWireDict(signed, true),
  (key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted = {};
      for (const k of Object.keys(value).sort()) sorted[k] = value[k];
      return sorted;
    }
    return value;
  },
  2,
) + "\n";

const tnpkgBytes = packTnpkg([
  { name: "manifest.json", data: new TextEncoder().encode(manifestJson) },
  { name: "body/encrypted.bin", data: encrypted },
]);
console.log(`step 5: packed tnpkg (${tnpkgBytes.length}B)`);

// ----- Step 6: absorb in a temp cwd, verify keystore lands ------------

const cwd = mkdtempSync(join(tmpdir(), "tn-sealed-absorb-smoke-"));
try {
  const receipt = await absorbSealedBootstrap(tnpkgBytes, { seed: bearer.seed, cwd });
  console.log(`step 6: absorb receipt: ${JSON.stringify({ kind: receipt.kind, accepted: receipt.acceptedCount, reason: receipt.rejectedReason })}`);
  assert(receipt.rejectedReason === undefined,
    `absorb succeeded (no rejectedReason; ${receipt.rejectedReason ?? "ok"})`);
  assert(receipt.acceptedCount > 0,
    `acceptedCount > 0 (got ${receipt.acceptedCount} — one per installed body member)`);

  // Walk the cwd: project_seed installs ./.tn/<stem>/keys/local.{private,public}
  // plus a yaml at the bundle's declared path. We just confirm the
  // private key landed somewhere and matches the publisher's seed.
  let foundPrivate = false;
  let foundYaml = false;
  function walk(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name === "local.private") {
        foundPrivate = true;
        const onDisk = new Uint8Array(readFileSync(p));
        assert(onDisk.length === 32, `local.private is 32 bytes (${onDisk.length})`);
        // Byte-compare to the publisher's seed
        let match = true;
        for (let i = 0; i < 32; i += 1) {
          if (onDisk[i] !== publisher.seed[i]) { match = false; break; }
        }
        assert(match, "on-disk local.private matches publisher.seed byte-for-byte");
      } else if (entry.name === "tn.yaml") {
        foundYaml = true;
        const text = new TextDecoder().decode(new Uint8Array(readFileSync(p)));
        assert(text.includes(publisher.did),
          "tn.yaml on disk carries the publisher DID");
      }
    }
  }
  walk(cwd);
  assert(foundPrivate, "local.private landed on disk");
  assert(foundYaml, "tn.yaml landed on disk");
} finally {
  rmSync(cwd, { recursive: true, force: true });
}

console.log(`\n${failures === 0 ? "smoke PASSED" : `smoke FAILED -- ${failures} assertion(s)`}`);
process.exit(failures === 0 ? 0 : 1);
