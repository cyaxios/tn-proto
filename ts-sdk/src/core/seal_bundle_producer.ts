// Producer-side sealing for `kit_bundle` `.tnpkg` artifacts.
//
// The TS SDK long carried the seal PRIMITIVES (core/recipient_seal.ts:
// `sealBekForRecipient` / `buildRecipientWraps`, and
// core/body_encryption.ts: `encryptBodyBlob`) and a CONSUMER that could
// unseal them (runtime/absorb_bootstrap.ts: `absorbSealedBootstrap`).
// What was missing was the PRODUCER composition: take an already-minted
// `kit_bundle` body, encrypt it under a per-export Body Encryption Key
// (BEK), wrap that BEK to a recipient DID, and emit a sealed `.tnpkg`
// whose manifest carries the recipient wraps. `tn bundle` /
// `tn add_recipient --seal-for-recipient` previously REFUSED to do this
// (a documented gap; see docs/cli-test-plans/absorb.md).
//
// This module closes that gap by COMPOSING the existing primitives — no
// new crypto is invented here:
//
//   1. Take the plaintext kit_bundle body (the `body/<group>.btn.mykit`
//      members) produced by the existing `bundleForRecipient` primitive.
//   2. Mint a fresh 32-byte BEK.
//   3. `encryptBodyBlob(body, bek)` -> `body/encrypted.bin`.
//   4. Build the manifest skeleton (kind=kit_bundle, the existing kits
//      metadata, plus a `state.body_encryption` descriptor) and run
//      `buildRecipientWraps(bek, [recipientDid], skeleton)` so the BEK is
//      sealed to the recipient and the wraps land in
//      `state.body_encryption.recipient_wraps[]`.
//   5. Sign the manifest and write the sealed `.tnpkg`.
//
// AAD parity with the consumer is load-bearing: `buildRecipientWraps`
// binds each wrap against `manifestAadForWrap(skeleton)`, while
// `absorbSealedBootstrap` (and `absorbSealedKitBundle` below) recompute
// the AAD from `manifestAadForWrap(toWireDict(manifest, true))`. We
// therefore derive the skeleton from `toWireDict(manifest, false)` so the
// producer's AAD canonicalizes byte-for-byte to the consumer's. The wrap
// and signature fields are stripped from the AAD on both sides, so the
// order (wrap, then sign) is correct.
//
// Layer note: this module touches the Node-only `writeTnpkg` / `readTnpkg`
// I/O wrappers, so it lives under src/core but is Node-flavored (same as
// the runtime). The crypto it composes is browser-safe.

import { existsSync, mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve } from "node:path";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { DeviceKey } from "./signing.js";
import {
  type Manifest,
  newManifest,
  signManifest,
  toWireDict,
  fromWireDict,
  isManifestSignatureValid,
} from "./tnpkg.js";
import { readTnpkg, writeTnpkg } from "../tnpkg_io.js";
import { encryptBodyBlob, decryptBodyBlob, BODY_CIPHER_SUITE, BODY_FRAME } from "./body_encryption.js";
import {
  buildRecipientWraps,
  manifestAadForWrap,
  unsealBekFromWrap,
  didKeyToEd25519Pub,
  UnsealError,
} from "./recipient_seal.js";

/** Inputs to {@link sealBundleForRecipient}. */
export interface SealBundleInput {
  /** An UNSEALED `kit_bundle` `.tnpkg` — path or raw bytes. Typically the
   *  output of `NodeRuntime.bundleForRecipient`. Its body members
   *  (`body/<group>.btn.mykit`, ...) become the sealed payload; its
   *  manifest supplies `fromDid` / `ceremonyId` / the `state.kits`
   *  metadata. */
  unsealedBundle: string | Uint8Array;
  /** Recipient's real key-DID (`did:key:z...` with an embedded base58
   *  Ed25519 public key). The BEK is sealed so only the holder of this
   *  DID's private seed can recover it. Synthetic placeholder DIDs (no
   *  embedded key) are rejected by {@link didKeyToEd25519Pub}. */
  recipientDid: string;
  /** Publisher's device key — signs the sealed manifest. Must match the
   *  unsealed bundle's `publisher_identity`, else the result would carry a
   *  signature that doesn't verify against `fromDid`. */
  publisherKey: DeviceKey;
  /** Destination path for the sealed `.tnpkg`. */
  outPath: string;
}

/** Result of {@link sealBundleForRecipient}. */
export interface SealBundleResult {
  /** Absolute path to the written sealed `.tnpkg`. */
  outPath: string;
  /** The fresh 32-byte BEK that encrypted the body (returned for tests /
   *  debugging; the recipient recovers it via the wrap, not from here). */
  bek: Uint8Array;
}

/** Is `did` a real key-DID with an embedded base58 Ed25519 public key
 *  (the only kind the seal step can wrap under)? `didKeyToEd25519Pub`
 *  throws on synthetic / non-Ed25519 / malformed DIDs. */
export function recipientKeyIsResolvable(did: string): boolean {
  try {
    didKeyToEd25519Pub(did);
    return true;
  } catch {
    return false;
  }
}

/**
 * Seal an UNSEALED `kit_bundle` `.tnpkg` to `recipientDid`.
 *
 * Composes the existing seal primitives: mint a BEK, encrypt the bundle
 * body under it, wrap the BEK to the recipient, and emit a sealed
 * `.tnpkg`. The result's body is `body/encrypted.bin` (AES-256-GCM) and
 * the manifest's `state.body_encryption.recipient_wraps[]` carries the
 * sealed BEK; only the recipient's private seed recovers it.
 *
 * @throws Error when the recipient DID has no embedded key to wrap under
 *   (use {@link recipientKeyIsResolvable} to pre-flight), when the input
 *   isn't a `kit_bundle`, or when its signature doesn't verify.
 */
export async function sealBundleForRecipient(input: SealBundleInput): Promise<SealBundleResult> {
  // Pre-flight the recipient key — the seal step has nothing to wrap
  // under for a synthetic placeholder DID. Surface a clear error before
  // doing any crypto.
  if (!recipientKeyIsResolvable(input.recipientDid)) {
    throw new Error(
      `sealBundleForRecipient: recipient ${JSON.stringify(input.recipientDid)} has no embedded ` +
        `Ed25519 public key to seal under. Pass a real did:key:z... identity.`,
    );
  }

  // 1. Read the plaintext kit_bundle body + its manifest. We reuse the
  //    minting primitive's output rather than re-deriving kit bytes.
  const { manifest: srcManifest, body: srcBody } = readTnpkg(input.unsealedBundle);
  if (srcManifest.kind !== "kit_bundle") {
    throw new Error(
      `sealBundleForRecipient: expected an unsealed kit_bundle, got kind ` +
        `${JSON.stringify(srcManifest.kind)}.`,
    );
  }
  if (!isManifestSignatureValid(srcManifest)) {
    throw new Error(
      "sealBundleForRecipient: the unsealed bundle's manifest signature does not verify; " +
        "refusing to re-seal a corrupt input.",
    );
  }

  // The plaintext body members to seal. The source bundle's body is the
  // `body/<group>.btn.mykit` set; carry every body/ member through.
  const plaintextBody = new Map<string, Uint8Array>();
  for (const [name, data] of srcBody) {
    if (name.startsWith("body/")) plaintextBody.set(name, data);
  }
  if (plaintextBody.size === 0) {
    throw new Error("sealBundleForRecipient: unsealed bundle has no body/ members to seal.");
  }

  // 2. Mint a fresh 32-byte BEK.
  const bek = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bek);

  // 3. Encrypt the body under the BEK.
  const encrypted = await encryptBodyBlob(plaintextBody, bek);
  const ciphertextSha =
    "sha256:" + createHash("sha256").update(Buffer.from(encrypted)).digest("hex");

  // 4. Build the manifest skeleton. Carry the source kits metadata so a
  //    consumer can inspect the bundle without unsealing. The
  //    body_encryption descriptor records the cipher/frame/hash; the
  //    recipient_wraps are injected by buildRecipientWraps below.
  const manifest: Manifest = newManifest({
    kind: "kit_bundle",
    fromDid: srcManifest.fromDid,
    ceremonyId: srcManifest.ceremonyId,
    scope: srcManifest.scope || "kit_bundle",
    toDid: input.recipientDid,
  });
  const baseState: Record<string, unknown> =
    srcManifest.state && typeof srcManifest.state === "object" ? { ...srcManifest.state } : {};
  baseState.body_encryption = {
    cipher_suite: BODY_CIPHER_SUITE,
    nonce_bytes: 12,
    frame: BODY_FRAME,
    ciphertext_sha256: ciphertextSha,
  };
  manifest.state = baseState;

  // Skeleton == the exact wire shape, minus the signature. buildRecipientWraps
  // computes AAD = manifestAadForWrap(skeleton); the consumer recomputes it as
  // manifestAadForWrap(toWireDict(manifest, true)) with the signature + wraps
  // stripped. Deriving the skeleton from toWireDict(manifest, false) makes the
  // two canonicalize byte-for-byte.
  const skeleton = toWireDict(manifest, false) as Record<string, unknown>;
  const wrapped = await buildRecipientWraps(bek, [input.recipientDid], skeleton);

  // 5. Adopt the wrap-injected state, then sign + write. The wraps live
  //    in state.body_encryption.recipient_wraps[]; signing happens AFTER
  //    so the (signature-excluding) AAD still matches the consumer.
  const wrappedState = (wrapped.manifest as Record<string, unknown>).state;
  if (wrappedState && typeof wrappedState === "object") {
    manifest.state = wrappedState as Record<string, unknown>;
  }
  signManifest(manifest, input.publisherKey);

  // Body is the single encrypted blob (plaintext members are gone).
  const outBody: Record<string, Uint8Array> = { "body/encrypted.bin": encrypted };
  const outPath = writeTnpkg(input.outPath, manifest, outBody);

  return { outPath, bek };
}

/** Receipt shape from {@link absorbSealedKitBundle}. */
export interface SealedKitBundleReceipt {
  /** "kit_bundle" on success; carries the manifest kind otherwise. */
  kind: string;
  /** Number of kit files written into the keystore. */
  acceptedCount: number;
  /** Number of kit files already present (byte-identical) and skipped. */
  dedupedCount: number;
  /** Populated on any failure (not for us, bad signature, unseal/decrypt
   *  failure). When set, nothing was installed. */
  rejectedReason?: string;
  /** Keystore paths whose prior bytes were backed up + overwritten. */
  replacedKitPaths?: string[];
}

/**
 * Consumer for a SEALED `kit_bundle` `.tnpkg`: recover the BEK using the
 * recipient's seed, decrypt the body, and install the `*.btn.mykit`
 * members into `keystoreDir`.
 *
 * This mirrors `NodeRuntime._absorbKitBundle` for the install step, but
 * adds the unseal that the runtime's plaintext-only path does not perform
 * (the runtime's `absorbSealedBootstrap` only routes `identity_seed` /
 * `project_seed`, not `kit_bundle`). It lets a NAMED recipient prove the
 * binding by reading back, and lets a DIFFERENT recipient prove it fails.
 *
 * Never throws for expected failures — they surface as `rejectedReason`.
 */
export async function absorbSealedKitBundle(
  source: string | Uint8Array,
  opts: { seed: Uint8Array; keystoreDir: string },
): Promise<SealedKitBundleReceipt> {
  let manifest: Manifest;
  let body: Map<string, Uint8Array>;
  try {
    const parsed = readTnpkg(source);
    manifest = parsed.manifest;
    body = parsed.body;
  } catch (err) {
    return { kind: "", acceptedCount: 0, dedupedCount: 0, rejectedReason: (err as Error).message };
  }

  if (!isManifestSignatureValid(manifest)) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      rejectedReason:
        `manifest signature does not verify against publisher_identity ` +
        `${JSON.stringify(manifest.fromDid)}. The package is corrupt, truncated, or tampered.`,
    };
  }
  if (opts.seed.length !== 32) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      rejectedReason: `absorbSealedKitBundle: seed must be 32 bytes, got ${opts.seed.length}`,
    };
  }

  const ourDid = DeviceKey.fromSeed(opts.seed).did;

  const state =
    manifest.state && typeof manifest.state === "object"
      ? (manifest.state as Record<string, unknown>)
      : null;
  const bodyEnc =
    state && typeof state["body_encryption"] === "object" && state["body_encryption"] !== null
      ? (state["body_encryption"] as Record<string, unknown>)
      : null;
  const wrapsArray = bodyEnc?.["recipient_wraps"];
  const wrapSingular = bodyEnc?.["recipient_wrap"];
  if (bodyEnc === null || (wrapsArray === undefined && wrapSingular === undefined)) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      rejectedReason: "absorbSealedKitBundle: bundle is not recipient-sealed (no recipient_wrap[s]).",
    };
  }

  // Candidate wraps addressed to us (plural wins when both present).
  const candidates: Record<string, unknown>[] = [];
  if (Array.isArray(wrapsArray)) {
    for (const entry of wrapsArray) {
      if (entry && typeof entry === "object" && !Array.isArray(entry)) {
        const e = entry as Record<string, unknown>;
        if (e["recipient_identity"] === ourDid) candidates.push(e);
      }
    }
  } else if (wrapSingular && typeof wrapSingular === "object" && !Array.isArray(wrapSingular)) {
    const e = wrapSingular as Record<string, unknown>;
    if (e["recipient_identity"] === ourDid) candidates.push(e);
  }
  if (candidates.length === 0) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      rejectedReason: `sealed-box wrap is not addressed to ${JSON.stringify(ourDid)}.`,
    };
  }

  // AAD over the WIRE manifest, signature + wraps stripped — must match
  // what the producer bound against.
  const aad = manifestAadForWrap(toWireDict(manifest, true) as Record<string, unknown>);

  let bek: Uint8Array | null = null;
  let lastErr = "";
  for (const cand of candidates) {
    try {
      bek = await unsealBekFromWrap(cand, opts.seed, aad);
      break;
    } catch (err) {
      if (err instanceof UnsealError) {
        lastErr = err.message;
        continue;
      }
      throw err;
    }
  }
  if (bek === null) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      rejectedReason: `sealed-box unwrap failed: ${lastErr}`,
    };
  }

  const encrypted = body.get("body/encrypted.bin");
  if (encrypted === undefined) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      rejectedReason: "manifest declares body_encryption but body/encrypted.bin is missing.",
    };
  }

  let decrypted: Map<string, Uint8Array>;
  try {
    decrypted = await decryptBodyBlob(encrypted, bek);
  } catch (err) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      rejectedReason: `body decrypt with unwrapped BEK failed: ${(err as Error).message}`,
    };
  }

  // Install the decrypted *.btn.mykit members. Mirror of
  // NodeRuntime._absorbKitBundle's install loop (flat keystore writes,
  // byte-identical dedup, previous-backup on overwrite).
  const keystore = pathResolve(opts.keystoreDir);
  if (!existsSync(keystore)) mkdirSync(keystore, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15) + "Z";
  let accepted = 0;
  let skipped = 0;
  const replaced: string[] = [];
  for (const [name, data] of decrypted) {
    if (!name.startsWith("body/")) continue;
    const rel = name.slice("body/".length);
    if (!rel) continue;
    if (rel.includes("/") || rel.includes("\\")) continue;
    const dest = pathResolve(keystore, rel);
    if (existsSync(dest)) {
      const existing = readFileSync(dest);
      if (existing.length === data.length && Buffer.from(existing).equals(Buffer.from(data))) {
        skipped += 1;
        continue;
      }
      renameSync(dest, pathResolve(keystore, `${rel}.previous.${ts}`));
      replaced.push(dest);
    }
    writeFileSync(dest, Buffer.from(data));
    accepted += 1;
  }

  return {
    kind: manifest.kind,
    acceptedCount: accepted,
    dedupedCount: skipped,
    replacedKitPaths: replaced,
  };
}

/**
 * One-shot producer: mint an unsealed kit_bundle for `recipientDid` via
 * the runtime, then seal it. Cleans up the intermediate unsealed bundle.
 *
 * Kept here (not in the CLI verbs) so both `tn bundle` and
 * `tn add_recipient` share one seal composition.
 *
 * @param mintUnsealed - callback that mints an unsealed kit_bundle to the
 *   given temp path and returns it (the CLI verbs pass a closure over
 *   `NodeRuntime.bundleForRecipient`). Keeping it as a callback avoids a
 *   hard dependency on the runtime from this core module.
 */
export async function mintAndSealBundle(opts: {
  recipientDid: string;
  publisherKey: DeviceKey;
  outPath: string;
  mintUnsealed: (tmpUnsealedPath: string) => string | Promise<string>;
}): Promise<SealBundleResult> {
  const td = mkdtempSync(join(tmpdir(), "tn-seal-bundle-"));
  const tmpUnsealed = join(td, "unsealed.tnpkg");
  try {
    const minted = await opts.mintUnsealed(tmpUnsealed);
    const result = await sealBundleForRecipient({
      unsealedBundle: minted,
      recipientDid: opts.recipientDid,
      publisherKey: opts.publisherKey,
      outPath: opts.outPath,
    });
    return result;
  } finally {
    try {
      rmSync(td, { recursive: true, force: true });
    } catch {
      // Best-effort temp cleanup.
    }
  }
}

// Re-export for callers/tests that compose the consumer side.
export { fromWireDict };
