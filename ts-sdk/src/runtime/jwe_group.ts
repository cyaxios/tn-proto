// jwe group keystore management — mirrors Python `tn.cipher.JWEGroupCipher`
// (create / add_recipient / revoke_recipient). A jwe group's on-disk material:
//
//   <group>.jwe.sender       32B X25519 private (inert identity anchor)
//   <group>.jwe.mykey        32B X25519 private (this party's recipient key)
//   <group>.jwe.recipients   JSON list [{recipient_identity, pub_b64}, ...]
//
// ECDH-ES generates an ephemeral sender key per seal, so `.jwe.sender` is never
// used to seal or open — it is kept only so the keystore layout matches Python
// (the ceremony / compile / absorb surface reads it as a stable group anchor).

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { join } from "node:path";

import { x25519 } from "@noble/curves/ed25519";

/** One entry in a `<group>.jwe.recipients` file. `pub_b64` is standard base64
 *  (matching Python's `base64.b64encode`) of the recipient's raw 32-byte
 *  X25519 public key. The optional trust metadata records HOW the binding was
 *  admitted: `verified: true` entries came through a verified key-binding
 *  proof (`proof_digest` + `public_key_sha256` retained); `verified: false`
 *  marks an explicitly unsafe raw registration that can never be silently
 *  promoted to trusted state. */
export interface JweRecipientEntry {
  recipient_identity: string;
  pub_b64: string;
  verified?: boolean;
  proof_digest?: string | null;
  public_key_sha256?: string | null;
}

/** Trust metadata persisted alongside a jwe recipient registration. */
export interface JweRecipientTrust {
  verified: boolean;
  proof_digest?: string | null;
  public_key_sha256?: string | null;
}

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");

function recipientsPath(keysDir: string, group: string): string {
  return join(keysDir, `${group}.jwe.recipients`);
}

function validateJweGroupName(group: string): string {
  if (
    group.length === 0 ||
    group !== group.trim() ||
    group === "." ||
    group === ".." ||
    group.includes("/") ||
    group.includes("\\") ||
    group.includes("\0")
  ) {
    throw new Error(`jwe: invalid group name ${JSON.stringify(group)} for keystore filenames`);
  }
  return group;
}

function validateRecipientDid(did: string): string {
  if (did.length === 0 || did !== did.trim() || did.includes("\0")) {
    throw new Error(`jwe: invalid recipient identity ${JSON.stringify(did)}`);
  }
  return did;
}

function validateTimestamp(ts: string): string {
  if (
    ts.length === 0 ||
    ts !== ts.trim() ||
    ts === "." ||
    ts === ".." ||
    ts.includes("/") ||
    ts.includes("\\") ||
    ts.includes("\0")
  ) {
    throw new Error(`jwe: invalid rotation timestamp ${JSON.stringify(ts)}`);
  }
  return ts;
}

function validateRecipientPublicKey(pub: Uint8Array, label = "recipient public key"): Uint8Array {
  if (pub.length !== 32) {
    throw new Error(`jwe: ${label} must be 32 raw X25519 bytes, got ${pub.length}`);
  }
  return pub;
}

function decodeRecipientPublicKey(pubB64: unknown, index: number): Uint8Array {
  if (typeof pubB64 !== "string" || pubB64.length === 0) {
    throw new Error(`jwe: recipient public key at index ${index} must be base64 text`);
  }
  return validateRecipientPublicKey(
    new Uint8Array(Buffer.from(pubB64, "base64")),
    `recipient public key at index ${index}`,
  );
}

function readRecipients(path: string): JweRecipientEntry[] {
  if (!existsSync(path)) {
    throw new Error(`jwe: recipients file is missing at ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`jwe: recipients file is invalid JSON at ${path}: ${(err as Error).message}`, {
      cause: err,
    });
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`jwe: recipients file must contain an array at ${path}`);
  }
  return parsed.map((entry, index) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`jwe: recipient entry at index ${index} must be an object`);
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.recipient_identity !== "string") {
      throw new Error(`jwe: recipient_identity at index ${index} must be a string`);
    }
    validateRecipientDid(e.recipient_identity);
    const out: JweRecipientEntry = {
      recipient_identity: e.recipient_identity,
      pub_b64: b64(decodeRecipientPublicKey(e.pub_b64, index)),
    };
    // Preserve the trust metadata written by verified/unsafe registrations;
    // absent fields stay absent so legacy files round-trip byte-stable.
    if (typeof e.verified === "boolean") out.verified = e.verified;
    if (typeof e.proof_digest === "string" || e.proof_digest === null) {
      out.proof_digest = e.proof_digest as string | null;
    }
    if (typeof e.public_key_sha256 === "string" || e.public_key_sha256 === null) {
      out.public_key_sha256 = e.public_key_sha256 as string | null;
    }
    return out;
  });
}

/** Write JSON via write-temp-then-rename so a crash can't tear the file. */
function atomicWriteJson(path: string, doc: unknown): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(doc, null, 2));
  renameSync(tmp, path);
}

/** Write secret key bytes owner-only (0600) via write-temp-then-rename. The
 *  temp is created fresh with mode 0600 and rename carries those bits onto the
 *  target (so a rewrite re-tightens perms too). A bare writeFileSync would
 *  inherit the umask and leave the private key world-readable (0644). On
 *  Windows the mode is a no-op; the user-profile ACL protects it, the same
 *  posture as every other keystore secret. */
function writeSecretBytes(path: string, data: Uint8Array): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, Buffer.from(data), { mode: 0o600 });
  renameSync(tmp, path);
}

/**
 * Mint a fresh jwe group as publisher-and-sole-reader: an inert sender key, a
 * self-recipient X25519 keypair, and a recipients list holding `selfDid`.
 * Mirrors `JWEGroupCipher.create` for the solo-ceremony case.
 *
 * Throws if the flat keystore filenames would be unsafe, if `selfDid` is not a
 * usable recipient identity, or if any group material already exists. Rotation
 * must use {@link jweRotateGroup}; create never overwrites live material.
 */
export function createJweGroup(keysDir: string, group: string, selfDid: string): void {
  validateJweGroupName(group);
  validateRecipientDid(selfDid);
  mkdirSync(keysDir, { recursive: true });
  for (const suffix of ["jwe.sender", "jwe.mykey", "jwe.recipients"]) {
    const path = join(keysDir, `${group}.${suffix}`);
    if (existsSync(path)) {
      throw new Error(`jwe: group ${JSON.stringify(group)} already exists at ${path}`);
    }
  }
  const senderPriv = x25519.utils.randomPrivateKey();
  writeSecretBytes(join(keysDir, `${group}.jwe.sender`), senderPriv);

  const myPriv = x25519.utils.randomPrivateKey();
  const myPub = x25519.getPublicKey(myPriv);
  writeSecretBytes(join(keysDir, `${group}.jwe.mykey`), myPriv);

  atomicWriteJson(recipientsPath(keysDir, group), [
    { recipient_identity: selfDid, pub_b64: b64(myPub) },
  ] satisfies JweRecipientEntry[]);
}

/**
 * Append `did` with its raw 32-byte X25519 public key to the recipient list;
 * the next seal wraps a CEK for it. Idempotent — re-adding a DID replaces its
 * entry rather than duplicating. Mirrors `JWEGroupCipher.add_recipient`.
 * `trust` records how the binding was admitted (verified proof vs explicitly
 * unsafe raw registration); omitted for legacy callers.
 */
export function jweAddRecipient(
  keysDir: string,
  group: string,
  did: string,
  pub: Uint8Array,
  trust?: JweRecipientTrust,
): void {
  validateJweGroupName(group);
  validateRecipientDid(did);
  validateRecipientPublicKey(pub);
  const path = recipientsPath(keysDir, group);
  const doc = readRecipients(path).filter((e) => e.recipient_identity !== did);
  const entry: JweRecipientEntry = { recipient_identity: did, pub_b64: b64(pub) };
  if (trust !== undefined) {
    entry.verified = trust.verified;
    if (trust.proof_digest !== undefined) entry.proof_digest = trust.proof_digest;
    if (trust.public_key_sha256 !== undefined) entry.public_key_sha256 = trust.public_key_sha256;
  }
  doc.push(entry);
  atomicWriteJson(path, doc);
}

/**
 * Drop `did` from the recipient list; the next seal omits its block. Returns
 * true if a recipient was removed, false if it was already absent (idempotent).
 * Mirrors `JWEGroupCipher.revoke_recipient`.
 */
export function jweRevokeRecipient(keysDir: string, group: string, did: string): boolean {
  validateJweGroupName(group);
  validateRecipientDid(did);
  const path = recipientsPath(keysDir, group);
  const doc = readRecipients(path);
  const next = doc.filter((e) => e.recipient_identity !== did);
  if (next.length === doc.length) return false;
  atomicWriteJson(path, next);
  return true;
}

/** The recipient DIDs currently entitled for a jwe group (order preserved). */
export function jweRecipients(keysDir: string, group: string): string[] {
  validateJweGroupName(group);
  return readRecipients(recipientsPath(keysDir, group)).map((e) => e.recipient_identity);
}

/**
 * Rotate a jwe group: archive the current `sender` / `recipients` / `mykey` as
 * `.revoked.<ts>` and mint fresh material (the new recipients list holds only
 * `selfDid` — prior recipients must re-enroll). Mirrors Python's jwe rotate.
 * `ts` is a filename-safe timestamp supplied by the caller.
 *
 * New material is staged to `.pending` files before any active file is archived,
 * so a failed mint leaves the currently usable group files in place.
 */
export function jweRotateGroup(keysDir: string, group: string, selfDid: string, ts: string): void {
  validateJweGroupName(group);
  validateRecipientDid(selfDid);
  validateTimestamp(ts);

  const senderPath = join(keysDir, `${group}.jwe.sender`);
  const recipients = recipientsPath(keysDir, group);
  const myKeyPath = join(keysDir, `${group}.jwe.mykey`);
  for (const path of [senderPath, recipients, myKeyPath]) {
    if (!existsSync(path)) {
      throw new Error(`jwe: recipients file/group material is missing at ${path}`);
    }
  }
  readRecipients(recipients);

  const senderPriv = x25519.utils.randomPrivateKey();
  const myPriv = x25519.utils.randomPrivateKey();
  const myPub = x25519.getPublicKey(myPriv);
  const recipientsDoc = [
    { recipient_identity: selfDid, pub_b64: b64(myPub) },
  ] satisfies JweRecipientEntry[];

  writeSecretBytes(`${senderPath}.pending`, senderPriv);
  writeSecretBytes(`${myKeyPath}.pending`, myPriv);
  atomicWriteJson(`${recipients}.pending`, recipientsDoc);

  for (const src of [senderPath, recipients, myKeyPath]) {
    renameSync(src, `${src}.revoked.${ts}`);
  }
  renameSync(`${senderPath}.pending`, senderPath);
  renameSync(`${myKeyPath}.pending`, myKeyPath);
  renameSync(`${recipients}.pending`, recipients);
}
