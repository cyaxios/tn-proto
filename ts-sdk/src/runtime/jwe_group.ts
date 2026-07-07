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

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { join } from "node:path";

import { x25519 } from "@noble/curves/ed25519";

/** One entry in a `<group>.jwe.recipients` file. `pub_b64` is standard base64
 *  (matching Python's `base64.b64encode`) of the recipient's raw 32-byte
 *  X25519 public key. */
export interface JweRecipientEntry {
  recipient_identity: string;
  pub_b64: string;
}

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");

function recipientsPath(keysDir: string, group: string): string {
  return join(keysDir, `${group}.jwe.recipients`);
}

function readRecipients(path: string): JweRecipientEntry[] {
  return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as JweRecipientEntry[]) : [];
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
 */
export function createJweGroup(keysDir: string, group: string, selfDid: string): void {
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
 */
export function jweAddRecipient(
  keysDir: string,
  group: string,
  did: string,
  pub: Uint8Array,
): void {
  if (pub.length !== 32) {
    throw new Error(`jwe: recipient public key must be 32 raw X25519 bytes, got ${pub.length}`);
  }
  const path = recipientsPath(keysDir, group);
  const doc = readRecipients(path).filter((e) => e.recipient_identity !== did);
  doc.push({ recipient_identity: did, pub_b64: b64(pub) });
  atomicWriteJson(path, doc);
}

/**
 * Drop `did` from the recipient list; the next seal omits its block. Returns
 * true if a recipient was removed, false if it was already absent (idempotent).
 * Mirrors `JWEGroupCipher.revoke_recipient`.
 */
export function jweRevokeRecipient(keysDir: string, group: string, did: string): boolean {
  const path = recipientsPath(keysDir, group);
  const doc = readRecipients(path);
  const next = doc.filter((e) => e.recipient_identity !== did);
  if (next.length === doc.length) return false;
  atomicWriteJson(path, next);
  return true;
}

/** The recipient DIDs currently entitled for a jwe group (order preserved). */
export function jweRecipients(keysDir: string, group: string): string[] {
  return readRecipients(recipientsPath(keysDir, group)).map((e) => e.recipient_identity);
}

/**
 * Rotate a jwe group: archive the current `sender` / `recipients` / `mykey` as
 * `.revoked.<ts>` and mint fresh material (the new recipients list holds only
 * `selfDid` — prior recipients must re-enroll). Mirrors Python's jwe rotate.
 * `ts` is a filename-safe timestamp supplied by the caller.
 */
export function jweRotateGroup(keysDir: string, group: string, selfDid: string, ts: string): void {
  for (const suffix of ["jwe.sender", "jwe.recipients", "jwe.mykey"]) {
    const src = join(keysDir, `${group}.${suffix}`);
    if (existsSync(src)) renameSync(src, `${src}.revoked.${ts}`);
  }
  createJweGroup(keysDir, group, selfDid);
}
