import { existsSync, readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { join } from "node:path";

import { computeRowHash } from "./raw.js";
import { signatureFromB64, verify } from "./core/signing.js";
import { asDid, asSignatureB64 } from "./core/types.js";
import { parseEd25519DidKey, TrustError } from "./core/trust.js";

const RESERVED = new Set([
  "device_identity",
  "timestamp",
  "event_id",
  "event_type",
  "level",
  "sequence",
  "prev_hash",
  "row_hash",
  "signature",
]);

interface ForeignGroupHash {
  ciphertext_b64: string;
  field_hashes: Record<string, string>;
}

export interface ForeignReadTrustOptions {
  trustedPublisherDids?: string[];
  unsafeAllowUnverifiedPublisher?: boolean;
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TrustError("statement_invalid", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function canonicalCiphertext(value: string): string {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TrustError("statement_invalid", "foreign ciphertext is not canonical base64");
  }
  const canonical = Buffer.from(value, "base64").toString("base64");
  if (canonical !== value) {
    throw new TrustError("statement_invalid", "foreign ciphertext is not canonical base64");
  }
  return canonical;
}

function fieldHashes(value: unknown): Record<string, string> {
  const object = objectValue(value, "foreign field_hashes");
  for (const digest of Object.values(object)) {
    if (typeof digest !== "string") {
      throw new TrustError("statement_invalid", "foreign field_hashes values must be strings");
    }
  }
  return object as Record<string, string>;
}

function groupHashes(env: Record<string, unknown>): Map<string, ForeignGroupHash> {
  const groups = new Map<string, ForeignGroupHash>();
  for (const [name, value] of Object.entries(env)) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
    const row = value as Record<string, unknown>;
    const hashes = row["field_hashes"];
    if (
      typeof row["ciphertext"] !== "string" ||
      hashes === null ||
      typeof hashes !== "object" ||
      Array.isArray(hashes)
    )
      continue;
    groups.set(name, {
      ciphertext_b64: canonicalCiphertext(row["ciphertext"]),
      field_hashes: fieldHashes(hashes),
    });
  }
  return groups;
}

function text(env: Record<string, unknown>, key: string): string {
  return typeof env[key] === "string" ? env[key] : "";
}

/** Recompute row_hash from the full foreign envelope and verify its signature. */
export function verifyForeignRowIntegrity(env: Record<string, unknown>): {
  signature: boolean;
  rowHash: boolean;
} {
  const rowHash = (() => {
    try {
      const groups = groupHashes(env);
      const publicFields: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(env)) {
        if (!RESERVED.has(key) && !groups.has(key)) publicFields[key] = value;
      }
      return (
        computeRowHash({
          device_identity: text(env, "device_identity"),
          timestamp: text(env, "timestamp"),
          event_id: text(env, "event_id"),
          event_type: text(env, "event_type"),
          level: text(env, "level"),
          prev_hash: text(env, "prev_hash"),
          public_fields: publicFields,
          groups: Object.fromEntries(groups),
        }) === env["row_hash"]
      );
    } catch {
      return false;
    }
  })();
  const signature = (() => {
    try {
      return verify(
        asDid(text(env, "device_identity")),
        new TextEncoder().encode(text(env, "row_hash")),
        signatureFromB64(asSignatureB64(text(env, "signature"))),
      );
    } catch {
      return false;
    }
  })();
  return { signature, rowHash };
}

function installedPublisherDids(keystoreDir: string): string[] {
  const path = join(keystoreDir, "trust", "verified_publishers.v1.json");
  if (!existsSync(path)) return [];
  let doc: Record<string, unknown>;
  try {
    doc = objectValue(JSON.parse(readFileSync(path, "utf8")), "verified publisher registry");
  } catch (error) {
    if (error instanceof TrustError) throw error;
    throw new TrustError("statement_invalid", "verified publisher registry is unreadable");
  }
  if (doc["version"] !== 1) {
    throw new TrustError("statement_invalid", "unsupported verified publisher registry version");
  }
  const publishers = objectValue(doc["publishers"], "verified publisher records");
  return Object.entries(publishers).map(([did, value]) => {
    objectValue(value, "verified publisher record");
    parseEd25519DidKey(did);
    return did;
  });
}

export function foreignReadTrustedPublishers(
  keystoreDir: string,
  opts: ForeignReadTrustOptions,
): Set<string> | null {
  if (opts.unsafeAllowUnverifiedPublisher === true) return null;
  const dids = opts.trustedPublisherDids ?? installedPublisherDids(keystoreDir);
  for (const did of dids) parseEd25519DidKey(did);
  return new Set(dids);
}

export function assertForeignPublisherTrusted(
  env: Record<string, unknown>,
  trusted: Set<string> | null,
): void {
  if (trusted === null) return;
  const did = text(env, "device_identity");
  if (!trusted.has(did)) {
    throw new TrustError(
      "untrusted_principal",
      `foreign row writer ${JSON.stringify(did)} is not trusted`,
    );
  }
}
