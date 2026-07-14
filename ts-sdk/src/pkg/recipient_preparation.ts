import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToB64 } from "../core/encoding.js";
import type { BundleResult } from "../core/results.js";
import { TrustError, parseEd25519DidKey, sha256Digest, type AcceptedOffer } from "../core/trust.js";
import type { NodeRuntime } from "../runtime/node_runtime.js";

export interface PrepareRecipientOptions {
  recipientDid: string;
  outDir: string;
  groups?: string[];
  sealKitBundleForRecipient?: boolean;
  acceptedOffers: AcceptedOffer[];
  activationTtlMs?: number;
}

export interface JweActivationResult {
  group: string;
  package: { outPath: string; manifestSha256: string };
}

export interface PrepareRecipientResult {
  recipientDid: string;
  requestedGroups: string[];
  kitBundle: BundleResult | null;
  jweActivations: JweActivationResult[];
}

export interface RecipientPreparationEvidence {
  group: string;
  accepted: AcceptedOffer;
}

export interface RecipientPreparationPlan {
  requestedGroups: string[];
  kitGroups: string[];
  evidence: RecipientPreparationEvidence[];
  ttlMs: number;
}

export function resolveRequestedGroups(rt: NodeRuntime, groups?: string[]): string[] {
  const source = groups ?? [...rt.config.groups.keys()].filter((group) => group !== "tn.agents");
  const requested = [...new Set(source)];
  if (requested.length === 0) {
    throw new Error("tn.pkg: no groups requested; declare a regular group first");
  }
  const unknown = requested.filter((group) => !rt.config.groups.has(group));
  if (unknown.length > 0) {
    throw new Error(
      `tn.pkg: unknown groups ${JSON.stringify(unknown)}; this ceremony declares ` +
        JSON.stringify([...rt.config.groups.keys()].sort()),
    );
  }
  return requested;
}

function assertCompatibleRecipient(
  rt: NodeRuntime,
  group: string,
  did: string,
  publicKey: Uint8Array,
): void {
  const path = join(rt.config.keystorePath, `${group}.jwe.recipients`);
  let rows: Array<Record<string, unknown>> = [];
  try {
    rows = JSON.parse(readFileSync(path, "utf8")) as Array<Record<string, unknown>>;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (!Array.isArray(rows))
    throw new TrustError("binding_invalid", "JWE recipient list is malformed");
  const existing = rows.find((row) => row["recipient_identity"] === did);
  if (existing !== undefined && existing["pub_b64"] !== bytesToB64(publicKey)) {
    throw new TrustError(
      "replay_conflict",
      "a different X25519 key is already registered for this reader DID",
    );
  }
}

function acceptedOfferFor(
  rt: NodeRuntime,
  offers: AcceptedOffer[],
  recipientDid: string,
  group: string,
): AcceptedOffer {
  const matches = offers.filter(
    (offer) =>
      offer.binding.principal.did === recipientDid && offer.binding.principal.group === group,
  );
  if (matches.length !== 1) {
    const detail = matches.length === 0 ? "requires an" : "received multiple";
    throw new Error(
      `tn.pkg.prepareRecipient ${detail} accepted JWE offer for reader ` +
        `${JSON.stringify(recipientDid)} in group ${JSON.stringify(group)}`,
    );
  }
  const accepted = matches[0]!;
  const binding = accepted.binding;
  if (binding.principal.purpose !== "jwe-reader") {
    throw new TrustError("binding_invalid", "accepted offer is not a jwe-reader binding");
  }
  if (binding.principal.audienceDid !== rt.did) {
    throw new TrustError("wrong_recipient", "accepted offer names a different publisher");
  }
  if (binding.principal.ceremonyId !== rt.config.ceremonyId) {
    throw new TrustError("scope_mismatch", "accepted offer ceremony does not match");
  }
  if (
    accepted.offerDigest !== binding.proofDigest ||
    sha256Digest(binding.publicKey) !== binding.publicKeySha256
  ) {
    throw new TrustError("binding_invalid", "accepted offer digest or X25519 key is inconsistent");
  }
  assertCompatibleRecipient(rt, group, recipientDid, binding.publicKey);
  return accepted;
}

export function planRecipientPreparation(
  rt: NodeRuntime,
  opts: PrepareRecipientOptions,
): RecipientPreparationPlan {
  parseEd25519DidKey(opts.recipientDid);
  const requestedGroups = resolveRequestedGroups(rt, opts.groups);
  const kitGroups = requestedGroups.filter(
    (group) => rt.config.groups.get(group)?.cipher !== "jwe",
  );
  const jweGroups = requestedGroups.filter(
    (group) => rt.config.groups.get(group)?.cipher === "jwe",
  );
  const ttlMs = opts.activationTtlMs ?? 10 * 60_000;
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    throw new Error("tn.pkg.prepareRecipient: activationTtlMs must be a positive safe integer");
  }
  const evidence = jweGroups.map((group) => ({
    group,
    accepted: acceptedOfferFor(rt, opts.acceptedOffers, opts.recipientDid, group),
  }));
  return { requestedGroups, kitGroups, evidence, ttlMs };
}
