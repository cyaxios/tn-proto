import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToB64 } from "../core/encoding.js";
import {
  jweActivationReferenceDigest,
  jweRecipientFromAcceptedOffer,
  validateVerifiedJweRecipient,
  type VerifiedJweRecipient,
} from "../core/jwe_binding.js";
import type { BundleResult } from "../core/results.js";
import {
  TrustError,
  formatTrustTimestamp,
  parseEd25519DidKey,
  type AcceptedOffer,
} from "../core/trust.js";
import type { NodeRuntime } from "../runtime/node_runtime.js";
import { assertReconciledAcceptedOffer } from "../runtime/enrollment.js";

export interface PrepareRecipientOptions {
  recipientDid: string;
  outDir: string;
  groups?: string[];
  /**
   * Explicitly deliver BTN/HIBE bearer keys as plaintext package members.
   * The normal preparation path recipient-seals them to `recipientDid`.
   */
  unsafePlaintextKitBundle?: boolean;
  acceptedOffers?: AcceptedOffer[];
  /** Direct authenticated bindings. Signed proof routes must use acceptedOffers. */
  jweRecipients?: VerifiedJweRecipient[];
  activationTtlMs?: number;
}

export interface JweActivationResult {
  group: string;
  bindingDigest: string;
  activationReferenceDigest: string;
  publicKeySha256: string;
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
  binding: VerifiedJweRecipient;
  activationReferenceDigest: string;
  acceptedOffer?: AcceptedOffer;
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

function assertBindingScope(
  rt: NodeRuntime,
  binding: VerifiedJweRecipient,
  recipientDid: string,
  group: string,
): void {
  if (binding.readerDid !== recipientDid) {
    throw new TrustError("did_signer_mismatch", "JWE binding names a different reader");
  }
  if (binding.audienceDid !== rt.did) {
    throw new TrustError("wrong_recipient", "JWE binding names a different publisher");
  }
  if (binding.ceremonyId !== rt.config.ceremonyId || binding.group !== group) {
    throw new TrustError("scope_mismatch", "JWE binding ceremony or group does not match");
  }
  assertCompatibleRecipient(rt, group, recipientDid, binding.publicKey);
}

interface NormalizedPreparationSource {
  binding: VerifiedJweRecipient;
  acceptedOffer?: AcceptedOffer;
}

function normalizedSources(
  opts: PrepareRecipientOptions,
  now: string,
): NormalizedPreparationSource[] {
  const accepted = (opts.acceptedOffers ?? []).map((offer) => {
    assertReconciledAcceptedOffer(offer);
    return {
      binding: validateVerifiedJweRecipient(jweRecipientFromAcceptedOffer(offer), now),
      acceptedOffer: offer,
    };
  });
  const direct = (opts.jweRecipients ?? []).map((source) => {
    const binding = validateVerifiedJweRecipient(source, now);
    if (
      binding.evidence.kind === "signed-key-card" ||
      binding.evidence.kind === "challenge-response"
    ) {
      throw new TrustError(
        "binding_invalid",
        "signed JWE bindings must enter through acceptedOffers after reconciliation",
      );
    }
    return { binding };
  });
  return [...accepted, ...direct];
}

function sourceForGroup(
  rt: NodeRuntime,
  sources: NormalizedPreparationSource[],
  recipientDid: string,
  group: string,
): RecipientPreparationEvidence {
  const matches = sources.filter(
    (source) => source.binding.readerDid === recipientDid && source.binding.group === group,
  );
  if (matches.length !== 1) {
    throw new Error(
      `tn.pkg.prepareRecipient requires exactly one verified JWE source for reader ` +
        `${JSON.stringify(recipientDid)} in group ${JSON.stringify(group)}; got ${matches.length}`,
    );
  }
  const source = matches[0]!;
  const binding = source.binding;
  assertBindingScope(rt, binding, recipientDid, group);
  return {
    group,
    binding,
    activationReferenceDigest: jweActivationReferenceDigest(binding),
    ...(source.acceptedOffer === undefined ? {} : { acceptedOffer: source.acceptedOffer }),
  };
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
  const now = formatTrustTimestamp(Date.now() * 1000);
  const sources = normalizedSources(opts, now);
  const evidence = jweGroups.map((group) =>
    sourceForGroup(rt, sources, opts.recipientDid, group),
  );
  return { requestedGroups, kitGroups, evidence, ttlMs };
}
