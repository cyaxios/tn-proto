import { readFileSync, writeFileSync } from "node:fs";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { jweSeal } from "../core/jwe.js";
import {
  jwksDocumentFingerprint,
  jwksKeySelectedEvent,
  jwksKeyFingerprint,
  parseTnJwks,
  selectActiveJwksEncryptionKey,
  TN_JWKS_KEY_SELECTED_EVENT,
  trustedJwksEncryptionRecipient,
  type TnJwksDocument,
  type TnJwksKeySelectedEventOptions,
  type TnJwksKeySelectedEvent,
  type TnJwksPinnedTrust,
  type TnTrustedJwksEncryptionRecipient,
} from "../core/jwks.js";
import type { VaultJwksConfig } from "../runtime/config.js";
import { authoritativeYamlFor } from "../runtime/config.js";
import type { AdminJwksPinState, AdminState } from "../core/types.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export const TN_JWKS_PINNED_EVENT = "tn.jwks.pinned";
export const TN_JWKS_ROTATED_EVENT = "tn.jwks.rotated";

export interface VaultJwksFetchOptions {
  jwks: VaultJwksConfig;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface VaultJwksInspectOptions {
  url: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface VaultJwksSealOptions extends VaultJwksFetchOptions {
  selectedAt?: string;
  signingKid?: string;
  signingKeyFingerprint?: string;
  recorder?: JwksSelectionRecorder;
}

export interface JwksSelectionRecorder {
  infoAsync(eventType: string, fields?: Record<string, unknown>): Promise<unknown>;
}

export interface VaultJwksRecipientResult {
  recipient: TnTrustedJwksEncryptionRecipient;
  event: TnJwksKeySelectedEvent;
}

export interface VaultJwksInspectResult {
  url: string;
  jwks: TnJwksDocument;
  issuer: string;
  jwksFingerprint: string;
  activeEncryptionKid: string;
  activeEncryptionKeyFingerprint: string;
}

export interface VaultJwksSealResult extends VaultJwksRecipientResult {
  ciphertext: Uint8Array;
}

export interface WriteVaultJwksConfigResult {
  yamlPath: string;
  targetYamlPath: string;
  jwks: VaultJwksConfig;
}

export interface JwksPinnedEventFields {
  issuer: string;
  jwks_url: string;
  jwks_fingerprint: string;
  pinned_at: string;
  signing_kid?: string;
  signing_key_fingerprint?: string;
}

export interface JwksRotatedEventFields {
  issuer: string;
  jwks_url: string;
  previous_jwks_fingerprint: string;
  jwks_fingerprint: string;
  rotated_at: string;
  signing_kid?: string;
  signing_key_fingerprint?: string;
}

export type VaultJwksPinCheckStatus =
  | "unconfigured"
  | "match"
  | "yaml-missing"
  | "admin-missing"
  | "mismatch";

export interface VaultJwksPinCheck {
  status: VaultJwksPinCheckStatus;
  yaml: VaultJwksConfig | null;
  admin: AdminJwksPinState | null;
  reason: string;
}

export function pinnedTrustFromVaultJwksConfig(jwks: VaultJwksConfig): TnJwksPinnedTrust {
  return {
    issuer: jwks.issuer,
    jwksFingerprint: jwks.fingerprint,
  };
}

function normalizeJwksConfigInput(jwks: VaultJwksConfig): VaultJwksConfig {
  if (!jwks.issuer) throw new Error("vault jwks: issuer must be a non-empty string");
  if (!jwks.url) throw new Error("vault jwks: url must be a non-empty string");
  if (!/^sha256:[0-9a-f]{64}$/.test(jwks.fingerprint)) {
    throw new Error("vault jwks: fingerprint must be sha256:<64 lowercase hex chars>");
  }
  if (jwks.pinnedAt !== undefined && !Number.isFinite(Date.parse(jwks.pinnedAt))) {
    throw new Error("vault jwks: pinnedAt must be an ISO timestamp when present");
  }
  return { ...jwks };
}

function vaultBaseFromJwksUrl(jwksUrl: string): string | null {
  try {
    const u = new URL(jwksUrl);
    return u.origin;
  } catch {
    return null;
  }
}

export function writeVaultJwksConfig(
  yamlPath: string,
  jwks: VaultJwksConfig,
): WriteVaultJwksConfigResult {
  const normalized = normalizeJwksConfigInput(jwks);
  const target = authoritativeYamlFor(yamlPath, "vault");
  const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};
  const vault = (doc.vault ?? {}) as Record<string, unknown>;
  const base = vaultBaseFromJwksUrl(normalized.url);

  vault.jwks = {
    issuer: normalized.issuer,
    url: normalized.url,
    fingerprint: normalized.fingerprint,
    ...(normalized.pinnedAt === undefined ? {} : { pinned_at: normalized.pinnedAt }),
  };
  vault.enabled = vault.enabled ?? true;
  if ((vault.url === undefined || vault.url === "") && base !== null) vault.url = base;
  vault.autosync = vault.autosync ?? true;
  vault.sync_interval_seconds = vault.sync_interval_seconds ?? 600;

  doc.vault = vault;
  writeFileSync(target, stringifyYaml(doc), "utf8");
  return { yamlPath, targetYamlPath: target, jwks: normalized };
}

export function jwksPinnedEventFields(
  jwks: VaultJwksConfig,
  opts: {
    pinnedAt?: string;
    signingKid?: string;
    signingKeyFingerprint?: string;
  } = {},
): JwksPinnedEventFields {
  const pinnedAt = opts.pinnedAt ?? jwks.pinnedAt ?? new Date().toISOString();
  return {
    issuer: jwks.issuer,
    jwks_url: jwks.url,
    jwks_fingerprint: jwks.fingerprint,
    pinned_at: pinnedAt,
    ...(opts.signingKid === undefined ? {} : { signing_kid: opts.signingKid }),
    ...(opts.signingKeyFingerprint === undefined
      ? {}
      : { signing_key_fingerprint: opts.signingKeyFingerprint }),
  };
}

export function jwksRotatedEventFields(
  next: VaultJwksConfig,
  previousJwksFingerprint: string,
  opts: {
    rotatedAt?: string;
    signingKid?: string;
    signingKeyFingerprint?: string;
  } = {},
): JwksRotatedEventFields {
  return {
    issuer: next.issuer,
    jwks_url: next.url,
    previous_jwks_fingerprint: previousJwksFingerprint,
    jwks_fingerprint: next.fingerprint,
    rotated_at: opts.rotatedAt ?? new Date().toISOString(),
    ...(opts.signingKid === undefined ? {} : { signing_kid: opts.signingKid }),
    ...(opts.signingKeyFingerprint === undefined
      ? {}
      : { signing_key_fingerprint: opts.signingKeyFingerprint }),
  };
}

export function checkVaultJwksPinAgainstAdminState(
  yamlJwks: VaultJwksConfig | undefined,
  state: Pick<AdminState, "jwksPins">,
): VaultJwksPinCheck {
  const pins = state.jwksPins;
  if (yamlJwks === undefined && pins.length === 0) {
    return {
      status: "unconfigured",
      yaml: null,
      admin: null,
      reason: "no JWKS pin in YAML or signed admin state",
    };
  }
  if (yamlJwks === undefined) {
    return {
      status: "yaml-missing",
      yaml: null,
      admin: pins[pins.length - 1] ?? null,
      reason: "signed admin state has a JWKS pin but vault.jwks is missing from YAML",
    };
  }
  const admin = pins.find((pin) => pin.issuer === yamlJwks.issuer) ?? null;
  if (admin === null) {
    return {
      status: "admin-missing",
      yaml: yamlJwks,
      admin,
      reason: "vault.jwks is present in YAML but no matching signed admin pin exists",
    };
  }
  if (admin.jwksUrl !== yamlJwks.url) {
    return {
      status: "mismatch",
      yaml: yamlJwks,
      admin,
      reason: "vault.jwks.url does not match signed admin state",
    };
  }
  if (admin.jwksFingerprint !== yamlJwks.fingerprint) {
    return {
      status: "mismatch",
      yaml: yamlJwks,
      admin,
      reason: "vault.jwks.fingerprint does not match signed admin state",
    };
  }
  return {
    status: "match",
    yaml: yamlJwks,
    admin,
    reason: "vault.jwks matches signed admin state",
  };
}

async function fetchJson(
  url: string,
  opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<unknown> {
  const f = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const resp = await f(url, {
      headers: { Accept: "application/json" },
      signal: ctrl.signal,
    });
    if (!resp.ok) {
      throw new Error(`vault jwks: GET ${url} returned ${resp.status}`);
    }
    return await resp.json();
  } finally {
    clearTimeout(timer);
  }
}

export async function inspectVaultJwks(
  opts: VaultJwksInspectOptions,
): Promise<VaultJwksInspectResult> {
  const jwks = parseTnJwks(await fetchJson(opts.url, opts));
  const selected = selectActiveJwksEncryptionKey(jwks);
  return {
    url: opts.url,
    jwks,
    issuer: jwks.issuer,
    jwksFingerprint: jwksDocumentFingerprint(jwks),
    activeEncryptionKid: selected.kid,
    activeEncryptionKeyFingerprint: jwksKeyFingerprint(selected.jwk),
  };
}

export async function trustedVaultJwksRecipient(
  opts: VaultJwksFetchOptions,
): Promise<VaultJwksRecipientResult> {
  const jwksJson = await fetchJson(opts.jwks.url, opts);
  const recipient = trustedJwksEncryptionRecipient(jwksJson, {
    policy: "pinned",
    pinned: pinnedTrustFromVaultJwksConfig(opts.jwks),
  });
  const event = jwksKeySelectedEvent(recipient, {
    jwksUrl: opts.jwks.url,
  });
  return { recipient, event };
}

export async function sealForTrustedVaultJwks(
  payload: Uint8Array,
  opts: VaultJwksSealOptions,
): Promise<VaultJwksSealResult> {
  const jwksJson = await fetchJson(opts.jwks.url, opts);
  const recipient = trustedJwksEncryptionRecipient(jwksJson, {
    policy: "pinned",
    pinned: pinnedTrustFromVaultJwksConfig(opts.jwks),
  });
  const eventOptions: TnJwksKeySelectedEventOptions = { jwksUrl: opts.jwks.url };
  if (opts.selectedAt !== undefined) eventOptions.selectedAt = opts.selectedAt;
  if (opts.signingKid !== undefined) eventOptions.signingKid = opts.signingKid;
  if (opts.signingKeyFingerprint !== undefined) {
    eventOptions.signingKeyFingerprint = opts.signingKeyFingerprint;
  }
  const event = jwksKeySelectedEvent(recipient, eventOptions);
  const ciphertext = await jweSeal([recipient], payload);
  if (opts.recorder !== undefined) {
    await opts.recorder.infoAsync(TN_JWKS_KEY_SELECTED_EVENT, { ...event });
  }
  return { recipient, event, ciphertext };
}
