// Canonical-scenario helpers for the cross-language byte-compare tests
// covering `client.secureRead()` flat output and `tn.agents` pre-encryption
// canonical bytes.
//
// Spec: docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md
// section 5.4.
//
// Imported by:
//   - test/fixtures/build_secure_read_fixtures.ts (regenerate the committed fixture)
//   - test/secure_read_interop.test.ts             (consume the Python + Rust fixtures)
//
// Holding the helpers in a single file keeps the canonical scenario
// inputs in one place and prevents drift between the regenerate script
// and the byte-compare tests.

import { canonicalize } from "../../src/core/canonical.js";
import { parsePolicyText } from "../../src/agents_policy.js";
import type { ReadEntry } from "../../src/runtime/node_runtime.js";

export const CANONICAL_DID =
  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

export const CANONICAL_POLICY_PATH = ".tn/config/agents.md";

export const CANONICAL_POLICY_TEXT = [
  "# TN Agents Policy",
  "version: 1",
  "schema: tn-agents-policy@v1",
  "",
  "## payment.completed",
  "",
  "### instruction",
  "This row records a completed payment.",
  "",
  "### use_for",
  "Aggregate reporting on amount and currency.",
  "",
  "### do_not_use_for",
  "Credit decisions, loan underwriting, risk scoring.",
  "",
  "### consequences",
  "customer_id is PII; exposure violates GDPR.",
  "",
  "### on_violation_or_error",
  "POST https://merchant.example.com/controls/escalate",
  "",
].join("\n");

const ZERO_HASH = "sha256:" + "0".repeat(64);
const ONE_HASH = "sha256:" + "1".repeat(64);
const TWO_HASH = "sha256:" + "2".repeat(64);

/** Build the canonical-scenario raw entry for `order.created`.
 *
 * Two group payloads in the envelope (`default`, `pii`); caller holds
 * only the `default` kit so `pii` lands in `_hidden_groups`.
 */
export function orderCreatedRaw(): ReadEntry {
  return {
    envelope: {
      did: CANONICAL_DID,
      timestamp: "2026-04-25T18:32:18.000000Z",
      event_id: "01HXYZ0000000000000000ORD1",
      event_type: "order.created",
      level: "info",
      sequence: 1,
      prev_hash: ZERO_HASH,
      row_hash: ONE_HASH,
      signature: "AAAA",
      request_id: "req_abc",
      default: { ciphertext: "ZGVmYXVsdA==", field_hashes: {} },
      pii: { ciphertext: "cGlp", field_hashes: {} },
    },
    plaintext: {
      default: {
        order_id: "ord_2026_q2_a47b9",
        amount: 4999,
        currency: "USD",
      },
    },
    valid: { signature: true, rowHash: true, chain: true },
  };
}

/** Build the canonical-scenario raw entry for `payment.completed`.
 *
 * Caller holds both the `default` kit and the `tn.agents` kit; the
 * `tn.agents` plaintext carries the six policy fields exactly as the
 * splice payload would have populated them at emit time.
 */
export function paymentCompletedRaw(): ReadEntry {
  return {
    envelope: {
      did: CANONICAL_DID,
      timestamp: "2026-04-25T18:33:42.000000Z",
      event_id: "01HXYZ0000000000000000PAY1",
      event_type: "payment.completed",
      level: "info",
      sequence: 2,
      prev_hash: ONE_HASH,
      row_hash: TWO_HASH,
      signature: "BBBB",
      default: { ciphertext: "ZGVmYXVsdA==", field_hashes: {} },
      "tn.agents": { ciphertext: "YWdlbnRz", field_hashes: {} },
    },
    plaintext: {
      default: {
        order_id: "ord_2026_q2_a47b9",
        amount: 4999,
        currency: "USD",
      },
      "tn.agents": {
        instruction: "This row records a completed payment.",
        use_for: "Aggregate reporting on amount and currency.",
        do_not_use_for:
          "Credit decisions, loan underwriting, risk scoring.",
        consequences: "customer_id is PII; exposure violates GDPR.",
        on_violation_or_error:
          "POST https://merchant.example.com/controls/escalate",
        policy:
          ".tn/config/agents.md#payment.completed@1#sha256:79e0aefecfce8b26d2ea3be0026effee96c9c7aaa8f189d0236fa555eabbb36e",
      },
    },
    valid: { signature: true, rowHash: true, chain: true },
  };
}

const FLAT_ENVELOPE_KEYS = [
  "timestamp",
  "event_type",
  "level",
  "did",
  "sequence",
  "event_id",
] as const;

const RESERVED_ENVELOPE_KEYS = new Set<string>([
  ...FLAT_ENVELOPE_KEYS,
  "prev_hash",
  "row_hash",
  "signature",
]);

function isGroupPayloadValue(v: unknown): boolean {
  return (
    typeof v === "object" &&
    v !== null &&
    !Array.isArray(v) &&
    "ciphertext" in (v as Record<string, unknown>)
  );
}

/** Mirror of the private `flattenRawEntry` in `src/client.ts`. Replicated
 * here to keep this scenario module decoupled from internal client APIs.
 * Spec §1.1 / §1.3.
 */
function flattenRawEntry(raw: ReadEntry): Record<string, unknown> {
  const env = raw.envelope;
  const plaintext = raw.plaintext;
  const out: Record<string, unknown> = {};

  for (const k of FLAT_ENVELOPE_KEYS) {
    if (k in env) out[k] = env[k];
  }

  for (const [k, v] of Object.entries(env)) {
    if (RESERVED_ENVELOPE_KEYS.has(k)) continue;
    if (isGroupPayloadValue(v)) continue;
    out[k] = v;
  }

  const decryptErrors: string[] = [];
  const groupNames = Object.keys(plaintext).sort();
  for (const gname of groupNames) {
    const body = plaintext[gname];
    if (!body || typeof body !== "object" || Array.isArray(body)) continue;
    const b = body as Record<string, unknown>;
    if (b["$decrypt_error"] === true) {
      decryptErrors.push(gname);
      continue;
    }
    if (b["$no_read_key"] === true) continue;
    for (const [fk, fv] of Object.entries(body)) {
      out[fk] = fv;
    }
  }

  const hidden: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    if (RESERVED_ENVELOPE_KEYS.has(k)) continue;
    if (!isGroupPayloadValue(v)) continue;
    const body = plaintext[k];
    if (
      body === undefined ||
      (typeof body === "object" &&
        body !== null &&
        (body as Record<string, unknown>)["$no_read_key"] === true)
    ) {
      hidden.push(k);
    }
  }
  if (hidden.length > 0) {
    out["_hidden_groups"] = [...hidden].sort();
  }
  if (decryptErrors.length > 0) {
    out["_decrypt_errors"] = [...decryptErrors].sort();
  }

  return out;
}

/** Mirror of the private `attachInstructions` in `src/client.ts`. */
function attachInstructions(
  flat: Record<string, unknown>,
  raw: ReadEntry,
): void {
  const body = raw.plaintext["tn.agents"];
  if (!body || typeof body !== "object" || Array.isArray(body)) return;
  const b = body as Record<string, unknown>;
  if (b["$no_read_key"] === true || b["$decrypt_error"] === true) return;

  const instructions: Record<string, unknown> = {};
  for (const f of [
    "instruction",
    "use_for",
    "do_not_use_for",
    "consequences",
    "on_violation_or_error",
    "policy",
  ] as const) {
    if (f in b) {
      instructions[f] = b[f];
    }
    delete flat[f];
  }
  if (Object.keys(instructions).length > 0) {
    flat["instructions"] = instructions;
  }
}

/** Build the `secure_read_canonical.json` payload — the dict
 * `client.secureRead()` would hand to the LLM for the canonical scenario.
 */
export function buildSecureReadCanonical(): Record<string, unknown> {
  const order = orderCreatedRaw();
  const orderFlat = flattenRawEntry(order);
  attachInstructions(orderFlat, order);

  const payment = paymentCompletedRaw();
  const paymentFlat = flattenRawEntry(payment);
  attachInstructions(paymentFlat, payment);

  return {
    order_created: orderFlat,
    payment_completed: paymentFlat,
  };
}

/** Build the `tn_agents_pre_encryption.json` payload — the canonical
 * pre-encryption bytes of the splice payload for the canonical
 * `payment.completed` event.
 */
export function buildTnAgentsPreEncryption(): Record<string, unknown> {
  const doc = parsePolicyText(CANONICAL_POLICY_TEXT, CANONICAL_POLICY_PATH);
  const template = doc.templates.get("payment.completed");
  if (!template) {
    throw new Error("policy must declare payment.completed");
  }

  const splice: Record<string, string> = {
    instruction: template.instruction,
    use_for: template.use_for,
    do_not_use_for: template.do_not_use_for,
    consequences: template.consequences,
    on_violation_or_error: template.on_violation_or_error,
    policy: `${template.path}#${template.eventType}@${template.version}#${template.contentHash}`,
  };

  const cb = canonicalize(splice);
  return {
    splice_dict: splice,
    canonical_bytes_hex: hexEncode(cb),
    canonical_bytes_len: cb.length,
    policy_content_hash: doc.contentHash,
  };
}

function hexEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

/** Encode `obj` as canonical JSON (sorted keys, compact separators, UTF-8).
 *
 * Wire form must match Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
 * and Rust's `tn_core::canonical::canonical_bytes`.
 */
export function canonicalJsonBytes(obj: unknown): Uint8Array {
  return canonicalize(obj);
}

// --------------------------------------------------------------------------
// Per-admin-event canonical scenarios. Each entry's `fields` is the exact
// emit-time payload `canonicalize(...)` runs over for the row_hash. Mirrored
// byte-for-byte by the Python + Rust builders. Adding an event_type here
// pins the canonical shape across all three SDKs.
// --------------------------------------------------------------------------

const ADMIN_EVENT_SCENARIOS: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
  [
    "tn.ceremony.init",
    {
      ceremony_id: "cer_byte_compare_canonical_2026",
      cipher: "btn",
      device_did: CANONICAL_DID,
      created_at: "2026-04-25T18:00:00.000000Z",
    },
  ],
  [
    "tn.group.added",
    {
      group: "default",
      cipher: "btn",
      publisher_did: CANONICAL_DID,
      added_at: "2026-04-25T18:00:01.000000Z",
    },
  ],
  [
    "tn.recipient.added",
    {
      group: "default",
      leaf_index: 7,
      recipient_did: "did:key:zRecipientCanonical",
      kit_sha256: "sha256:" + "a".repeat(64),
      cipher: "btn",
    },
  ],
  [
    "tn.recipient.revoked",
    {
      group: "default",
      leaf_index: 7,
      recipient_did: "did:key:zRecipientCanonical",
    },
  ],
  [
    "tn.coupon.issued",
    {
      group: "default",
      slot: 3,
      to_did: "did:key:zCouponHolder",
      issued_to: "did:key:zCouponHolder",
    },
  ],
  [
    "tn.rotation.completed",
    {
      group: "default",
      cipher: "btn",
      generation: 2,
      previous_kit_sha256: "sha256:" + "b".repeat(64),
      old_pool_size: 12,
      new_pool_size: 24,
      rotated_at: "2026-04-25T18:00:02.000000Z",
    },
  ],
  [
    "tn.enrolment.compiled",
    {
      group: "default",
      peer_did: "did:key:zPeerEnrolment",
      package_sha256: "sha256:" + "c".repeat(64),
      compiled_at: "2026-04-25T18:00:03.000000Z",
    },
  ],
  [
    "tn.enrolment.absorbed",
    {
      group: "default",
      from_did: "did:key:zSenderEnrolment",
      package_sha256: "sha256:" + "c".repeat(64),
      absorbed_at: "2026-04-25T18:00:04.000000Z",
    },
  ],
  [
    "tn.vault.linked",
    {
      vault_did: "did:web:vault.example",
      project_id: "proj_byte_compare",
      linked_at: "2026-04-25T18:00:05.000000Z",
    },
  ],
  [
    "tn.vault.unlinked",
    {
      vault_did: "did:web:vault.example",
      project_id: "proj_byte_compare",
      reason: "operator_initiated",
      unlinked_at: "2026-04-25T18:00:06.000000Z",
    },
  ],
  [
    "tn.agents.policy_published",
    {
      policy_uri: CANONICAL_POLICY_PATH,
      version: "1",
      content_hash:
        "sha256:79e0aefecfce8b26d2ea3be0026effee96c9c7aaa8f189d0236fa555eabbb36e",
      event_types_covered: [
        "order.created",
        "payment.completed",
        "tn.recipient.added",
      ],
      policy_text: CANONICAL_POLICY_TEXT,
    },
  ],
  [
    "tn.read.tampered_row_skipped",
    {
      envelope_event_id: "01HXYZ0000000000000000PAY1",
      envelope_did: CANONICAL_DID,
      envelope_event_type: "payment.completed",
      envelope_sequence: 2,
    },
  ],
];

/** Build the `admin_events_canonical.json` payload — per-event canonical
 * bytes for every admin event_type in the catalog. Mirrors Python +
 * Rust output byte-for-byte.
 */
export function buildAdminEventsCanonical(): Record<string, unknown> {
  const top: Record<string, unknown> = {};
  for (const [eventType, fields] of ADMIN_EVENT_SCENARIOS) {
    const cb = canonicalize(fields);
    top[eventType] = {
      fields,
      canonical_bytes_hex: hexEncode(cb),
      canonical_bytes_len: cb.length,
    };
  }
  return top;
}
