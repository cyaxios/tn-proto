import { buildEnvelope as rawBuildEnvelope } from "../raw.js";
import type { Envelope } from "./types.js";

/**
 * Render an envelope to an ndjson line (ends with `\n`).
 *
 * Key order: the 9 mandatory scalar fields first, then `publicFields`
 * in insertion order (skipping any that collide with a mandatory key),
 * then `groupPayloads` in insertion order.
 */
export function buildEnvelopeLine(env: Envelope): string {
  return rawBuildEnvelope({
    did: env.did,
    timestamp: env.timestamp,
    event_id: env.eventId,
    event_type: env.eventType,
    level: env.level,
    sequence: env.sequence,
    prev_hash: env.prevHash,
    row_hash: env.rowHash,
    signature_b64: env.signatureB64,
    public_fields: env.publicFields ?? {},
    group_payloads: env.groupPayloads ?? {},
  });
}
