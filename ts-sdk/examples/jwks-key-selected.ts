// Demonstrates the intended integration boundary for trusted JWKS discovery:
// build audit-friendly fields from a trusted key decision, then emit the
// standard tn.jwks.key_selected event. This example intentionally does not
// fetch over the network; callers should pass a JWKS document fetched and
// reviewed according to their trust policy.

import {
  jwksKeySelectedEvent,
  TN_JWKS_KEY_SELECTED_EVENT,
  trustedJwksEncryptionRecipient,
} from "../src/core/jwks.js";
import { jweSeal } from "../src/core/jwe.js";

interface JwksEventEmitter {
  infoAsync(eventType: string, fields?: Record<string, unknown>): Promise<unknown>;
}

export async function sealWithTrustedJwksAndRecordSelection(
  tn: JwksEventEmitter,
  jwksJson: unknown,
  pinned: { issuer: string; jwksFingerprint: string },
  payload: Uint8Array,
): Promise<Uint8Array> {
  const recipient = trustedJwksEncryptionRecipient(jwksJson, {
    policy: "pinned",
    pinned,
  });

  const fields: Record<string, unknown> = {
    ...jwksKeySelectedEvent(recipient, {
      selectedAt: new Date().toISOString(),
    }),
  };
  await tn.infoAsync(TN_JWKS_KEY_SELECTED_EVENT, fields);

  return jweSeal([recipient], payload);
}
