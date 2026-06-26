// `tn-js verify` — stdin filter that verifies public-only envelopes.
//
// Reads envelope ndjson lines from stdin and writes one result line per
// input: `{"ok": true, ...}` on success or `{"ok": false, "reason": ...}`
// on any failure. TypeScript port of the inline `verifyCmd` in
// `bin/tn-js.mjs`; behaviour, stdout bytes, and exit codes are verbatim
// (spawn-based tests assert exact output). Group-payload envelopes are
// rejected — this is the public-only verify path.

import { Buffer } from "node:buffer";
import { stdout } from "node:process";

import { rowHash } from "../core/chain.js";
import { verify, signatureFromB64 } from "../core/signing.js";
import { asDid, asRowHash, asSignatureB64 } from "../core/types.js";
import { forEachLine } from "./_stdin.js";

/**
 * Execute `tn-js verify`. Reads envelope ndjson lines from stdin and
 * writes one result line per input. Returns the process exit code (0).
 */
export async function verifyCmd(): Promise<number> {
  await forEachLine((raw) => {
    const env = raw as Record<string, unknown>;
    try {
      // Rebuild the row-hash input from public-only envelope fields.
      const {
        device_identity,
        timestamp,
        event_id,
        event_type,
        level,
        sequence,
        prev_hash,
        row_hash,
        signature,
        ...rest
      } = env;

      for (const k of [
        "device_identity",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "sequence",
        "prev_hash",
        "row_hash",
        "signature",
      ]) {
        if (env[k] === undefined) {
          return stdout.write(
            JSON.stringify({ ok: false, reason: `missing ${k}`, event_id }) + "\n",
          );
        }
      }

      // rest may carry public fields and group payloads. Split them.
      const publicFields: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(rest)) {
        if (v && typeof v === "object" && !Array.isArray(v) && "ciphertext" in v) {
          // Group payload. Not handled in the public-only verify path.
          return stdout.write(
            JSON.stringify({
              ok: false,
              reason: `group payload ${k} present; public-only verify`,
              event_id,
            }) + "\n",
          );
        }
        publicFields[k] = v;
      }

      const recomputed = rowHash({
        device_identity: asDid(device_identity as string),
        timestamp: timestamp as string,
        eventId: event_id as string,
        eventType: event_type as string,
        level: level as string,
        prevHash: asRowHash(prev_hash as string),
        publicFields,
      });

      if (recomputed !== row_hash) {
        return stdout.write(
          JSON.stringify({
            ok: false,
            reason: "row_hash mismatch",
            expected: recomputed,
            got: row_hash,
            event_id,
          }) + "\n",
        );
      }

      const sig = signatureFromB64(asSignatureB64(signature as string));
      const sigOk = verify(
        asDid(device_identity as string),
        new Uint8Array(Buffer.from(row_hash as string, "utf8")),
        sig,
      );
      if (!sigOk) {
        return stdout.write(
          JSON.stringify({ ok: false, reason: "bad signature", event_id }) + "\n",
        );
      }

      stdout.write(
        JSON.stringify({
          ok: true,
          did: device_identity,
          event_type,
          event_id,
          row_hash,
          sequence,
        }) + "\n",
      );
    } catch (e) {
      stdout.write(JSON.stringify({ ok: false, reason: `exception: ${(e as Error).message}` }) + "\n");
    }
  });
  return 0;
}
