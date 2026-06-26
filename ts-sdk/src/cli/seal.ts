// `tn-js seal` — stdin filter that signs public-only events.
//
// Reads one JSON object per line from stdin (the seal-input shape: a
// device seed plus the envelope scalars and optional public fields) and
// writes one envelope ndjson line per input to stdout. TypeScript port of
// the inline `sealCmd` in `bin/tn-js.mjs`; behaviour, stdout bytes, and
// exit codes are verbatim (spawn-based tests assert exact output).

import { Buffer } from "node:buffer";
import { stdout } from "node:process";

import { DeviceKey } from "../core/signing.js";
import { rowHash } from "../core/chain.js";
import { buildEnvelopeLine } from "../core/envelope.js";
import { signatureB64 } from "../core/signing.js";
import { asRowHash } from "../core/types.js";
import { forEachLine, cliDie } from "./_stdin.js";

/** Per-line seal input. Mirrors the documented seal-input JSON shape; all
 *  required scalars plus optional `public_fields`. */
interface SealInput {
  seed_b64: string;
  event_type: string;
  level: string;
  sequence: number;
  prev_hash: string;
  timestamp: string;
  event_id: string;
  public_fields?: Record<string, unknown>;
}

/**
 * Execute `tn-js seal`. Reads seal-input JSON lines from stdin and writes
 * one envelope ndjson line per input. Returns the process exit code (0).
 * A missing required field or unparsable line exits the process via
 * `cliDie` (exit 2).
 */
export async function sealCmd(): Promise<number> {
  await forEachLine((raw) => {
    const inp = raw as SealInput;
    const required = [
      "seed_b64",
      "event_type",
      "level",
      "sequence",
      "prev_hash",
      "timestamp",
      "event_id",
    ];
    for (const k of required) {
      if (!(k in (inp as unknown as Record<string, unknown>))) cliDie(`seal: missing field ${k}`);
    }
    const seed = new Uint8Array(Buffer.from(inp.seed_b64, "base64"));
    const dk = DeviceKey.fromSeed(seed);

    const rh = rowHash({
      device_identity: dk.did,
      timestamp: inp.timestamp,
      eventId: inp.event_id,
      eventType: inp.event_type,
      level: inp.level,
      prevHash: asRowHash(inp.prev_hash),
      publicFields: inp.public_fields ?? {},
    });

    const sig = dk.sign(new Uint8Array(Buffer.from(rh, "utf8")));
    const sigB64 = signatureB64(sig);

    const line = buildEnvelopeLine({
      device_identity: dk.did,
      timestamp: inp.timestamp,
      eventId: inp.event_id,
      eventType: inp.event_type,
      level: inp.level,
      sequence: inp.sequence,
      prevHash: asRowHash(inp.prev_hash),
      rowHash: rh,
      signatureB64: sigB64,
      publicFields: inp.public_fields ?? {},
    });
    stdout.write(line);
  });
  return 0;
}
