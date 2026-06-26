// Synthesize an EmitReceipt for callers of methods that delegate to wasm
// (which returns void). We do this by reading the most recent envelope
// from the runtime's log after the emit and pulling its row_hash +
// sequence + event_id out — fields that live in the *public* envelope
// surface, so no decryption is required.
//
// We deliberately avoid `wasm.readFrom(logPath)` here: that path runs
// the full decrypt pipeline, which can fail after a rotation when the
// log contains envelopes from the previous epoch (the live kit can't
// decrypt them). The receipt only needs three top-level public fields,
// so a raw line read + JSON.parse is both faster and rotation-safe.
import { existsSync, readFileSync } from "node:fs";

import type { WasmRuntime } from "tn-wasm";
import type { EmitReceipt } from "../core/results.js";
import { asRowHash, type RowHash } from "../core/types.js";

/** Synthesize an EmitReceipt from a canonical envelope NDJSON line (the
 *  value returned by `wasm.emitReturningLine`). `null` / `undefined` —
 *  the emit was filtered by the log-level threshold and produced no
 *  envelope — yields a zero receipt. This is the templating-safe path:
 *  the line is the envelope regardless of which file it was written to,
 *  so it works for `./logs/{event_id}.ndjson` and friends where the row
 *  isn't in the single main log. */
export function receiptFromLine(line: string | null | undefined): EmitReceipt {
  if (line === null || line === undefined || line.trim() === "") {
    // Zero-receipt sentinel: a level-filtered emit (no envelope produced) or a
    // contained logging failure. The empty rowHash is intentional and bypasses
    // asRowHash, which only accepts a real "sha256:"+64hex digest — validating
    // the sentinel would throw and defeat the no-op/containment contract.
    return { eventId: "", rowHash: "" as RowHash, sequence: 0 };
  }
  let env: Record<string, unknown>;
  try {
    env = JSON.parse(line.trim()) as Record<string, unknown>;
  } catch (e) {
    throw new Error(
      `receiptFromLine: malformed envelope line: ${(e as Error).message}`,
      { cause: e },
    );
  }
  return {
    eventId: String(env["event_id"] ?? ""),
    rowHash: asRowHash(String(env["row_hash"] ?? "")),
    sequence: Number(env["sequence"] ?? 0),
  };
}

/** Read the last envelope and synthesize an EmitReceipt. The caller should
 *  invoke this *immediately* after a wasm.* method that wrote a single
 *  envelope; if multiple emits raced, you get the most recent.
 *
 *  `logPath` selects which file to read. Omit / undefined to read the
 *  runtime's main log (default, via wasm.readRaw which is the raw
 *  no-decrypt path); pass the admin-log path for `tn.*` events when
 *  the ceremony routes protocol events to a separate file. */
export function lastEmitReceipt(wasm: WasmRuntime, logPath?: string): EmitReceipt {
  // Path-driven branch: parse the file's last non-empty line directly.
  // Avoids wasm `readFrom` because that path decrypts every envelope
  // in the file and can fail on older epochs after a rotation.
  if (logPath !== undefined) {
    if (!existsSync(logPath)) {
      throw new Error(`lastEmitReceipt: log file does not exist: ${logPath}`);
    }
    const text = readFileSync(logPath, "utf8");
    let lastLine = "";
    for (const line of text.split(/\r?\n/)) {
      const s = line.trim();
      if (s) lastLine = s;
    }
    if (!lastLine) {
      throw new Error(`lastEmitReceipt: no envelopes in log (${logPath})`);
    }
    let env: Record<string, unknown>;
    try {
      env = JSON.parse(lastLine) as Record<string, unknown>;
    } catch (e) {
      throw new Error(
        `lastEmitReceipt: malformed envelope in ${logPath}: ${(e as Error).message}`,
        { cause: e },
      );
    }
    return {
      eventId: String(env["event_id"] ?? ""),
      rowHash: asRowHash(String(env["row_hash"] ?? "")),
      sequence: Number(env["sequence"] ?? 0),
    };
  }
  // Main-log default: use `readRaw` which yields the raw envelope shape
  // without the decrypt cost (and without rotation-epoch fragility).
  const entries = wasm.readRaw() as Array<{ envelope: Record<string, unknown> }>;
  if (entries.length === 0) {
    throw new Error("lastEmitReceipt: no envelopes in log");
  }
  const last = entries[entries.length - 1]!.envelope;
  return {
    eventId: String(last["event_id"] ?? ""),
    rowHash: asRowHash(String(last["row_hash"] ?? "")),
    sequence: Number(last["sequence"] ?? 0),
  };
}
