import { canonicalBytes, canonicalJson } from "./raw.js";

/** Recursively reject NaN / +Infinity / -Infinity so we match Python's
 * `canonical_bytes` contract. Without this check, JSON.stringify (which the
 * wasm layer uses internally) silently coerces them to `null`, which would
 * produce a different row_hash than Python for the same input. */
function assertFinite(value: unknown): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalize: float NaN/inf not supported in canonical form");
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) assertFinite(v);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const v of Object.values(value)) assertFinite(v);
  }
}

/** Canonicalize a JSON value to sorted-keys / no-whitespace bytes. */
export function canonicalize(value: unknown): Uint8Array {
  assertFinite(value);
  return canonicalBytes(value);
}

/** Canonicalize and decode to UTF-8. Useful for tests and debugging. */
export function canonicalizeToString(value: unknown): string {
  assertFinite(value);
  return canonicalJson(value);
}
