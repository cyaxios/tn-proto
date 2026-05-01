// Helper for the positional-`message` ergonomic shared by
// `TNClient.log/info/warning/error/debug`. Mirrors Python's behavior:
//
//   normalize(undefined)              -> {}
//   normalize("hi")                   -> {message: "hi"}
//   normalize("hi", {port: 8080})     -> {message: "hi", port: 8080}
//   normalize({port: 8080})           -> {port: 8080}
//
// Kept in its own tiny module (no `tn-wasm` dep) so the shape is unit-
// testable without standing up a full TNClient ceremony.

/** Normalize the (msg|fields, fieldsIfMessage) arg pair into a plain
 * fields dict. If the first arg is an object, the second arg is ignored
 * (callers should not pass both). If the user supplies their own
 * `message` key in the fields object, it wins over the positional
 * string (kwargs override). */
export function normalizeLogFields(
  msgOrFields: string | Record<string, unknown> | undefined,
  fieldsIfMessage: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (msgOrFields === undefined) {
    return fieldsIfMessage ?? {};
  }
  if (typeof msgOrFields === "string") {
    const out: Record<string, unknown> = { message: msgOrFields };
    if (fieldsIfMessage) {
      for (const [k, v] of Object.entries(fieldsIfMessage)) {
        out[k] = v;
      }
    }
    return out;
  }
  return msgOrFields;
}
