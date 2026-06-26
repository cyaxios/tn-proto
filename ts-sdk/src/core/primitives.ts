// Primitives namespace: re-exports the lower-level crypto + chain helpers
// that the TS SDK builds on. Gives callers a single stable name
// (`primitives.foo`) so app code doesn't pin against the flat top-level
// surface, which we want to be free to reorganize later.
//
// Top-level re-exports (e.g. `import { canonicalize } from "tn-proto"`)
// remain in place for backward compatibility with existing consumers.

export * from "./canonical.js";
export * from "./chain.js";
export * from "./envelope.js";
export * from "./indexing.js";
export * from "./signing.js";
