// Named aggregate of the public surface, so consumers can write the
// idiomatic named import and still keep the `tn.` prefix that mirrors
// Python's `import tn`:
//
//     import { tn } from "tn-proto";
//     await tn.init(yamlPath);
//     tn.info("event.type", { a: 1 });
//
// This re-exports the whole module namespace of `./index.js` under the name
// `tn`. `index.ts` re-exports `{ tn }` from here; the index <-> _namespace
// cycle is resolved by ESM live bindings (the verbs are defined by the time
// any `tn.*` member is called).
export * as tn from "./index.js";
