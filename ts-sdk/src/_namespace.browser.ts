// Named aggregate of the browser surface, so consumers can write:
//
//     import { tn } from "tn-proto/browser";
//     await tn.init();
//     tn.info("event.type", { a: 1 });
//
// Mirrors src/_namespace.ts for the browser entry. Re-exports the whole
// module namespace of `./index.browser.js` under the name `tn`; the
// index.browser <-> _namespace.browser cycle is resolved by ESM live
// bindings.
export * as tn from "./index.browser.js";
