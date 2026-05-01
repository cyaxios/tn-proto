// @tnproto/sdk/core — Layer 1 of the SDK.
//
// Browser-safe by construction: this directory and its descendants MUST NOT
// import from `node:*`, `fs`, `path`, `os`, `child_process`, or Node's
// `crypto` module. Random bytes come from globalThis.crypto (Web Crypto API)
// or via the wasm core's getrandom binding. ESLint enforces this rule;
// see ../../eslint.config.js.
//
// This barrel re-exports the public surface of every Layer 1 module.
// Phase 1 of the 0.3.0 refresh is moving modules in here one by one;
// see docs/superpowers/plans/2026-05-01-ts-sdk-refresh.md.

export {};  // populated by subsequent tasks in this phase
