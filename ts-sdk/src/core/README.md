# @tnproto/sdk/core

Layer 1 of the TN TypeScript SDK. Pure functions over wasm-backed crypto.
Browser-safe — no `node:*` imports allowed (enforced by ESLint).

Consumers:
- `@tnproto/sdk` (Layer 2; Node entry) wraps this.
- `extensions/tn-decrypt/` (Chrome MV3) imports from here directly.

If you need filesystem, network, yaml, handlers, or a `Tn` instance, you
are in the wrong layer — see `../tn.ts` for Layer 2.
