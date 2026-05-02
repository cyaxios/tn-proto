# @tnproto/sdk/core

Layer 1 of the TN TypeScript SDK. Pure functions over wasm-backed crypto.
Browser-safe — no `node:*` imports allowed (enforced by ESLint and a
runtime test in `test/core_no_node_imports.test.ts`).

## Consumers

- `@tnproto/sdk` (Layer 2; Node entry) wraps this.
- `extensions/tn-decrypt/` (Chrome MV3) is the canonical browser consumer
  and the reason this layer exists. Anything the extension needs to
  decrypt or render envelopes lives here.

## What's in here

- `branded.ts` — branded type helpers (`Did`, `RowHash`, `SignatureB64`)
- `types.ts` — shared structural types (envelopes, admin state, read entries)
- `canonical.ts` — canonical-bytes serialization (matches Python byte-for-byte)
- `chain.ts` — `rowHash`, `ZERO_HASH`, `sha256Hex` (over `@noble/hashes`)
- `signing.ts` — Ed25519 sign/verify
- `indexing.ts` — `deriveGroupKey`, `indexTokenFor` (HMAC-based field index)
- `envelope.ts` — `buildEnvelopeLine` for ndjson emission
- `primitives.ts` — low-level wasm primitives
- `tnpkg.ts` — manifest helpers (sign / verify / canonicalize)
- `tnpkg_archive.ts` — zip pack/parse over `Uint8Array` (uses `fflate`)
- `agents_policy.ts` — markdown parser for `.tn/config/agents.md`
- `read_shape.ts` — flatten `ReadEntry` → flat dict (the default `tn.read()` shape)
- `decrypt.ts` — cipher-aware envelope decrypt (`btn` today, `jwe` ready to wire)
- `errors.ts` — Error subclasses (`VerificationError`, `ChainConflictError`, …)
- `admin/state.ts` — `AdminStateReducer` (pure event-fold; the persistence + log-tailing wrapper is `../admin/cache.ts` in Layer 2)
- `admin/catalog.ts` — wasm-backed admin catalog (`reduce`, `catalogKinds`, `validateEmit`)

## What's NOT in here

If you need filesystem, network, yaml parsing, handlers, or a `Tn`
instance, you are in the wrong layer — see `../tn.ts` (Layer 2) and the
matching Layer 2 helpers (`../tnpkg_io.ts`, `../agents_policy.ts`,
`../admin/cache.ts`, `../admin/log.ts`).
