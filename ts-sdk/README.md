# @tnproto/sdk

TypeScript SDK for the [TN protocol](https://github.com/cyaxios/tn-proto)
— attested logging with broadcast encryption.

A thin, typed wrapper over `tn-wasm` (compiled from the `tn-core` Rust
crate). One Rust core, three bindings: PyO3 (Python), wasm-bindgen
(JS/TS), napi-rs (Node native — future). The TS surface mirrors Python
verb-for-verb; divergence between the two is a bug. See
[`docs/sdk-parity.md`](https://github.com/cyaxios/tn-proto/blob/main/docs/sdk-parity.md)
for the full table.

## Install

```bash
npm install @tnproto/sdk
```

Node ≥ 20 required. The package ships a Node entry plus a browser-safe
`@tnproto/sdk/core` subpath for use in MV3 extensions and other
no-fs environments.

## Quickstart

```ts
import { Tn } from "@tnproto/sdk";

const tn = await Tn.init("./tn.yaml");          // mints a fresh ceremony if absent
tn.info("order.created", { order_id: "A100", amount: 4999 });

for (const entry of tn.read()) {
  console.log(entry.event_type, entry.order_id);
}

await tn.close();
```

`Tn.init()` is async to leave room for future bootstrap work (vault
prefetch, remote ceremony fetch). Most user code is sync — only verbs
that touch disk or the network are `Promise<T>`.

## Surface

```ts
import { Tn } from "@tnproto/sdk";

// Hot path — sync.
tn.log / tn.debug / tn.info / tn.warning / tn.error
tn.read(opts?)                                 // sync, Iterable<Entry>
tn.scope(fields, body)                         // contextual logging
tn.setContext / updateContext / clearContext / getContext

// Tail-aware — async-iterable.
tn.watch(opts?)                                // for await (const e of tn.watch()) { ... }

// Namespaced verbs — async (touch disk and/or network).
tn.admin.{addRecipient, revokeRecipient, rotate, ensureGroup, recipients, state, cache, revokedCount}
tn.pkg.{export, absorb, bundleForRecipient, compileEnrolment, offer}
tn.vault.{link, unlink, setLinkState}
tn.agents.{addRuntime, policy, reloadPolicy}
tn.handlers.{add, list, flush}

// Process-global toggles — also exported as bare functions.
import { setLevel, setSigning, setStrict } from "@tnproto/sdk";
setLevel("info");
setSigning(false);     // hot-loop tracing — turn off Ed25519 entirely
```

Every namespace verb returns a structured result object (e.g.
`AddRecipientResult`, `BundleResult`, `OfferReceipt`) so consumers
don't re-parse kit files or re-derive timestamps to learn what
just happened.

## Tailing the log

```ts
// Tail forever — yields entries as they're appended.
for await (const entry of tn.watch({ since: "now" })) {
  console.log(entry.event_type, entry.order_id);
}

// Replay everything.
for await (const entry of tn.watch({ since: "start" })) { ... }

// Resume from a specific sequence number (per event-type sequence).
for await (const entry of tn.watch({ since: 42 })) { ... }

// Resume from an ISO-8601 timestamp.
for await (const entry of tn.watch({ since: "2026-05-01T12:00:00.000Z" })) { ... }
```

`tn.watch` tracks byte offset, never re-reads prior bytes, and survives
file rotation (inode change → reset to 0 of the new file). Truncation
emits a `tn.watch.truncation_observed` admin event so monitoring
catches the case.

There's also a CLI:

```bash
tn-js watch --yaml ./tn.yaml                    # follow, decoded JSONL
tn-js watch --yaml ./tn.yaml --once             # dump current log and exit
tn-js watch --yaml ./tn.yaml --since 42         # resume from sequence 42
```

Pipe into any JSON-aware tailer:

```bash
tn-js watch --yaml ./tn.yaml | jq -C .
tn-js watch --yaml ./tn.yaml | humanlog
```

## Browser / extension use

```ts
import { decryptGroup, flattenRawEntry, AdminStateReducer } from "@tnproto/sdk/core";
import { importEmk, wrapKeystoreSecret } from "@tnproto/sdk/core";
```

`@tnproto/sdk/core` (Layer 1) has no `node:*` imports — verified by
ESLint at build time and by a runtime smoke test. Use this entry from
MV3 extensions, browser bundles, or any non-Node host. The Layer 1
surface includes:

- Crypto primitives: `canonicalize`, `rowHash`, `sha256Hex`, `verify`, `signatureB64`.
- Read-shape projection: `flattenRawEntry`.
- Cipher-aware decrypt: `decryptGroup`, `decryptAllGroups`. btn ships today; jwe-ready dispatch is in place.
- Admin-state derivation: `AdminStateReducer` — pure event-fold, no fs.
- Browser-safe zip: `packTnpkg`, `parseTnpkg` (uses `fflate` under the hood).
- Audited EMK helpers: `importEmk`, `deriveEmkFromPassphrase`, `emkFromPrfOutput`, `makeVerifier`, `wrapKeystoreSecret`, `unwrapKeystoreSecret`.
- Errors-as-classes: `VerificationError`, `ChainConflictError`, `RotationConflictError`, `LeafReuseError`, `SameCoordinateForkError`.

The Chrome extension at
[`extensions/tn-decrypt/`](https://github.com/cyaxios/tn-proto/tree/main/extensions/tn-decrypt)
is a working consumer.

## Performance and log levels

Default config writes a JSON envelope to `process.stdout` AND signs every
event with Ed25519. For an audit log this is the right default. For
hot-loop tracing or benchmarks where you don't need either:

```ts
// Stdout — opt-out at init or via env var:
const tn = await Tn.init("./tn.yaml", { stdout: false });
// or process.env.TN_NO_STDOUT = "1";

// Signing — process-global toggle:
Tn.setSigning(false);
Tn.setSigning(null);          // restore yaml default

// Per-call sign override (wins over the global toggle):
tn.emitOverrideSign("info", "evt.unsigned", { x: 1 }, false);

// Log-level threshold — stdlib-style filtering:
Tn.setLevel("info");          // drops debug() emits
Tn.setLevel("warning");       // drops debug + info
Tn.setLevel("error");         // drops everything below error

if (Tn.isEnabledFor("debug")) {
  tn.debug("snapshot", { tree: expensiveTreeDump(root) });
}
```

Yaml `ceremony.log_level: "info"` in `tn.yaml` sets a fresh-process
default; programmatic `Tn.setLevel(...)` takes precedence.

## Cross-language parity

The TS surface mirrors Python's `tn` module verb-for-verb. See
[`docs/sdk-parity.md`](https://github.com/cyaxios/tn-proto/blob/main/docs/sdk-parity.md)
for the table; new verbs MUST add a row before the SDK can publish
(CI gate at `tools/check_parity.py`).

## Errors

All thrown errors are real `Error` subclasses you can `instanceof` route:

```ts
import { VerificationError, ChainConflictError } from "@tnproto/sdk";

try {
  for (const entry of tn.secureRead({ onInvalid: "raise" })) { ... }
} catch (e) {
  if (e instanceof VerificationError) {
    console.error("tampered envelope:", e.envelope.event_type, e.invalidReasons);
  } else {
    throw e;
  }
}
```

## Layout

```
src/
  index.ts                  Layer 2 entry — Tn class + namespaces + types
  tn.ts                     Tn class itself
  watch.ts                  tn.watch (tail-aware async-iterable)
  admin/                    tn.admin namespace (Layer 2) + AdminStateCache
  pkg/                      tn.pkg namespace (Layer 2)
  vault/                    tn.vault namespace (Layer 2)
  agents/                   tn.agents namespace (Layer 2)
  handlers/                 handler implementations + tn.handlers namespace
  runtime/                  NodeRuntime (the engine the namespaces wrap)
  core/                     Layer 1 — browser-safe by ESLint enforcement
    canonical.ts            canonical-bytes serialization (Python-compatible)
    chain.ts                rowHash, ZERO_HASH, sha256Hex (over @noble/hashes)
    signing.ts              Ed25519 sign/verify
    indexing.ts             deriveGroupKey, indexTokenFor
    envelope.ts             buildEnvelopeLine for ndjson
    primitives.ts           low-level wasm wrappers
    types.ts                shared structural types (Envelope, ReadEntry, AdminState, ...)
    branded.ts              Did, RowHash, SignatureB64
    errors.ts               5 Error subclasses
    decrypt.ts              cipher-aware envelope decrypt (btn today; jwe-ready)
    read_shape.ts           flattenRawEntry projection
    tnpkg.ts                manifest helpers (sign / verify / canonicalize)
    tnpkg_archive.ts        packTnpkg / parseTnpkg over Uint8Array (fflate)
    encoding.ts             bytesToB64 / b64ToBytes / randomBytes
    emk.ts                  Audited EMK helpers (extension master key)
    agents_policy.ts        Markdown parser for .tn/config/agents.md
    admin/state.ts          AdminStateReducer (pure event-fold)
    admin/catalog.ts        wasm-backed admin catalog
  raw.ts                    Layer 0 — verbatim re-exports of tn-wasm
```

## License

Apache-2.0. See [LICENSE](../LICENSE).
