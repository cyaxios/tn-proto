# @cyaxios/tn-proto

TypeScript / Node SDK for **TN** — signed, encrypted, append-only logging where every entry is a verifiable transaction. The Rust core ships **bundled inside the package** as WebAssembly, and produces byte-for-byte the same records as the Python SDK, so a row written in Node can be decoded in Python or the browser and vice versa.

## Install

```bash
npm install @cyaxios/tn-proto
```

One package, one import — the wasm engine is bundled in, so there is nothing else to install and no native toolchain to set up. Node ≥ 20.

> This is an alpha. The API and on-the-wire format may still change; pin an exact version for anything you depend on, and install the alpha line with `npm install @cyaxios/tn-proto@alpha`.

## Quickstart

```ts
import * as tn from "@cyaxios/tn-proto";

await tn.init("./tn.yaml");   // mints a fresh ceremony if absent (or: tn.use("billing"))

tn.info("order.created", { order_id: "A100", amount: 4999 });
tn.warning("order.flagged", { order_id: "A100", reason: "hold" });

// Read it back. Each row is decrypted and returned as a typed Entry.
for (const entry of tn.read({ allRuns: true })) {
  console.log(entry.event_type, entry.fields);
}

await tn.close();
```

Every entry is Ed25519-signed and hash-chained to the previous one. `tn.read({ verify: true })` re-verifies the chain and signatures and throws on any tampering. Fields are encrypted on disk; only readers you grant can decrypt them.

## API surface

```ts
// Emit (sync). Same level set as Python.
tn.log / tn.debug / tn.info / tn.warning / tn.error

// Read (sync iterator) and tail (async iterator).
tn.read(opts?)              // { allRuns?, verify?, log?, raw?, where? }
tn.watch(opts?)             // for await (const e of tn.watch({ since: "now" })) { ... }

// Contextual fields.
tn.scope(fields, body) / tn.setContext / tn.updateContext / tn.clearContext

// Namespaced verbs (async — they touch disk and/or the vault).
tn.admin.{ addRecipient, revokeRecipient, rotate, ensureGroup, recipients, state }
tn.pkg.{ export, absorb, bundleForRecipient }
tn.vault.{ link, unlink }
tn.agents.{ addRuntime, policy }
tn.handlers.{ add, list, flush }

// Process-global toggles (also bare exports).
import { setLevel, setSigning } from "@cyaxios/tn-proto";
setLevel("info");           // stdlib-style threshold; drops debug()
setSigning(false);          // skip Ed25519 for hot-loop tracing
```

Namespace verbs return structured result objects (recipient kit paths, bundle receipts, rotation outcomes) so you never have to re-parse files to learn what happened.

## Tailing the log

```ts
for await (const entry of tn.watch({ since: "now" })) {     // live tail
  console.log(entry.event_type, entry.fields);
}
// since also accepts "start", a sequence number, or an ISO-8601 timestamp.
```

`tn.watch` tracks byte offset, never re-reads prior bytes, and survives file rotation. A CLI ships too:

```bash
tn-js watch --yaml ./tn.yaml | jq .
```

## Browser and extensions

`@cyaxios/tn-proto/core` is a Node-free subpath (no `node:*` imports, enforced at build time) for MV3 extensions, browser bundles, and other non-Node hosts. It exposes the verify/decrypt primitives:

```ts
import { decryptGroup, flattenRawEntry, AdminStateReducer } from "@cyaxios/tn-proto/core";
```

## Errors

Thrown errors are real `Error` subclasses you can route on:

```ts
import { VerificationError, ChainConflictError } from "@cyaxios/tn-proto";

try {
  for (const _ of tn.read({ verify: true })) { /* ... */ }
} catch (e) {
  if (e instanceof VerificationError) console.error("tampered:", e.envelope.event_type);
  else throw e;
}
```

## Performance and log levels

The default config signs every entry and echoes a JSON envelope to stdout — the right default for an audit log. For high-volume tracing, turn either off:

```ts
await tn.init("./tn.yaml", { stdout: false });   // or set TN_NO_STDOUT=1
setSigning(false);                                 // skip signatures
setLevel("warning");                               // drop debug + info
```

## Documentation

- [Getting started](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/getting-started.md) and the [TypeScript cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-typescript.md)
- [Groups, readers, bundles, rotation](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/groups-readers-rotation.md) — sharing and access control
- [Advanced usage](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/advanced-usage.md) — reading modes, scoped lifecycles, templated paths, cross-language parity
- [Protocol](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/protocol.md) — the on-the-wire record format

The Python SDK is the cross-language counterpart: [`tn-proto` on PyPI](https://pypi.org/project/tn-proto/). Both bindings share one Rust core and agree on the wire down to the byte.

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
