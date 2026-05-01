# @tn/sdk

TypeScript SDK for TN. Thin, typed wrapper over `tn-wasm` (which is
compiled from the `tn-core` Rust crate). One Rust core, three bindings:
PyO3 (Python), wasm-bindgen (JS/TS), and, later, napi-rs (Node native).

If you find yourself writing a new crypto primitive in TypeScript, stop.
Add it to `tn-core` first, then expose it through `tn-wasm`, then wrap
it here. Divergence between the Python and TS surfaces is a bug.

## Install

The package depends on the local `tn-wasm` build. After modifying the
Rust core:

```
cd ../crypto/tn-wasm
wasm-pack build --target nodejs --release
cd ../../ts-sdk
npm install            # picks up the new pkg via file:../crypto/tn-wasm/pkg
npm run build
npm test
```

## Surface

```ts
import {
  DeviceKey, verify, signatureB64,
  canonicalize, canonicalizeToString,
  rowHash, ZERO_HASH,
  deriveGroupKey, indexTokenFor,
  buildEnvelopeLine,
  admin,
} from "@tn/sdk";
```

- `DeviceKey` wraps an Ed25519 seed; `generate()` / `fromSeed(bytes)` /
  `sign(msg)` / `signB64(msg)` / `did` / `publicKey` / `seed`.
- `verify(did, msg, sig)` static check.
- `canonicalize(value)` returns canonical bytes; `canonicalizeToString`
  returns the UTF-8 decoded form.
- `rowHash(input)` and `ZERO_HASH`.
- `deriveGroupKey`, `indexTokenFor` for the HKDF + HMAC index.
- `buildEnvelopeLine(envelope)` for the ndjson line.
- `admin.reduce`, `admin.catalogKinds`, `admin.validateEmit` for the
  admin catalog.

Need something lower-level? `@tn/sdk/raw` re-exports every tn-wasm
function verbatim.

## Performance and log levels

Default config writes a JSON envelope to `process.stdout` AND signs every
event with Ed25519. For an audit log this is the right default. For
hot-loop tracing or benchmarks where you don't need either of those:

```ts
// Stdout — opt-out at init or via env var:
const c = TNClient.init("./tn.yaml", { stdout: false });
// or process.env.TN_NO_STDOUT = "1";

// Signing — toggle for the session:
TNClient.setSigning(false);
TNClient.setSigning(null);   // restore yaml default

// Log-level threshold — stdlib-style filtering:
TNClient.setLevel("info");      // drops debug() emits
TNClient.setLevel("warning");   // drops debug + info
TNClient.setLevel("error");     // drops everything below error

if (TNClient.isEnabledFor("debug")) {
  client.debug("snapshot", { tree: expensiveTreeDump(root) });
}
```

Verbs whose level is below the threshold short-circuit before any
work happens — no encryption, no chain advance, no I/O. Default is
`"debug"` (the floor); the severity-less `client.log()` always emits
regardless of the threshold.

Yaml `ceremony.log_level: "info"` in `tn.yaml` sets a fresh-process
default; programmatic `setLevel(...)` takes precedence.

## Interop contract

Byte-identical with Python. The interop test suite lives alongside the
WASM crate: `tn-protocol/crypto/tn-wasm/test/`. It drives the same
primitives from Node and from Python's `tn` module and fails on any
diff, including whitespace or key ordering.

## Open questions

- Package name: `@tn/sdk` is a placeholder; could be `@tnproto/sdk`.
- When published, the `tn-wasm` dep becomes a real npm package rather
  than a `file:` link.
