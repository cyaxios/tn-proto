# @tnproto/sdk — API quick reference

**For LLM coders + humans skimming.** One-line summaries, signatures,
one-line examples. The authoritative contract lives in the TSDoc on
each symbol; this file is the discovery map. Find a verb here, then
hover or read the TSDoc for the full contract.

Two entry shapes:

```ts
// Node (server-side, CLI, tests):
import { Tn } from "@tnproto/sdk";
import * as tn from "@tnproto/sdk";

// Browser (single-page apps, extensions, witness-style harnesses):
import { Tn } from "@tnproto/sdk/browser";
import * as tn from "@tnproto/sdk/browser";
```

The verb surface is identical between the two; only the runtime layer
differs (Node uses fs + the wasm pkg target; browser uses localStorage
+ the wasm pkg-web target).

---

## Start a client

### `Tn.init(opts?)`  /  `tn.init(opts?)`
Mint a fresh ceremony in storage (first call) or load the existing
one. Default storage: localStorage in browser, fs under
`./.tn/<stem>/` in Node.

```ts
const tn = await Tn.init();                       // default
const tn = await Tn.init({ http: INGEST_URL });   // ship envelopes
```

### `Tn.initFromSeed(opts)`  /  `tn.initFromSeed(opts)`  *(browser only)*
Adopt server-provisioned credentials (32-byte seed + pre-minted
publisher state). Defaults to in-memory storage and `console: false` —
witness pattern.

```ts
await tn.initFromSeed({
  seed: b64decode(PUBLISHER_SEED_B64),
  btnPublisherState: b64decode(BTN_PUBLISHER_STATE_B64),
  http: { url: INGEST_URL, headers: { "X-Agreement": agreementId } },
});
```

### `Tn.use(name, opts?)`  *(Node only; multi-ceremony)*
Open or auto-mint the ceremony at `.tn/<name>/tn.yaml`.

### `Tn.absorb(source)`  *(Node only today)*
Install an `identity_seed` / `project_seed` `.tnpkg` from a file path
or bytes.

---

## Emit events

Every emit auto-injects the process-singleton `run_id` and any active
`tn.scope()` overlay. The first argument is the event type (dotted
identifier, `[A-Za-z0-9._-]{1,64}`). The second argument can be a
string (auto-promoted to `{message: <str>}`) or a fields object. The
third argument is accepted only when the second was a string.

### `tn.log(eventType, fields?)`  —  severity-less
Always emits. Use for facts that must land regardless of level (audit
landmarks, schema migrations, ceremony boundaries).

```ts
tn.log("schema.migrated", { from: "v1", to: "v2" });
```

### `tn.debug(eventType, fields?)`  —  DEBUG (10)
Suppressed when `Tn.setLevel` threshold > DEBUG.

### `tn.info(eventType, fields?)`  —  INFO (20)
The common emit verb. Routine business events.

```ts
tn.info("user.signed_in", { user_id: "u_123" });
```

### `tn.warning(eventType, fields?)`  —  WARNING (30)
Recoverable anomalies. Rate limits approaching, retries, degraded paths.

### `tn.error(eventType, fields?)`  —  ERROR (40)
Unrecoverable failures. Caught exceptions, terminal protocol errors.

---

## Read entries back

### `tn.read()`  →  `Array<flat entry>`
Flat-shaped entries — envelope basics (`timestamp`, `event_type`,
`level`, `did`, `sequence`, `event_id`) plus every readable group's
decrypted fields hoisted to the top level. Matches Python's `tn.read()`
shape.

```ts
for (const e of tn.read()) {
  console.log(e.sequence, e.event_type, e.user_id);
}
```

### `tn.readRaw()`  →  `Array<{envelope, plaintext}>`
Audit-grade variant. Returns the full on-disk envelope (with
signatures, hashes, group ciphertext metadata) alongside per-group
plaintext maps.

### `tn.watch(opts?)`  *(Node only today)*
Tail the log live. Async iterable. Throws `NotYetWiredForBrowserError`
on browser.

---

## Process-state management

### `Tn.setLevel(level)` / `tn.setLevel(level)`
Set the process-wide level threshold (`"debug"` / `"info"` /
`"warning"` / `"error"`).

```ts
Tn.setLevel("warning");        // suppress debug + info
```

### `Tn.getLevel()` → `string`
Read the active threshold.

### `Tn.isEnabledFor(level)` → `boolean`
Cheap pre-check before constructing an expensive emit payload.

### `Tn.setStrict(enabled)` / `Tn.clearStrict()` / `Tn.isStrict()`
Control the no-yaml-found-throws behavior. Override > `TN_STRICT` env >
default false.

---

## Per-call context

### `tn.setContext(fields)` / `tn.updateContext(fields)` / `tn.clearContext()` / `tn.getContext()`
Long-lived context — merged into every subsequent emit until cleared.

```ts
tn.setContext({ tenant_id: "t_42", request_id: "r_99" });
tn.info("anything", { ... });   // includes tenant_id, request_id automatically
```

### `tn.scope(fields, body)`
Block-scoped overlay. Restores prior context after `body` returns or
throws.

```ts
tn.scope({ trace_id: "tr_1" }, () => {
  tn.info("step.entered");   // tagged with trace_id
});
// trace_id no longer in scope
```

---

## Side handlers (browser)

### `Tn.init({ console: true | false | ConsoleHandler })`
Default: true. Every emit also prints to
`globalThis.console.{debug|info|warn|error}` so DevTools' level filter
works. Pass `false` to silence. Pass a custom `ConsoleHandler` for
test capture / remote shipping.

### `Tn.init({ http: URL | HttpHandlerOptions })`
Default: off. Ship each attested envelope to a remote URL. Body is the
canonical ndjson bytes — byte-identical to what would persist to a log
file, so server-side signature checks work.

```ts
// URL only
await Tn.init({ http: "https://ingest.example.com/intake" });

// Full opts
await Tn.init({
  http: {
    url: INGEST_URL,
    headers: { "X-Agreement": agreementId },
    batchIntervalMs: 2000,        // 0 = immediate
    flushOnUnload: true,          // pagehide + beforeunload
  },
});
```

### `consoleHandler(opts?)` / `httpHandler(opts)`
Factory functions for the above when you want explicit control over a
`BrowserRuntime` outside of `Tn.init`.

---

## Storage adapters (browser)

### `localStorageStorageAdapter(opts?)`
Default for `Tn.init` in browser. Persists across page loads in the
same origin. ~5 MB per-origin quota.

### `memoryStorageAdapter()`
In-memory only. Default for `Tn.initFromSeed`. Use when you want every
page load to re-bootstrap from server-supplied credentials.

---

## Lifecycle

### `tn.flush()`
Drain pending out-of-process handlers (HTTP queue, future sinks)
without closing the runtime.

### `tn.close()`
Flush + close. Idempotent. `await tn.close()` before tab unload to make
sure queued envelopes ship.

---

## Cold-start from a vault API key (Node)

### `bootstrapFromApiKey(opts)` → `ApiKeyFetchResult | null`
Read `TN_API_KEY` from env (or accept explicit), run the full
challenge/verify/sealed-bundle/install flow. Returns `null` on
fallthrough; never throws.

```ts
const result = await bootstrapFromApiKey({ vaultDid: "did:web:vault.example.com" });
if (result && !result.receipt.rejectedReason) {
  // keystore is now hot at cwd
}
```

### `parseBearer(bearer)` → `ParsedBearer | null`
Split `tn_apikey_<43>_<22>` into raw bytes. Returns `null` on shape
failure.

### `challengeVerify(base, did, seed)` → `Promise<string | null>`
Run the vault's auth handshake. Returns JWT or `null`.

---

## Low-level primitives

### `canonicalBytes(value)` / `canonicalJson(value)`
Canonical-bytes encoding for a JSON value. Sorted keys, no whitespace.
Byte-identical to Python's `tn.canonical.canonical_bytes`.

### `computeRowHash(input)` → `"sha256:<hex>"`
Compute the row hash for an envelope skeleton. Server-side verifies
recompute matches.

### `zeroHash()` → `"sha256:0000..."`
The 64-zero prev_hash used for the first row in a new event_type
chain.

### `signMessage(seed, message)` → `Uint8Array(64)`
Ed25519 signature.

### `signatureB64(sig)` / `signatureFromB64(s)`
URL-safe base64 (no padding) encode/decode of signatures.

### `verifyDid(did, message, signature)` → `boolean`
Verify a signature against a `did:key:z…` identity.

### `BtnPublisher`
Class. `new BtnPublisher(seed | null)` to create, `.mint()` to issue a
reader kit, `.encrypt(plaintext)` to seal for current readers,
`.toBytes()` / `BtnPublisher.fromBytes(bytes)` to persist/restore.

### `DeviceKey`
Class. `DeviceKey.fromSeed(seed)` → `{seed, publicKey, did}` for the
publisher identity. `DeviceKey.generate()` to mint fresh.

---

## Sealed `.tnpkg` body cipher

### `encryptBodyBlob(body, key)` → `Uint8Array`
AES-256-GCM-encrypt a body member map. Plaintext is a STORED zip;
output is `nonce || ciphertext+tag`. Goes into the outer tnpkg's
`body/encrypted.bin` slot.

### `decryptBodyBlob(blob, key)` → `Map<string, Uint8Array>`
Inverse. Returns the body member map.

### `sealBekForRecipient(bek, recipientDid, aad)` → `RecipientWrap`
Producer side. Wraps the BEK under the recipient's `did:key:`.

### `unsealBekFromWrap(wrap, devicePrivSeed, aad)` → `Uint8Array`
Consumer side. Recovers the BEK from a wrap using the recipient's
seed.

### `manifestAadForWrap(manifest)` → `Uint8Array`
Compute the AAD that binds a recipient wrap to its manifest. AAD is
identical on producer and consumer sides; recipient_wrap[s] are
stripped before canonicalisation.

### `absorbSealedBootstrap(source, {seed, cwd})` → `Promise<AbsorbReceipt>`
The full sealed-bundle install flow: unseal BEK, decrypt body,
dispatch to project_seed / identity_seed installer. Never throws on
input errors — populates `receipt.rejectedReason` instead.

---

## Env vars (Node)

| Variable | Effect |
|---|---|
| `TN_YAML` | Explicit yaml path for `Tn.init()` discovery chain. |
| `TN_HOME` | Fallback `~/.tn/tn.yaml` discovery dir. |
| `TN_STRICT` | When truthy (`{1,true,yes,on}`), block fresh-mint. |
| `TN_RUN_ID` | Stamped by us at first `Tn` construction; wasm reads. |
| `TN_NO_STDOUT` | When `=1`, silences the stdout handler. |
| `TN_STDOUT_FORMAT` | `"pretty"` (default) or `"json"`. |
| `TN_STDOUT_INCLUDE_ADMIN` | When `=1`, allow `tn.*` admin events on stdout. |
| `TN_AUTOINIT_QUIET` | When `=1`, silences the auto-init banner. |
| `TN_VAULT_URL` | Vault base URL (default `https://vault.tn-proto.org`). |
| `TN_VAULT_DEFAULT_BASE` | `did:key:` vault hint (same default). |
| `TN_NO_LINK` | When `=1`, skip future auto-link paths. |
| `TN_API_KEY` | Bearer for the cold-start vault redeem. |

---

## Error types

### `NotYetWiredForBrowserError`
Thrown by placeholder browser verbs (`tn.admin.*`, `tn.watch`,
`Tn.use`, `Tn.absorb`, `Tn.ephemeral`). `instanceof`-check to
distinguish "not implemented yet" from real errors.

### `UnsealError`
Thrown by `unsealBekFromWrap` on any unseal failure (wrong recipient,
tampered wrap, malformed bytes). Catch and try the next wrap in a
multi-recipient bundle.

### `LocalStorageQuotaError`
Thrown by the localStorage adapter when a write would exceed the
per-origin quota (~5 MB). Carries `path` and `bytesAttempted` for
diagnostics.

---

## Cross-references

- **The Python reference implementation** of every verb here lives in
  `python/tn/`. Names are snake_case there (`tn.set_context` ↔
  `tn.setContext`).
- **The Rust core** that wasm wraps is at `crypto/tn-core/`.
- **The canonical wire format** (envelope shape, row_hash algorithm,
  signature scheme) is defined in the spec docs at
  `docs/spec/` *(consolidating; see `docs/spec/index.md`)*.

When the spec and the libraries disagree, the spec wins — libraries
are conformant implementations, not the source of truth.
