# TS SDK refresh — design

**Status:** approved (brainstorming complete, ready for implementation plan)
**Date:** 2026-05-01
**Target version:** `@tnproto/sdk@0.3.0`, `tn-protocol@0.3.0`

## Summary

Refactor the TypeScript SDK to remove the 2200-line `TNClient` god-class, bring it to verb-for-verb parity with the post-refactor Python SDK (0.2.0a1+), introduce a three-layer split that makes a subset of the SDK browser-safe so the Chrome extension at `extensions/tn-decrypt/` can drop its inline crypto duplication, promote `watch` from a Python CLI to a library verb on both languages, and rewrite the README and the cross-language parity docs from scratch. Alpha license: no deprecation shims, no compat aliases — break the existing TS surface cleanly at `0.3.0`.

The wire shape, ndjson on-disk format, every event-type string, and the byte-identical Python ↔ TS interop suite at `crypto/tn-wasm/test/` all stay unchanged. Only the SDK boundary moves.

## Why now

The Python 0.2.0a1 alpha pulled `tn.admin`, `tn.pkg`, `tn.vault` out into focused subpackages, slimmed `tn/__init__.py` from 1844 to 845 LOC, and removed 18 flat aliases without deprecation. The TS SDK still carries the pre-refactor shape: every verb hangs off `TNClient`, admin verbs return bare `number` instead of structured result types, `tn.offer` and `tn.admin.rotate` are missing entirely, and the Chrome extension re-implements decrypt logic inline because the SDK is Node-only. The user's instruction is "make Python and TS the same; missing things are not intentional; clean it up the TypeScript way."

## Goals

1. **Verb parity with Python.** Every Python public verb has a TS counterpart with matching semantics. `tn.admin.add_recipient` → `tn.admin.addRecipient`, `tn.pkg.export` → `tn.pkg.export`, etc.
2. **No god-class.** The `Tn` class file stays under 600 lines. Each namespace file (`admin/index.ts`, `pkg/index.ts`, `vault/index.ts`, `agents/index.ts`, `handlers/index.ts`) stays under 600 lines.
3. **Browser-safe core.** Layer 1 of the SDK contains no `node:*` imports. The Chrome extension can consume Layer 1 directly. CI lint enforces the boundary.
4. **Tail-aware watch on both sides.** New `tn.watch()` library verb in Python and TS, async-iterable, tracks file offset, survives rotation. Existing CLIs (`python -m tn.watch`, `tn-js watch`) rewire to the library verb.
5. **Crisp DX.** Every public verb typed end-to-end (no `any` in Layer 1 or Layer 2 surfaces). New top-level README written for a TS dev who has never seen the protocol. Errors are real `Error` subclasses so consumers can `instanceof` them.

## Non-goals

- **Async core / tokio Rust runtime.** The wasm core stays sync. The async I/O verbs at the SDK boundary are wrappers around sync wasm calls; if a future async Rust core lands, the `Promise<T>` signatures absorb it without a second rename.
- **napi-rs Node-native binding.** README mentions it as a future; this spec stays on `tn-wasm`. Switching backends should not change the public `Tn` surface.
- **Streaming reads of historical logs beyond watch.** `read()` stays sync-iterable over a snapshot. Backpressure-aware streaming over historical logs is a separate spec if ever needed.
- **Chrome extension migration.** This spec creates the layering that *enables* the extension to consume `@tnproto/sdk/core`; doing the migration is its own task. A CI smoke test pins the contract.
- **Singleton sweep.** Spawned as a separate task. The three-layer split makes it sharper (Layer 1 has no place to put a singleton; the audit becomes "does Layer 2 hold per-instance state correctly").

## Architecture

### Three-layer split

```
@tnproto/sdk/raw     // Layer 0 — pure tn-wasm exports.
                     //   Already exists today. Unchanged.
                     //   No imports outside tn-wasm.

@tnproto/sdk/core    // Layer 1 — verbs that don't touch fs / network.
                     //   - encode/decode envelopes from bytes
                     //   - decrypt against a kit held in memory
                     //   - derive admin state from a list of events
                     //   - secure-read over a Uint8Array of ndjson
                     //   - canonicalize / sign / verify (wraps wasm)
                     //   - the read-shape projection (flatten_raw_entry)
                     //   Browser-safe by lint rule: no node:* imports.

@tnproto/sdk         // Layer 2 — Node entry. Wraps Layer 1 with:
                     //   - yaml ceremony load
                     //   - log file read/append, keystore-on-disk
                     //   - handlers (stdout, file, fs_drop, fs_scan, otel,
                     //     vault_pull, vault_push)
                     //   - factory: Tn.init('./tn.yaml'), Tn.ephemeral()
                     //   - tn.watch (file-watcher under the hood)
                     //   - tn.admin / tn.pkg / tn.vault wired to disk artifacts
```

The Chrome extension imports from `@tnproto/sdk/core`. The Node app imports from `@tnproto/sdk`. The interop test suite imports from `@tnproto/sdk/raw` for byte-level fixtures.

**Lint enforcement.** `eslint-plugin-import` is configured with `no-restricted-imports` on `src/core/` to forbid every `node:*` import and the legacy bare specifiers `fs`, `path`, `os`, `child_process`, `crypto` (Layer 1 must use the wasm-provided RNG, not Node's `crypto` module). CI fails the build on a violation. This rule is the file-write audit — Layer 1 has no way to write to a file because it can't import one.

### Top-level shape

```ts
import { Tn } from "@tnproto/sdk";

const tn = await Tn.init("./tn.yaml");          // factory; mints ceremony if absent
// or
const tn = await Tn.init();                     // no-arg discovery (TN_YAML, ./tn.yaml, $TN_HOME)
// or
const tn = await Tn.ephemeral({ stdout: false }); // throwaway temp ceremony for tests/scripts

tn.info("order.created", { order_id: "A100", amount: 4999 });

for (const entry of tn.read()) {
  console.log(entry.event_type, entry.order_id);
}

for await (const entry of tn.watch()) {
  // tail forever, decoded
  process.stdout.write(JSON.stringify(entry) + "\n");
}

await tn.close();
```

The class is `Tn`. Consumers conventionally name the variable `tn`. `TNClient` retires.

### Process-global toggles

Three pieces of state are intentionally process-scoped (matches Python's module-level semantics):

- log-level threshold (default `"debug"`)
- signing override (allows turning Ed25519 off for hot-loop tracing)
- strict mode (blocks `Tn.init()` no-arg discovery)

Exposed as static methods on `Tn`:

```ts
Tn.setLevel("info");
Tn.setSigning(false);   // null restores yaml default
Tn.setStrict(true);
```

Also re-exported as bare functions for module-level callers:

```ts
import { setLevel, setSigning, setStrict } from "@tnproto/sdk";
```

These are documented as process-global. The singleton sweep treats them as intentional.

### Subpackage carve-out

```ts
tn.admin.addRecipient(group, opts)        → Promise<AddRecipientResult>
tn.admin.revokeRecipient(group, opts)     → Promise<RevokeRecipientResult>
tn.admin.rotate(group)                    → Promise<RotateGroupResult>
tn.admin.ensureGroup(group, opts)         → Promise<EnsureGroupResult>
tn.admin.recipients(group, opts)          → RecipientEntry[]            // sync, reads cache
tn.admin.state(group?)                    → AdminState                   // sync, reads cache
tn.admin.cache()                          → AdminStateCache              // sync, returns handle
tn.admin.revokedCount(group)              → number                       // sync

tn.pkg.export(opts, outPath)              → Promise<string>              // writes file
tn.pkg.absorb(source)                     → Promise<AbsorbReceipt>       // reads file/bytes
tn.pkg.bundleForRecipient(opts)           → Promise<BundleResult>        // writes file
tn.pkg.compileEnrolment(opts)             → Promise<CompiledPackage>     // writes file
tn.pkg.offer(opts)                        → Promise<OfferReceipt>        // bilateral lifecycle

tn.vault.link(vaultDid, projectId)        → Promise<EmitReceipt>         // future: HTTP
tn.vault.unlink(vaultDid, projectId, reason?) → Promise<EmitReceipt>
tn.vault.setLinkState(state)              → Promise<EmitReceipt>

tn.agents.addRuntime(opts)                → Promise<string>              // writes kit
tn.agents.policy()                        → PolicyDocument | null        // sync
tn.agents.reloadPolicy()                  → Promise<PolicyDocument | null>

tn.handlers.add(handler)                  → void
tn.handlers.list()                        → TNHandler[]
tn.handlers.flush()                       → Promise<void>
```

Every result type is a structured object — never a bare `number` or `void`. Field names in result types are camelCase (these are SDK-owned types, not wire keys).

### Verbs that stay on the root

```ts
tn.log / tn.debug / tn.info / tn.warning / tn.error    // sync
tn.read(opts?)                                         // sync, returns Iterable<Entry>
tn.readAsRecipient(opts)                               // sync
tn.readRaw(opts?)                                      // sync, raw envelope shape
tn.secureRead(opts?)                                   // sync, signature-checked
tn.watch(opts?)                                        // async, AsyncIterable<Entry>  ← NEW
tn.scope(fields, body)                                 // sync, contextual logging
tn.setContext / updateContext / clearContext / getContext   // sync, per-instance
tn.emit(level, type, fields)                           // low-level
tn.emitWith(...) / tn.emitOverrideSign(...)            // low-level escape hatches
tn.config()                                            // sync, returns LoadedConfig
tn.usingRust()                                         // sync, dispatch diagnostic
tn.close()                                             // async; flushes handlers
```

`emit*` stays on the root (not under `tn.raw.*`) because they are documented escape hatches; pushing them under `tn.raw` would tempt people to use them. The `emit*` prefix makes them findable via autocomplete but obviously low-level.

### Sync / async split rule

- **Sync:** anything on the emit hot path, anything that only reads in-memory state, anything that returns an `Iterable` over a snapshot.
- **Async:** anything that touches disk (writes a kit file, exports a tnpkg, absorbs a package), anything that could grow an HTTP call (vault link/unlink, future remote handlers), anything that returns an `AsyncIterable` over a live stream (watch).

Mechanical rule. The dev does not need to memorize a list — the signature tells them.

### Read shape (snake-case stays)

```ts
{
  event_type: "order.created",
  order_id: "A100",
  recipient_did: "did:key:z6...",
  timestamp: "2026-05-01T10:23:45.123Z",
  level: "info",
  ...
}
```

The envelope keys are spec-defined. The user-payload keys are whatever the caller wrote. Neither is the SDK's to rewrite. The `Entry` type definition carries a single `// eslint-disable @typescript-eslint/naming-convention` and the rest of the codebase enforces camelCase normally.

### Watch verb (NEW, both languages)

**TS:**
```ts
for await (const entry of tn.watch({ since: "now", verify: false })) {
  console.log(entry.event_type, entry.order_id);
}
```

`WatchOptions`:
- `since`: `"start"` (replay from byte 0) | `"now"` (default; only new entries) | a sequence number | a timestamp.
- `verify`: pass entries through `secureRead`'s validation.
- `pollIntervalMs`: fallback for filesystems without native watch (default 300).

Implementation: track byte offset on the underlying ndjson file, watch with `node:fs.watch` (or `chokidar` for cross-platform stability — pick during planning), reuse the line-parser path that `read()` already uses. On rotation (file inode change), reopen and resume from offset 0. On unexpected truncation (file shorter than the tracked offset, no inode change), the watch verb appends a tamper-class admin event and resumes from end — the exact event type is a planning-phase decision since it must be cross-language and may need a new admin-catalog entry (it is *not* the existing `tn.read.tampered_row_skipped`, which is for `secureRead` row-level failures).

**Python:**
```python
async for entry in tn.watch(since="now", verify=False):
    print(entry["event_type"], entry.get("order_id"))
```

Implementation: same offset-tracking approach over `watchdog` (or stat-poll fallback), shares the ndjson parser with `tn.read()`. The existing `python -m tn.watch` CLI is rewritten as a thin shell over `tn.watch()` — same flags, same JSONL output, no behavior change for existing users.

### Errors as real classes

Today: `VerificationError` is a class; `ChainConflict` / `RotationConflict` / `SameCoordinateFork` / `LeafReuseAttempt` are bare types. Promote them:

```ts
export class VerificationError extends Error { /* envelope, invalidReasons */ }
export class ChainConflictError extends Error { /* localHead, remoteHead, …*/ }
export class RotationConflictError extends Error { /* group, generation, …*/ }
export class LeafReuseError extends Error { /* group, leafIndex, …*/ }
export class SameCoordinateForkError extends Error { /* group, coordinate, …*/ }
```

Consumers can `try/catch` and route by `instanceof`. Mirror in Python (already exception classes there).

### Module entry exports

```
@tnproto/sdk/raw        → every tn-wasm primitive verbatim
@tnproto/sdk/core       → Layer 1 verbs (no node:* imports)
@tnproto/sdk/handlers   → BaseHandler, TNHandler interface, OutboxHandler
@tnproto/sdk            → Tn class + types + errors + handler-namespace exports
                          (Layer 2; the everyday entry)
```

Keeping handler base classes on a subpath stops the main entry from getting cluttered with implementation classes that 95% of consumers will never touch.

## Migration

This is alpha. We break it cleanly.

- No deprecation shims, no `@deprecated` JSDoc tags, no compat aliases.
- The current `@tn/sdk` is `0.0.1` on disk and was never published to npm. We publish `@tnproto/sdk@0.3.0` of the new package.
- CHANGELOG.md under `[0.3.0]` lists the rename table:
  - `TNClient` → `Tn`
  - `client.adminAddRecipient(...)` → `tn.admin.addRecipient(...)` (returns `AddRecipientResult` not `number`)
  - `client.export/absorb` → `tn.pkg.export/absorb` (now `Promise<T>`)
  - `client.vaultLink/vaultUnlink` → `tn.vault.link/unlink` (now `Promise<T>`)
  - `client.adminAddAgentRuntime` → `tn.agents.addRuntime` (now `Promise<string>`)
  - `client.read` stays sync; `client.watch` is new and async.
  - `TNClient.setLevel` → `Tn.setLevel` plus a function-export `import { setLevel } from "@tnproto/sdk"`.

Python at the same release moment adds `tn.watch()` as a library verb (`0.3.0`). No other Python surface changes.

## Success criteria

1. **Shape parity.** Every Python public verb has a TS counterpart with matching semantics. A `docs/sdk-parity.md` cross-language parity table lists every verb on both sides; CI fails on missing rows.
2. **Interop.** Existing `crypto/tn-wasm/test/` byte-identical tests still pass. New tests round-trip a `tn.watch()` stream Python ↔ TS to verify both library verbs see the same entries in the same order.
3. **Type safety.** No `any` in the public surface of Layer 1 or Layer 2. `@typescript-eslint/no-explicit-any` set to `error` for `src/core/` and `src/`. Allowed in `src/raw/` only (mirrors the wasm `.d.ts`).
4. **Docs.** New top-level `README.md` for the TS SDK is rewritten from scratch — quickstart + walkthrough of `tn.admin/pkg/vault/agents` + `tn.watch` example. Old README's "Open questions" section deleted.
5. **No god-class.** `src/tn.ts` stays under 600 lines. Each namespace file under 600 lines. CI lints the line count.
6. **Layer 1 is browser-safe.** CI lint forbids `node:*` imports in `src/core/`. A Chrome-extension consumer-contract smoke test imports Layer 1 in a browser-like context and exercises decrypt + admin-state derivation; it fails the build if Layer 1 grows a Node dependency.
7. **Watch is tail-aware.** New `tn.watch` (both languages) tracks file offset, doesn't re-read prior bytes, survives log rotation, emits within `pollIntervalMs` of an append (default 300ms).

## Open questions

None blocking. Implementation-plan-level questions (whether to use `chokidar` vs `node:fs.watch`, whether to vendor `watchdog` vs stat-poll on Python, the exact line-count CI mechanism) belong in the writing-plans pass.

## Out-of-scope follow-ups (already spawned or queued)

- **Singleton sweep** — spawned task; audits whether the new instance shape achieves per-instance state. The three-layer split sharpens this: Layer 1 has nowhere to put a singleton; the audit becomes "does Layer 2 hold per-instance state correctly."
- **Chrome extension migration to `@tnproto/sdk/core`** — the layering enables it. Migration is a separate task once 0.3.0 ships.
- **Browser bundle as a separate package** — superseded. Layer 1 (`@tnproto/sdk/core`) is the browser entry; there is no `@tnproto/browser` sibling.
- **napi-rs binding** — future, no public-surface change required.
- **Async Rust core** — future, the `Promise<T>` signatures already absorb it.
