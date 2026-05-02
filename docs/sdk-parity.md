# TN SDK cross-language parity

This file is the source of truth for verb parity between the Python and
TypeScript SDKs. New verbs land here when they ship; CI parses the table
below and fails on missing rows (see `tools/check_parity.py`).

## Format

Each row gives the Python form, the TS form, a status marker, and notes.

| Status | Meaning |
|---|---|
| ✓ | Behavior parity. Same semantics on both sides. |
| ⚠ | Minor divergence (typically wire form vs idiomatic shape). Documented inline. |
| ⊝ | Not yet ported on one side. Tracked. |

## Core verbs

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.init(yaml_path?, ...)` | `await Tn.init(yamlPath?, opts?)` | ✓ | TS is async to future-proof bootstrap; Python is sync. Same ceremony-discovery semantics on both. |
| `tn.flush_and_close()` | `await tn.close()` | ✓ | TS async; Python sync. |
| `tn.log(event_type, **fields)` | `tn.log(eventType, fields?)` | ✓ | Sync on both. |
| `tn.debug(...)` | `tn.debug(...)` | ✓ | Sync. |
| `tn.info(...)` | `tn.info(...)` | ✓ | Sync. |
| `tn.warning(...)` | `tn.warning(...)` | ✓ | Sync. |
| `tn.error(...)` | `tn.error(...)` | ✓ | Sync. |
| `tn.read(...)` | `tn.read(...)` | ✓ | Sync iterable in both. |
| `tn.read_all(...)` | `tn.read({allRuns: true})` | ✓ | TS folds into a flag. |
| `tn.read_raw(...)` | `tn.readRaw(...)` | ✓ | |
| `tn.read_as_recipient(...)` | `tn.readAsRecipient(...)` | ✓ | |
| `tn.secure_read(...)` | `tn.secureRead(...)` | ✓ | |
| `async tn.watch(since=, verify=, poll_interval=, log_path=)` | `tn.watch({ since, verify, pollIntervalMs, logPath })` | ✓ | Async iterable in both. NEW in 0.3.0a1. Stat-poll based; rotation + truncation handled. |

## Context verbs

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.set_context(**fields)` | `tn.setContext(fields)` | ✓ | |
| `tn.update_context(**fields)` | `tn.updateContext(fields)` | ✓ | |
| `tn.clear_context()` | `tn.clearContext()` | ✓ | |
| `tn.get_context()` | `tn.getContext()` | ✓ | |
| `tn.scope(fields, body)` | `tn.scope(fields, body)` | ✓ | |

## Process-global toggles

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.set_level(level)` | `Tn.setLevel(level)` / `setLevel(level)` | ✓ | Process-global on both. TS exports both static method and bare function. |
| `tn.get_level()` | `Tn.getLevel()` / `getLevel()` | ✓ | |
| `tn.is_enabled_for(level)` | `Tn.isEnabledFor(level)` / `isEnabledFor(level)` | ✓ | |
| `tn.set_signing(enabled)` | `Tn.setSigning(enabled)` / `setSigning(enabled)` | ✓ | |
| `tn.set_strict(enabled)` | `Tn.setStrict(enabled)` / `setStrict(enabled)` | ✓ | |

## Emit family (low-level escape hatches)

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.emit(level, event_type, fields)` | `tn.emit(level, eventType, fields)` | ✓ | |
| `tn.emit_with(level, event_type, ctx_fields, fields)` | `tn.emitWith(level, eventType, ctxFields, fields)` | ✓ | Per-call context-stack merge. |
| `tn.emit_override_sign(level, event_type, fields, sign)` | `tn.emitOverrideSign(level, eventType, fields, sign)` | ✓ | Per-call sign override (wins over `set_signing`). |
| `tn.emit_with_override_sign(...)` | `tn.emitWithOverrideSign(...)` | ✓ | Combo. |

## tn.admin

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.admin.add_recipient(group, ...)` | `await tn.admin.addRecipient(group, opts)` | ✓ | TS returns `AddRecipientResult`; Python returns `AddRecipientResult` dataclass. |
| `tn.admin.revoke_recipient(group, ...)` | `await tn.admin.revokeRecipient(group, opts)` | ✓ | Returns `RevokeRecipientResult`. |
| `tn.admin.rotate(group)` | `await tn.admin.rotate(group)` | ⚠ | TS throws on btn ("not supported in-band rotation"); Python may have different semantics for jwe groups. Verify per cipher. |
| `tn.admin.ensure_group(group, ...)` | `await tn.admin.ensureGroup(group, opts?)` | ⚠ | Python rewrites yaml on first call; TS only emits the attested event (no yaml-write). |
| `tn.admin.set_link_state(state)` | `await tn.vault.setLinkState(state)` | ⊝ | TS: stub-throws ("yaml-write not yet ported"). Python mutates `ceremony.mode` in yaml. |
| `tn.admin.recipients(group)` | `tn.admin.recipients(group, opts?)` | ✓ | Sync on both. Active-first sort. |
| `tn.admin.state(group?)` | `tn.admin.state(group?)` | ✓ | Sync. Both auto-derive `ceremony` from config when cache hasn't seen `tn.ceremony.init`. |
| `tn.admin.cache()` | `tn.admin.cache()` | ✓ | Sync. Returns `AdminStateCache` instance. |

## tn.pkg

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.pkg.export(opts, out_path)` | `await tn.pkg.export(opts, outPath)` | ✓ | Returns the path written (string). |
| `tn.pkg.absorb(source)` | `await tn.pkg.absorb(source)` | ✓ | Returns `AbsorbReceipt`. |
| `tn.pkg.bundle_for_recipient(opts)` | `await tn.pkg.bundleForRecipient(opts)` | ✓ | Returns `BundleResult` (TS adds `bundleSha256` + `groups[]`). |
| `tn.compile_enrolment(opts)` | `await tn.pkg.compileEnrolment(opts)` | ⚠ | TS namespaces under `tn.pkg.*`; Python keeps top-level. |
| `tn.offer(opts)` | `await tn.pkg.offer(opts)` | ✓ | Returns `OfferReceipt`. NEW in TS 0.3.0a1; ported from Python. |

## tn.vault

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.vault.link(vault_did, project_id)` | `await tn.vault.link(vaultDid, projectId)` | ✓ | Emits `tn.vault.linked`. |
| `tn.vault.unlink(vault_did, project_id, reason?)` | `await tn.vault.unlink(vaultDid, projectId, reason?)` | ✓ | Emits `tn.vault.unlinked`. |

## tn.agents

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.admin.add_agent_runtime(opts)` | `await tn.agents.addRuntime(opts)` | ⚠ | TS lifts to `tn.agents.*`; Python kept under `tn.admin.*`. Both mint a kit + emit `tn.agents.runtime_added`. |
| (cached `tn._agent_policy_doc`) | `tn.agents.policy()` | ✓ | TS exposes; Python is internal. |
| (`_reload_agents_policy()`) | `await tn.agents.reloadPolicy()` | ✓ | |

## tn.handlers

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.add_handler(h)` | `tn.handlers.add(h)` | ✓ | |
| (n/a) | `tn.handlers.list()` | ⊝ | New in TS 0.3.0a1; not yet on Python. |
| (n/a) | `await tn.handlers.flush()` | ⊝ | New in TS 0.3.0a1; not yet on Python. |

## Errors

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.VerifyError` / `tn.VerificationError` | `VerificationError` | ✓ | Real Exception / Error subclass on both. |
| `tn.admin.cache.LeafReuseAttempt` (dataclass) | `LeafReuseError` (Error class) + `LeafReuseAttempt` (data) | ⚠ | Both languages keep the dataclass for accumulator paths; TS adds an Error class for throw paths. Python may add the parallel Exception in a future release. |
| `tn.admin.cache.SameCoordinateFork` (dataclass) | `SameCoordinateForkError` + `SameCoordinateFork` | ⚠ | Same pattern. |
| `tn.admin.cache.RotationConflict` (dataclass) | `RotationConflictError` + `RotationConflict` | ⚠ | Same pattern. |
| (n/a) | `ChainConflictError` (Error class) | ⊝ | Type-union of the three above on both sides; only TS has the wrapper Error class. |

## Modules / namespaces

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.identity` | (parts of `@tnproto/sdk/core`) | ⚠ | TS exposes via Layer 1 module surface; not a 1:1 module mirror. |
| `tn.sealing` | (parts of `@tnproto/sdk/core`) | ⚠ | |
| `tn.wallet` | (not yet) | ⊝ | TS gap; future work. |
| `tn.vault_client` | (not yet) | ⊝ | TS gap; future work. |
| `tn.classifier` | (not yet) | ⊝ | TS gap; future work. |

## Browser-only surface (TS)

| TS | Notes |
|------|-------|
| `@tnproto/sdk/core` | Layer 1: pure functions over wasm-backed crypto. No `node:*`. ESLint-enforced. |
| `decryptGroup` / `decryptAllGroups` | Cipher-aware envelope decrypt. btn today; jwe-ready dispatch in place. |
| `AdminStateReducer` | Pure event-fold over admin envelopes. |
| `parseTnpkg` / `packTnpkg` | Browser-safe zip pack/parse via `fflate`. |
| `core/emk.ts` | Audited EMK helpers (importEmk, deriveEmkFromPassphrase, emkFromPrfOutput, makeVerifier, checkVerifier, wrapKeystoreSecret, unwrapKeystoreSecret). |
| `parsePolicyText` | Pure markdown parser for `.tn/config/agents.md`. |

Python doesn't have a Layer 1 / Layer 2 split because it's not a browser concern; everything in `python/tn/` runs on Python's standard library.

## CI parity gate

`tools/check_parity.py` walks the public symbols of `tn` (Python) and `@tnproto/sdk` (TS) and fails if a row is missing from this document. New verbs MUST add a row before the SDK can publish.

To re-run locally:

```bash
python tools/check_parity.py
```

Exit 0 = parity doc is current. Non-zero exit prints the missing symbols.
