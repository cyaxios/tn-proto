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
| `tn.use(name?, profile?, ...)` | `await Tn.use(name, opts?)` | ✓ | Get-or-create a multi-ceremony handle by registry name. TS interns by `(projectDir, name)`; Python interns by name. NEW in 0.3.0a4. `Tn.openCeremony` is a deprecated alias on the TS side. |
| `tn.list_ceremonies()` | `Tn.listCeremonies(projectDir?)` | ✓ | Return ceremony names registered/found under `.tn/<name>/`. Sync on both. NEW in 0.3.0a4. |
| `tn.flush_and_close()` | `await tn.close()` | ✓ | TS async; Python sync. |
| `tn.log(event_type, **fields)` | `tn.log(eventType, fields?)` | ✓ | Sync on both. |
| `tn.debug(...)` | `tn.debug(...)` | ✓ | Sync. |
| `tn.info(...)` | `tn.info(...)` | ✓ | Sync. |
| `tn.warning(...)` | `tn.warning(...)` | ✓ | Sync. |
| `tn.error(...)` | `tn.error(...)` | ✓ | Sync. |
| `tn.read(*, where, verify, raw, log, as_recipient, group, all_runs)` | `tn.read({ where, verify, raw, log, asRecipient, group, allRuns })` | ✓ | **0.4.0a1 unified read.** Sync iterable in both. Returns typed `Entry` (Python pydantic v2, TS class) by default; `raw=True` yields the on-disk envelope dict. `verify` accepts `False` (default), `True`/`"raise"`, or `"skip"` (silently drops integrity-failing rows + emits `tn.read.tampered_row_skipped` admin event). |
| `async tn.watch(*, where, verify, raw, log, as_recipient, group, since, poll_interval)` | `tn.watch({ where, verify, raw, log, asRecipient, group, since, pollIntervalMs })` | ✓ | **0.4.0a1 unified watch.** Async iterable in both. Same return shape (`Entry` / envelope dict) and kwargs as `read`, plus `since=` (`"now"` / `"start"` / int / iso-string) and `poll_interval=`. Stat-poll based; rotation + truncation handled. |

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
| `tn.admin.rotate(group)` | `await tn.admin.rotate(group)` | ✓ (btn) / ⚠ (jwe) | Both languages bump `index_epoch`, regenerate the publisher's self-kit, rename old material `.revoked.<ts>`, and emit `tn.rotation.completed`. JWE rotation is Python-only today. |
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

## Read return type — `Entry`

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.Entry` (pydantic v2 model) | `Entry` (TS class) | ✓ | **NEW in 0.4.0a1.** What `tn.read()` and `tn.watch()` yield by default. Typed envelope attributes (`event_type`, `timestamp`, `level`, `message`, `did`, `event_id`, `sequence`, `run_id`, `prev_hash`, `row_hash`, `signature`, `hidden_groups`); user-emitted kwargs in `entry.fields`. Both sides hoist the positional `message` and `run_id` from the encrypted plaintext into typed slots so callers use `e.message` / `e.run_id` rather than `e.fields[...]`. Python: `__str__` / `__repr__` / `_repr_html_` / `_repr_markdown_` for Jupyter/Databricks. TS: `toString()` / `toJSON()`; `Entry.ts` is browser-safe (no `node:*` imports — uses `Symbol.for("nodejs.util.inspect.custom")`). |

## Deleted in 0.4.0a1 — folded into `tn.read` / `tn.watch` kwargs

These were separate verbs in 0.3.x. Their replacements are listed in the migration column.

| Old verb (gone) | Replacement |
|---|---|
| `tn.read_raw(...)` / `tn.readRaw(...)` | `tn.read(raw=True)` / `tn.read({ raw: true })` — yields the on-disk envelope dict. |
| `tn.read_all(...)` | `tn.read(all_runs=True)` / `tn.read({ allRuns: true })`. |
| `tn.read_as_recipient(log, ks, group)` / `tn.readAsRecipient(...)` | `tn.read(log=, as_recipient=, group=, raw=True)` / `tn.read({ log, asRecipient, group, raw: true })`. The `raw=True` keeps the legacy `{envelope, plaintext, valid}` triple shape; without `raw`, yields `Entry`. |
| `tn.read_as_recipient_flat(...)` | `tn.read(log=, as_recipient=, group=)` / `tn.read({ log, asRecipient, group })`. |
| `tn.secure_read(on_invalid=)` / `tn.secureRead(...)` | `tn.read(verify=...)` / `tn.read({ verify })`. `verify="skip"` matches the legacy `on_invalid="skip"`; `verify=True` / `"raise"` matches `on_invalid="raise"`. |
| `tn.Audit` class (Python) | Folded into `Entry` typed attributes. `e.signature`, `e.row_hash`, `e.prev_hash`, etc. are direct attrs now. |

No compat shims — the deletions are hard. The branch is the alpha-track.

## Errors

| Python | TS | Status | Notes |
|--------|------|--------|-------|
| `tn.VerifyError` | `VerifyError` | ✓ | Raised by `verify=True`/`"raise"` when an entry fails one or more of (signature, row_hash, chain). Carries `.sequence`, `.event_type`, `.failed_checks`. Also raised by parse-level decrypt failures wrapped under `verify="skip"` or `verify=True` so consumers get one error type for "this row didn't validate." |
| `tn.admin.cache.LeafReuseAttempt` (dataclass) | `LeafReuseError` (Error class) + `LeafReuseAttempt` (data) | ⚠ | Both languages keep the dataclass for accumulator paths; TS adds an Error class for throw paths. Python may add the parallel Exception in a future release. |
| `tn.admin.cache.SameCoordinateFork` (dataclass) | `SameCoordinateForkError` + `SameCoordinateFork` | ⚠ | Same pattern. |
| `tn.admin.cache.RotationConflict` (dataclass) | `RotationConflictError` + `RotationConflict` | ⚠ | Same pattern. |
| (n/a) | `ChainConflictError` (Error class) | ⊝ | Type-union of the three above on both sides; only TS has the wrapper Error class. |
| `tn.KeystoreConflictError` | (n/a) | ⊝ | NEW in 0.4.2a1. Re-export of the Rust-bound `tn_core._core.TnRuntimeError` so deploy scripts can write `except tn.KeystoreConflictError:` without dipping into the private module. TS gap; future work. |
| `tn.is_keystore_diverged(exc)` | (n/a) | ⊝ | NEW in 0.4.2a1. Predicate that returns True when the exception carries the keystore-divergence marker (the retry-friendly subset of `KeystoreConflictError`). TS gap; future work. |

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

## CLI verbs

| Python                      | TS                            | Status | Notes |
|-----------------------------|-------------------------------|--------|-------|
| `tn init <project>`         | (n/a — TS uses lib `Tn.init`) | ⊝      | Python ships the scaffold-from-scratch flow; non-TTY safe (mnemonic to identity.json). TS callers init programmatically. |
| `tn add_recipient <g> <did>`| `tn-js admin add-recipient`   | ✓      | Same shape, different verb naming convention per language. |
| `tn bundle <did> <out>`     | (via lib `pkg.bundleForRecipient`) | ⊝ | TS bundle CLI not yet ported; library API is parity. |
| `tn rotate [<group>]`       | `tn-js admin rotate [<group>]`| ✓ (btn) | Both emit per-recipient `.tnpkg` artifacts; vault autosync fires when ceremony is linked. |
| `tn absorb <pkg>`           | (via lib `pkg.absorb`)        | ⊝      | TS absorb CLI not yet ported; library API + `Tn.absorb` factory cover it. |
| `tn read [<log>]`           | `tn-js read --yaml <path>`    | ✓      | Both decode envelopes to flat JSON. |
| `tn watch ...`              | `tn-js watch ...`             | ✓      | Identical kwargs (`--since`, `--verify`, `--poll`, `--once`). |
| `tn wallet ...`             | (n/a)                         | ⊝      | Vault flows are Python-only today. |

## 0.4.3a1 identity-naming flip status

The 0.4.3a1 release renames identity-bearing fields to a canonical role
vocabulary (`device_identity`, `publisher_identity`, `recipient_identity`).
The flip lands phase by phase across the SDKs; this table tracks where
each side is.

| Surface | Python | TS | Notes |
|---------|--------|------|-------|
| Wire envelope (`did` → `device_identity`) | ✓ | ✓ | Phase A. |
| tnpkg manifest (`from_did`/`to_did` → `publisher_identity`/`recipient_identity`) | ✓ | ✓ | Phase G commit `db2631d`. |
| Ceremony yaml top-level (`me: {did: ...}` → `device: {device_identity: ...}`) | ✓ | ✓ | Phase B. TS landed in batch B0.1. Validator rejects legacy `me:` outright. |
| Ceremony yaml `groups.<g>.recipients[].did` → `.recipient_identity` | ✓ | ✓ | Folded into TS B0.1; Rust loader strictly requires the new key. |
| `Entry.fromFlat` / `read_shape.FLAT_ENVELOPE_KEYS` / `Entry.device_identity` (`did` → `device_identity`) | n/a | ✓ | TS landed in batch B0.2: `FLAT_ENVELOPE_KEYS`, `Entry` typed attribute, `Entry.toJSON()`, `Entry.fromFlat`/`fromRaw`, `Entry.[util.inspect.custom]`, stdout `_CRYPTO_KEYS`, otel `ATTR_FIELDS`, `tn-js` CLI read output, and three internal `env["did"]` readers all flipped end-to-end. B0.1's wire-side alias removed. Python keeps `Entry.did` for now — TS is ahead on this row. |

## CI parity gate

`tools/check_parity.py` walks the public symbols of `tn` (Python) and `@tnproto/sdk` (TS) and fails if a row is missing from this document. New verbs MUST add a row before the SDK can publish.

To re-run locally:

```bash
python tools/check_parity.py
```

Exit 0 = parity doc is current. Non-zero exit prints the missing symbols.
