# Python ↔ TypeScript drift audit (v3)

Against `origin/main` at `1edd426` (tn-protocol `0.4.0a6.post2`,
`@tnproto/sdk` working tree).

**v1 audit was thin (eleven UX items).
v2 added architectural axes, public-surface table, handler/cipher inventory.
v3 adds wire-format compatibility (the most important gap v1/v2 missed),
init+lifecycle deep dive, config-loader deep dive, and a bundle/absorb
deep dive — re-reading every file the user called out: log/init/read/
watch/tnpkg.**

Three parallel agents read 18.8k LOC across both sides (Python ~10.3k,
TS ~12.7k including `node_runtime.ts`); I spot-verified the highest-
severity claims against actual code (canonical bytes, timestamp format,
`KNOWN_KINDS`, `compile.ts` vs `compile.py` bundle format). Agent
findings that didn't survive verification are recorded in §14.

---

## §1. TL;DR

| count | category | from |
|---|---|---|
| **4** | wire-format breaks (silently break interop) | §3 |
| **17** | public Python verbs without a TS equivalent | §4 |
| **8** | handler implementations missing in TS | §9 |
| **2** | whole subsystems missing in TS (CLI + MCP/lint) | §11 |
| **1** | cipher missing in TS (JWE on the foreign-read path) | §10 |
| **22** | init / lifecycle / config drift items | §5–§6 |
| **15** | read / watch / chain drift items | §7 |
| **18** | bundle / absorb / compile drift items | §8 |

**Critical-path items (block witness, vault TS rewrite, plug-in)**:
W1 / W2 / W3 / W4 (wire format), B (key-bag read), H (keystore safety),
L4 (vault HTTP client), L5 (wallet flows), H8 (durable outbox).

**Action**: open §3 first. If those four wire-format breaks aren't
fixed before any TS-produced artifact reaches a Python consumer
(witness ingesting publisher logs, vault storing kit bundles for
recovery), interop fails silently.

---

## §2. Architectural axes

Structural, not bugs. Names "different shape, same behavior."

| axis | Python | TypeScript |
|---|---|---|
| **State binding** | Module singleton (`tn._dispatch_rt`) + named-ceremony registry. `tn.info(...)` works without holding any object. | `class Tn`; the caller holds the instance. Module-level `setLevel` / `setSigning` toggles re-bind via class statics. |
| **Discovery + init** | `tn.init()` no-args walks the discovery chain and rebinds the singleton. `tn.init(name=...)` rebinds onto the named ceremony (post-PR #55). `tn.use(name)` is the lazy attach. | `Tn.init`, `Tn.absorb`, `Tn.ephemeral`, `Tn.use`, `Tn.openCeremony` are async static factories. No global singleton to rebind. |
| **Rust dispatch** | `tn._dispatch` chooses between Rust `tn_core` and pure-Python at init time, gated on cipher + extension availability + `TN_FORCE_PYTHON` env. ~495 lines. | `ts-sdk` always uses `tn-wasm`. No fallback path, no dispatch module. |
| **Async surface** | Sync emit + sync iterator read + asyncio `watch`. `flush_and_close` is sync. `tn.session()` is a sync context manager. | Sync emit, sync iterator read, async iterator watch. `Tn.close` is async (handler outboxes finalize asynchronously). `Tn.init / absorb / ephemeral` are async (await maturin-loaded wasm). |
| **Run ID semantics** | Module-global `_run_id` minted once-per-process at first init; **stamped to `$TN_RUN_ID`** so the Rust runtime sees the same id; default read filters to this run. | Per-`Tn` instance `_runId` (no env stamp). **Different processes that re-enter `Tn.init()` mint distinct runIds — multi-instance read filtering differs from Python.** |
| **Auto-cleanup** | `atexit` hook drains handlers on interpreter exit (PR #42). | None; user must call `await tn.close()`. |
| **Identity / keystore layout** | `<group>.btn.mykit`, `<group>.btn.state`, `local.private`, `local.public`, `index_master.key`, optional `<group>.btn.state.lock` (PR #51). | Same file names. No `.state.lock`. |
| **Profile system** | `tn._profiles`: transaction, audit, secure_log, telemetry, **stdout** (5 profiles). | `profiles.ts`: transaction, audit, secure_log, telemetry (4 — missing stdout). |
| **Error taxonomy** | `TNNotFound`, `TNCreateFailed`, `TNInvalidName`, `TNConfigConflict`, `MultiCeremonyEmitNotImplemented`, `VerifyError`, `VerificationError`, `LeafReuseAttempt`, `RotationConflict`, `SameCoordinateFork`, `ChainConflict`, `KeystoreConflict`. | `VerificationError`, `ChainConflictError`, `RotationConflictError`, `LeafReuseError`, `SameCoordinateForkError`. Missing TN-prefix family + KeystoreConflict. |
| **Bundle pipeline** | `tn.export(kind=...)` is the single producer; every `.tnpkg` carries the universal **signed** `TnpkgManifest`. `compile_kit_bundle` is a thin wrapper around `export(kind="kit_bundle"/"full_keystore")`. | **Two parallel pipelines**: `pkg/tnpkg.ts` (universal signed `Manifest`) AND `compile.ts` (bespoke unsigned `CompiledManifest`). The two produce incompatible `.tnpkg` files. |

---

## §3. Wire-format compatibility — the part v1/v2 missed

**Anything in this section silently breaks Python ↔ TS interop.**
Spot-verified against the actual code.

### W1 (CRITICAL): `compile.ts` produces a different (unsigned) bundle format than `compile.py`

- **Python**, `python/tn/compile.py:138–215` — `compile_kit_bundle` is now a thin wrapper around `tn.export(kind="kit_bundle")` / `tn.export(kind="full_keystore")`. Every produced archive carries the universal signed `TnpkgManifest` (`from_did`, `ceremony_id`, `as_of`, `scope`, `clock`, `event_count`, `head_row_hash`, `manifest_signature_b64`). The kits live at `body/<group>.btn.mykit`.
- **TS**, `ts-sdk/src/compile.ts:198–273` — `compileKitBundle` writes its own `CompiledManifest`:
  ```ts
  interface CompiledManifest {
    version: "tnpkg-v1";
    label: string | null;
    note: string | null;
    did: string | null;
    ceremony_id: string | null;
    kind: "readers-only" | "full-keystore";  // NOT a TnpkgManifest kind
    created_at: string;
    kits: Array<{ name: string; sha256: string; bytes: number }>;
  }
  ```
  **No signature field exists.** No `as_of`, no `from_did`, no `scope`. The string literal `"readers-only"` / `"full-keystore"` is not one of Python's `KNOWN_KINDS`. The manifest is written via `JSON.stringify(manifest, null, 2)` (pretty-printed) instead of canonical bytes.

**Impact**: A `.tnpkg` produced by TS `compileKitBundle` cannot be absorbed by Python: Python validates `KNOWN_KINDS` and verifies `manifest_signature_b64`. Both fail.

**Conversely**, a `.tnpkg` produced by Python `compile_kit_bundle` is not the shape TS's `compileKitBundle` consumers expect (TS has no symmetric reader of the universal manifest in the compile flow — it goes through `pkg/tnpkg.ts` instead).

**Fix path**: kill `compile.ts`'s bespoke manifest. Route through `pkg/tnpkg.ts` and sign with the device key, exactly the way `compile.py` routes through `export.py`. Estimated ~300 lines + tests.

### W2 (HIGH): TS `KNOWN_KINDS` missing `identity_seed`

- **Python**, `python/tn/tnpkg.py:64–85` — frozenset includes `"identity_seed"`.
- **TS**, `ts-sdk/src/core/tnpkg.ts:41–49` — Set does NOT include `"identity_seed"`.

**Impact**: today, mitigated because `absorb_bootstrap.ts:110` switches on the literal string `"identity_seed"` directly, not on membership in `KNOWN_KINDS`. But anyone who adds a "validate kind against `KNOWN_KINDS` before dispatch" check (a reasonable hardening) will silently break the bootstrap path.

**Fix path**: add `"identity_seed"` to the Set + `ManifestKind` union (~5 lines).

### W3 (HIGH): `project_seed` exists on TS, absent on Python

- **TS**, `ts-sdk/src/runtime/absorb_bootstrap.ts:149` — `project_seed` is a first-class bootstrap kind; handler at line 320–365.
- **Python** — no handler for `project_seed` anywhere in `absorb.py`. `tnpkg.py` `KNOWN_KINDS` doesn't include it.

**Impact**: dashboard / vault produces `project_seed` bundles (TS-only); Python cannot absorb them. This is a TS-leading drift; the spec lives only in the TS code.

**Fix path**: port the absorb handler to Python (~250 lines, mirrors `absorb_bootstrap.ts`'s `project_seed` body). Add the kind to Python `KNOWN_KINDS`.

### W4 (MEDIUM): `watch(pollInterval*)` unit mismatch

- **Python**, `python/tn/watch.py:38` — `poll_interval: float = 0.3` (seconds).
- **TS**, `ts-sdk/src/tn.ts:245` — `pollIntervalMs?: number` (milliseconds).

**Impact**: a developer porting `tn.watch(log, poll_interval=0.3)` from Python to TS by naming-convention swap (`pollInterval`) and not noticing the unit suffix will poll every 0.3ms or 1ms depending on a minimum-clamp — either way wildly different from the intent.

**Fix path**: pick one. Recommendation: rename TS field to `pollIntervalMs` everywhere it's exposed and document the unit explicitly in docstring + README; OR add `pollInterval` (seconds) as the documented field and make `pollIntervalMs` a deprecated alias.

### Spot-verified MATCH items (agents flagged but I confirmed they're aligned)

These are recorded so we don't re-flag them later:

- **Timestamp format**: Python `_now_iso()` (`export.py:56`) returns `datetime.now(timezone.utc).isoformat(timespec="milliseconds")` → `2026-05-13T14:30:45.123+00:00`. TS `nowIsoMillis()` (`core/tnpkg.ts:259`) does `new Date().toISOString().replace(/Z$/, "+00:00")` → same format. **Bytes match.**
- **Canonical JSON separators**: Python (`canonical.py:65`) uses `separators=(",", ":")`, `sort_keys=True`. TS (`core/canonical.ts:24`) routes through `tn-wasm`'s `canonicalBytes`, which is Rust-backed and documented to produce identical output. **Trust the wasm**; if it ever drifts, every signed manifest stops verifying — there's a cross-language byte-compare test that should be the canary.
- **Recipient seal HKDF salt**: both sides compute `salt = eph_pub || recipient_x_pub`. **Match.**
- **Ed25519 → X25519 derivation**: Python uses libsodium `crypto_sign_ed25519_pk_to_curve25519`; TS uses `@noble/curves` `edwardsToMontgomeryPub`. The math is the same birational map; both produce identical bytes for identical inputs. **Match** (but worth a one-off byte-compare CI test if not already present).

---

## §4. Public surface — verb by verb

Python's `__all__` has 47 callable names + 9 type/class exports.
TS splits between bare exports, the `Tn` class, and four sub-namespaces
(`tn.admin`, `tn.pkg`, `tn.vault`, `tn.agents`).

| Python | TS location | sig delta | drift |
|---|---|---|---|
| **Lifecycle** | | | |
| `tn.init(yaml_path?, name?, stream?, link?, device_seed?, identity?, project?, ...)` | `Tn.init(yamlPath?, opts?)` | TS bundles into opts; missing `name=` / `stream=` short-circuit, `link=`, `identity=`, `project=` kwargs | **L1** |
| `tn.use(name, project_dir?)` | `Tn.use(name, opts?)` | parity | ✓ |
| `tn.session()` | `Tn.ephemeral(opts?)` | parity (v1 wrongly said TS missing) | ✓ |
| `tn.flush_and_close(timeout=?)` | `tn.close()` | TS async, no timeout param, no atexit | **I** |
| `tn.list_ceremonies()` | `Tn.listCeremonies(projectDir?)` | parity | ✓ |
| `tn.current_config()` | `tn.config()` (instance) | semantic equivalent | ✓ |
| `tn.using_rust()` | `tn.usingRust()` | TS always returns true (wasm); knob unreachable | structural |
| `tn.set_strict / set_level / get_level / is_enabled_for / set_signing` | `Tn.set*` (static) + bare exports | parity, naming case | ✓ |
| **Emit** | | | |
| `tn.info / warning / error / debug / log(event_type, **fields)` | `tn.info / warning / error / debug / log(event_type, fields)` | TS takes a single object instead of kwargs | ✓ idiomatic |
| — | `tn.emit / emitWith / emitOverrideSign / emitWithOverrideSign` | TS exposes sign-override family explicitly; Python folds into `log`'s kwargs | **L2** (TS-extra) |
| **Read** | | | |
| `tn.read(log=, as_recipient=, group=, where=, verify=, raw=, all_runs=)` | `tn.read(opts: ReadOptions)` | TS hasn't ported: key-bag (B), `"admin"` alias (F), template glob (G), cwd-first relative paths (D), `read_all()` cross-file merge (R1). TS auto-detects foreign-log via DID (`_isForeignLog`) — neat. | **B, D, F, G, R1** |
| `tn.watch(...)` | `watch(opts)` bare export, also `tn.watch` instance | Same gaps + **unit mismatch on poll interval (W4)** | **B, D, F, G, W4** |
| `tn.read_all()` | not present | merges main + admin + every PEL ndjson by timestamp | **R1** |
| **Bundles** | | | |
| `tn.absorb(file)` | `Tn.absorb(file)` (static factory) | TS doesn't require prior init; Python does (issue #60) | **K** (reverse) |
| `tn.export(out, kind, ...)` | `tn.pkg.export(opts, outPath)` | parity in shape; TS lacks `kind="identity_seed"` export path | **L9** |
| `tn.compile_enrolment(args)` | `tn.pkg.compileEnrolment(opts)` | parity | ✓ |
| `tn.offer(...)` | `tn.pkg.offer(opts)` | Different return types: Python `Package`, TS `OfferReceipt`. Python writes outbox file; TS emits attested event. | **L10** |
| `tn.compile_kit_bundle(...)` | `compileKitBundle(opts)` (top-level, not in pkg) | **WIRE FORMAT BREAK — see W1** | **W1** |
| **Admin** | | | |
| `tn.admin.add_recipient(group, recipient_did, out_path?, public_key?)` | `tn.admin.addRecipient(group, opts)` | parity | ✓ |
| `tn.admin.revoke_recipient(group, leaf_index?, recipient_did?)` | `tn.admin.revokeRecipient(group, opts)` | parity | ✓ |
| `tn.admin.rotate(group)` | `tn.admin.rotate(group)` | parity | ✓ |
| `tn.admin.recipients(group, include_revoked=False)` | `tn.admin.recipients(group, opts?)` | parity | ✓ |
| `tn.admin.state(group?)` | `tn.admin.state(group?)` | parity | ✓ |
| `tn.ensure_group(group, ...)` | `tn.admin.ensureGroup(group, opts?)` | parity | ✓ |
| `tn.admin.add_agent_runtime(bundle)` | not in `AdminNamespace` | TS missing | **L3** |
| `tn.admin.revoked_count(group)` (via cache) | `tn.admin.revokedCount(group)` | parity | ✓ |
| `tn.admin.cache` | `tn.admin.cache()` | parity (different scope — Python module, TS instance) | structural |
| **Vault** | | | |
| `tn.vault.link / unlink` | `tn.vault.link / unlink` | parity | ✓ |
| `tn.set_link_state(state)` | `tn.vault.setLinkState(state)` | structural | ✓ |
| `tn.vault_client` (HTTP client export) | not exposed | **TS missing** | **L4** |
| `tn.wallet.*` (link, restore, status, sync, pull_prefs, export_mnemonic) | not present | **TS has NO wallet verbs** | **L5** |
| **Context** | | | |
| `tn.set_context / update_context / clear_context / get_context` | `tn.setContext / updateContext / clearContext / getContext` | parity | ✓ |
| `tn.scope(**fields)` (context manager) | not present | TS missing | **L6** |
| `tn.bootstrap_from_api_key()` | not present | TS missing | **L11** |
| **Agents policy** | | | |
| `tn.agents.PolicyDocument / PolicyTemplate` | `tn.agents.*` | needs surface check | **L7 (TBD)** |
| `tn.classifier` (LLM stub) | not present | low-priority | **L8** |

### Total Python verbs with no TS equivalent (revised)

Counting from §4 (after correcting v2's over-count):

1. `tn.read_all()` — **R1**
2. `tn.admin.add_agent_runtime` — **L3**
3. `tn.vault_client` HTTP client export — **L4**
4. `tn.wallet.link` — **L5**
5. `tn.wallet.unlink` — **L5**
6. `tn.wallet.status` — **L5**
7. `tn.wallet.sync` — **L5**
8. `tn.wallet.pull_prefs` — **L5**
9. `tn.wallet.export_mnemonic` — **L5**
10. `tn.wallet.restore` (multi-mode) — **L5**
11. `tn.scope(**fields)` — **L6**
12. `tn.bootstrap_from_api_key` — **L11**
13. `tn.classifier._configure / _register` — **L8**
14. `tn.export(kind="identity_seed")` — **L9**
15. `tn.offer` return-shape parity — **L10**
16. `tn.set_strict` autoinit gate on absorb path — **D-013** (small)
17. `link=`, `identity=`, `project=` kwargs on `tn.init` — **L1**

17 verbs, plus 8 subsystem/handler gaps below (§9–§11).

---

## §5. Init / lifecycle / log deep dive

What I actually found by reading `_autoinit.py` (328 lines), `_multi.py`
(1202 lines), `bootstrap.py` (360 lines), `_dispatch.py` (495 lines),
`__init__.py` (1214 lines) and walking each init path:

| id | item | severity | Python | TS | why it matters |
|---|---|---|---|---|---|
| **I1** | Module-global `_run_id` stamped to `$TN_RUN_ID` | high | `__init__.py:149,240` | per-instance, no env | Rust path sees same run_id; TS multi-instance read filter diverges |
| **I2** | `_run_id` intentionally preserved across `flush_and_close` | low | `__init__.py:1064` | per-instance, fresh on init | so re-init in same process stamps same run_id |
| **I3** | `atexit` hook auto-drains handlers | high | `__init__.py:987–1014` | absent | TS users must `await close()` explicitly or lose buffered events |
| **I4** | `tn.set_strict(True)` blocks autoinit no-args discovery | medium | `_autoinit.py:55` | `tn.ts:78` strict-mode covers `Tn.init()` only, NOT `Tn.absorb()` | TS strict-mode less load-bearing |
| **I5** | `TN_SURFACE_LOG=` diagnostic — every public verb logs ENTER / EXIT | low | `__init__.py:102–134` | absent | TS lacks the debugging surface; Python operators use it to trace SDK calls |
| **I6** | `_resolve_existing_yaml` load-only — never creates | high | `_autoinit.py:174` | `tn.ts:680` auto-creates for non-default streams | TS auto-mints with a 16-line banner where Python politely refuses |
| **I7** | `_session_impl` context manager wraps lifecycle + tmpdir + context | medium | `_session.py + __init__.py:1143` | `Tn.ephemeral()` exists but doesn't scope context | block-scoped tmpdir overlaps but TS resets less state |
| **I8** | `stream=` kwarg opens default ceremony then named stream in one call | medium | `_multi.py:621, _apply_stream` | absent | TS requires two `Tn.init` calls |
| **I9** | `link=True/False/None` auto-link to vault on init (IPython detection) | medium | `__init__.py:365, 377` | absent | demo-driver UX; TS has no vault HTTP integration |
| **I10** | `identity=Identity` kwarg seeds device key | medium | `__init__.py:269, _multi.py:559` | absent | TS users must pass `device_seed: Uint8Array` raw |
| **I11** | `project=` kwarg stores `tn._current_project` for vault tagging | low | `_multi.py:869, _store_project_tag` | absent | future vault integration |
| **I12** | `_resolve_init_aliases` validates mutual exclusion of `name`/`ceremony` and `yaml_path`/`load` aliases | low | `_multi.py:521–564` | tn.ts simple positional dispatch | Python catches caller errors loudly |
| **I13** | `_cached_admin_state` reset on `flush_and_close` | medium | `__init__.py:155, 1052` | `admin/cache.ts` per-runtime | Python module-level cache vs TS per-instance |
| **I14** | `_agent_policy_doc` splicing state reset on close | medium | `__init__.py:161` | `node_runtime.ts:139` instance-level | persistence scope differs |
| **I15** | Run ID env stamping forces Rust to see same `$TN_RUN_ID` | high | `__init__.py:244` | n/a — wasm | structural, but `using_rust()` distinction is unreachable in TS |
| **I16** | `_fan_out_python_handlers` after Rust emit skips redundant stdout / file | medium | `_dispatch.py:286, 353, 356` | n/a | Python combines Rust + Python handlers safely |
| **I17** | Stdout handler skip in Rust fan-out **except** in IPython | medium | `_dispatch.py:353` | n/a | matplotlib-style capture mismatch workaround |
| **I18** | Bootstrap from `TN_API_KEY` env (challenge / verify → sealed-bundle absorb) | medium | `bootstrap.py` 361 lines | partial in `absorb_bootstrap.ts` | TS supports the absorb half but not the challenge half |
| **I19** | `bootstrap.py` writes `sync_state.json` (bootstrapped_from + account_bound) | medium | `bootstrap.py:334, sync_state.py` | absent | TS doesn't track post-bootstrap provenance |
| **I20** | `_emit_missing_recipients` / `_emit_missing_group_added` idempotent ceremony init | medium | `__init__.py:602` | partial: `node_runtime.ts:205, reconcileRecipients` | TS scans recipients but not groups |
| **I21** | `.resolved.yaml` sibling generated when Rust path active + `extends:` present | medium | `_dispatch.py:228` | absent (resolves inline) | operator-inspection artefact differs |
| **I22** | `tn.is_default` / `tn.cfg` / `tn._get_runtime()` lazy attach on `TN` handle | low | `_handle.py:148, 152, 190` | `tn.ts` class-instance | structural — both work |

---

## §6. Config loader deep dive

`python/tn/config.py` is 1334 lines; `ts-sdk/src/runtime/config.ts` is
491 lines. The 2.7× ratio matches what's actually missing:

| id | item | severity | Python | TS | why it matters |
|---|---|---|---|---|---|
| **C1** | `extends:` resolution with explicit merge rules (parent-owned vs shallow-merge vs additive) | medium | `config.py:_resolve_extends` | `config.ts:130+` | both implement; behavior aligned |
| **C2** | `${VAR}` and `${VAR:-default}` env substitution | medium | `config.py:63, _ENV_VAR_RE` | `config.ts:84` | both implement; error messages differ slightly |
| **C3** | `protocol_events_location` (PEL) template validation against `_KNOWN_PEL_TOKENS` | medium | `config.py:163, _validate_pel_template` | absent | TS silently accepts garbage PEL templates |
| **C4** | `logs.path` template detection (forces Python emit when `{` in path because Rust can't per-envelope route) | medium | `_dispatch.py:55` | n/a (NodeRuntime supports per-envelope routing natively) | architectural; both correct on their side |
| **C5** | JWE group key files (`.jwe.sender`, `.jwe.recipients`, `.jwe.mykey`) recognized | high | `config.py:18–20` | `node_runtime.ts:174–179` throws if not btn | **TS cannot run JWE ceremonies at all** |
| **C6** | `public_fields` constant catalog | low | `config.py:172, DEFAULT_PUBLIC_FIELDS` | `config.ts` inline | identical set |
| **C7** | `fieldToGroups` sorted-alphabetically multi-group routing | medium | `config.py` | `config.ts:37` | aligned |
| **C8** | `ceremony.log_level` yaml field loaded as session default | low | `__init__.py:854` | `config.ts:56` | aligned |
| **C9** | Path absolutization during extends merge (at parent's directory) | medium | `config.py` | `config.ts` | aligned |
| **C10** | Handler specs `handlers:` block (Python builds, TS exposes raw) | medium | `config.py + handlers/` | `config.ts:67` | structural — both fine |
| **C11** | `admin_log_location` template validation | medium | `config.py:_validate_path_template` (PR #52) | absent | TS doesn't catch broken admin-log templates |
| **C12** | `keystore.path` / `keystore.dir` aliases + relative resolution | low | `config.py` | `config.ts` | aligned |
| **C13** | Profile selection (`ceremony.profile` yaml field) | medium | `config.py + _profiles.py` | `config.ts + profiles.ts` | aligned but TS missing `stdout` profile (P) |
| **C14** | Vault block (`vault.url`, `vault.token`, etc.) loaded into cfg | medium | `config.py` | absent | TS doesn't read vault block (matches absence of `tn.vault_client` — see L4) |
| **C15** | `link_state` loaded + validated | low | `config.py` | `config.ts` partial | aligned for the values that exist |

---

## §7. Read / watch / chain deep dive

Re-reading `read.py`, `_read_impl.py`, `reader.py`, `watch.py`,
`_watch_impl.py`, `_log_targets.py`, `chain.py`, `filters.py` against
`tn.ts:read/watch`, `read_as_recipient.ts`, `watch.ts`, `Entry.ts`,
`core/decrypt.ts`, `core/chain.ts`, `core/read_shape.ts`:

| id | item | severity | Python | TS | why it matters |
|---|---|---|---|---|---|
| **R1** | `tn.read_all()` merges main + admin + every PEL file by timestamp | medium | `reader.py:222–251` | absent | TS users must call `read()` separately on each path and merge themselves |
| **R2** | `tn.read(log=...)` key-bag (walks every absorbed kit + every group block) | **high** | `reader.py:read_with_keybag` (PR #61) | `readAsRecipient` single-group | TS can't decrypt multi-group foreign logs; vault / witness need this |
| **R3** | `log=` template-glob expansion (`{event_type}`, `{date}`, ...) | high | `_log_targets.py:70–147` | absent | TS takes literal paths only |
| **R4** | `log="admin"` alias resolves to `cfg.admin_log_location` | medium | `_log_targets.py:99–106` | absent | TS users must hardcode the admin log path |
| **R5** | Relative `log=` paths: cwd-first, yaml-dir fallback | medium | `_log_targets.py:124–134` | passes path raw to runtime | TS's behavior depends on CWD; surprising for config-supplied paths |
| **R6** | `where=` filter DSL (event_type_prefix, level_in, regex, starts_with, ...) | medium | `filters.py:1–142` | callable predicate only | TS users must write filter code; Python allows yaml-config filters |
| **R7** | `all_runs=` default scoping | medium | `_read_impl.py:414` uses module `$TN_RUN_ID` | `tn.ts:929` uses per-instance `_runId` | shared `$TN_RUN_ID` vs distinct instance ids — different filter behavior |
| **R8** | Protocol admin event filter bypass (`tn.*` event types skip run_id filter) | none | `_read_impl.py:334–341` | `tn.ts:961–973` | aligned |
| **R9** | `tn.read.tampered_row_skipped` emission on verify="skip" with loop-back protection | none | `read.py:69–84` | `tn.ts:1130–1142, 1026` | aligned |
| **R10** | Flat-dict envelope projection: Python includes `prev_hash` / `row_hash` / `signature`; TS excludes them | high | `reader.py:56–66` `FLAT_ENVELOPE_KEYS` | `read_shape.ts:13–20` `CRYPTO_ENVELOPE_KEYS` (split out) | callers reading `entry.prev_hash` via flat work in Python, fail in TS |
| **R11** | Chain validation: signature + recomputed row_hash + prev_hash continuity | none | `reader.py:618, 667, 679 + chain.py:32–46` | `read_as_recipient.ts:123–134 + chain.ts` | aligned |
| **R12** | Chain validation per event_type (not global) | none | `chain.py:32–46` | implicit in `prevHashByType` Map | aligned |
| **R13** | Cipher dispatch tries btn → jwe per kit; TS rejects jwe | **high** | `reader.py:415–418` | `read_as_recipient.ts:62–79` | TS cannot read JWE-encrypted foreign logs |
| **R14** | `{$no_read_key: true}` / `{$decrypt_error: true}` sentinel markers | none | `reader.py:347, 349` | `decrypt.ts:32–34` | aligned |
| **R15** | `{$unsupported_cipher: true}` graceful marker | medium | absent (Python raises FileNotFoundError) | `decrypt.ts:34, 79–80` | reverse drift — TS more lenient on jwe-without-key |
| **W4** | `watch(poll_interval)` seconds vs `watch(pollIntervalMs)` ms | **high** | `watch.py:38` | `tn.ts:245` | 1000× porting trap (already listed in §3) |
| **W5** | Watch multifile support via template glob | high | `_watch_impl.py:47–72 _resolve_watch_sources` | `watch.ts:49` literal only | mirrors R3 on the streaming side |
| **W6** | Watch monitor strategy: Python stat-poll only; TS chokidar (native fs.watch) with poll fallback | low | `_watch_impl.py:124` | `watch.ts:136–142` | TS more efficient; behaviorally equivalent |
| **W7** | Truncation detection (same inode, size < tracked offset) | none | `_watch_impl.py:154–157` | `watch.ts:79–94` | aligned, both emit `tn.watch.truncation_observed` |
| **W8** | Rotation handling: clear per-event-type prev_hash state | none | `_watch_impl.py:149–153` | `watch.ts:74–77` | aligned |
| **W9** | `since=` semantics: `"start"`, `"now"`, int sequence, ISO-8601 ts | none | `_watch_impl.py:75–85, 213–267` | `watch.ts:162–213` | aligned |
| **W10** | `watch(as_recipient=...)` raises NotImplementedError | none | `watch.py:359–367` | `tn.ts:1070–1074` | aligned limitation |
| **W11** | Watch lifecycle cleanup: Python file context manager close-on-exit; TS finally-block chokidar close | low | `_watch_impl.py:88–124` | `watch.ts:147–159` | TS more explicit; both correct |

---

## §8. Bundle / absorb / compile deep dive

The biggest section v1/v2 missed. Re-reading `tnpkg.py` (344),
`_pkg_impl.py` (315), `export.py` (960), `absorb.py` (1578),
`compile.py` (210), `offer.py`, `recipient_seal.py` (411),
`pkg.py`, `packaging.py`, `contacts.py`, `canonical.py` against
TS `compile.ts` (290), `tnpkg_io.ts` (140), `pkg/tnpkg.ts` (269),
`pkg/tnpkg_archive.ts` (240), `pkg/recipient_seal.ts` (500),
`pkg/agents_policy.ts`, `runtime/absorb_bootstrap.ts` (463):

| id | item | severity | Python | TS | why it matters |
|---|---|---|---|---|---|
| **W1** | `compile.ts` writes bespoke unsigned `CompiledManifest`; Python writes signed universal `TnpkgManifest` | **critical** | `compile.py:138–215 → export.py` | `compile.ts:198–273` (parallel implementation) | already detailed in §3 |
| **W2** | TS `KNOWN_KINDS` missing `identity_seed` | high | `tnpkg.py:64–85` | `core/tnpkg.ts:41–49` | already in §3 |
| **W3** | `project_seed` TS-only — no Python handler | high | absent | `absorb_bootstrap.ts:149, 320–365` | already in §3 |
| **B1** | TS lacks `tn.export(kind="identity_seed")` producer (absorb works, export doesn't) | medium | `export.py:352–392, _export_identity_seed` | absent | TS cannot mint identity_seed bundles; dashboard / wallet creation paths need this |
| **B2** | Export encryption options (`encrypt_body_with` BEK + `seal_for_recipient`) | medium | `export.py:749–762` | `pkg/index.ts:63–85` no encryption flags | vault integration needs encrypted body; TS callers can't produce |
| **B3** | Body encryption frame format (LEGACY: custom binary; NEW: STORED-zip + PK\x03\x04 magic) | medium | `export.py:881–910` | absent | back-compat path for old vault uploads; only matters if TS ever exports encrypted bodies |
| **B4** | Body encryption AAD: empty (vs. recipient seal AAD = manifest canonical bytes) | low | `export.py:840–843` | n/a | matches the two different paths; document so future TS impl doesn't confuse |
| **B5** | Multi-recipient (`to_dids: list[str]`) export | medium | `export.py:521–552, _merge_recipient_dids` | `pkg/index.ts` single `recipientDid` only | TS can't bundle for multiple recipients in one call |
| **B6** | Universal manifest scope-per-kind defaults (`full` for full_keystore, `identity` for identity_seed) | low | `export.py:913–922 _default_scope` | universal-side: `core/tnpkg.ts:133` defaults to `"admin"` | TS universal manifest writers must set scope explicitly; risk of wrong scope |
| **B7** | `identity_seed` state schema (`{schema: "tn-identity-seed-v1", nickname, minted_at}`) | medium | `export.py:352–362` | absent (TS has no producer) | informational |
| **B8** | `contact_update` absorb handler | low | `absorb.py:363–364 → _absorb_contact_update` | absent (no handler in `absorb_bootstrap.ts` or main runtime absorb) | vault-emitted contact updates ignored on TS — flag for vault rewrite |
| **B9** | `recipient_invite` reserved-but-rejected (both sides match) | none | `absorb.py:369–377` | `absorb_bootstrap.ts:152–162` | aligned |
| **B10** | Sealed-box unwrap before kind-specific handler | medium | `absorb.py:334–353` (verify sig → `_maybe_unseal_recipient_wrap` → dispatch) | `absorb_bootstrap.ts:132–145` bootstrap path **doesn't unseal** — main runtime absorb must | verify TS main runtime absorb does the unseal before kit_bundle dispatch |
| **B11** | `AbsorbReceipt.replaced_kit_paths: list[Path]` | medium | `absorb.py:103–111` | `core/results.ts` no equivalent field | programmatic absorb callers on TS can't detect kit replacement |
| **B12** | `AbsorbReceipt` legacy fields (`legacy_status`, `legacy_reason`) | low | `absorb.py:97–122` | absent | TS-new, no legacy compat needed |
| **B13** | Kit replacement on re-absorb: rename existing to `.previous.<ts>` sidecar | medium | `absorb.py:~1017–1070` | unclear — `absorb_bootstrap.ts` doesn't kit-replace; main runtime absorb may | verify TS main absorb does the same sidecar rename or kits get clobbered |
| **B14** | `compile_kit_bundle(full=True, confirm_includes_secrets=True)` safety gate | low | `export.py:417–423` | `pkg/index.ts:63–65 confirmIncludesSecrets` | aligned in spirit but TS compile.ts (separate path) doesn't have the gate |
| **B15** | `offer` return type: Python `Package`, TS `OfferReceipt` (status + sha256) | medium | `offer.py:33–68` | `pkg/index.ts:166–196` | callers expecting `Package` fail on TS |
| **B16** | `offer` writes to outbox directory; TS emits attested event instead | medium | `compile.py:107–127 emit_to_outbox` | `pkg/index.ts:166–196` `tn.offer.compiled` event | architectural difference — TS replaces outbox with event log |
| **B17** | `contacts.py` (14.4K) — local contact record storage | medium | full module | absent | TS has no local contacts store; will need one if TS clients track recipients |
| **B18** | `compile_enrolment` return type: Python `Package` with full payload; TS `CompiledPackage` with only `{outPath, manifestSha256}` | medium | `compile.py:32–104` | `pkg/index.ts:130–145` | callers expecting Package payload fail on TS |

---

## §9. Handler inventory

| handler | Python | TS | drift |
|---|---|---|---|
| `file.rotating` | ✓ | ✓ | ✓ |
| `file.timed_rotating` | ✓ | absent | **H1** |
| `file.templated` (PR #52) | ✓ | absent | **G (write side)** |
| `stdout` | ✓ | ✓ | ✓ |
| `kafka` | ✓ | absent | **H2** (gated on outbox H8) |
| `s3` | ✓ | absent | **H3** (gated on H8) |
| `delta` | ✓ | absent | **H4** (gated on H8) |
| `zenoh` | ✓ | absent | **H5** |
| `otel` | ✓ | ✓ | parity |
| `fs.drop` | ✓ | ✓ | parity |
| `fs.scan` | ✓ | ✓ | parity |
| `vault.pull` | ✓ | ✓ | wire-shape verification still TBD |
| `vault.push` | ✓ | ✓ | wire-shape verification still TBD |
| `vault.sync` | ✓ | absent | **H6** |
| `filter` (wrapper) | ✓ | absent | **H7** |
| `outbox` (durable retry queue, `persist-queue`) | ✓ | **absent** | **H8** — blocks kafka/s3/delta on TS |

---

## §10. Cipher inventory

| cipher | Python | TS |
|---|---|---|
| `btn` publish | `tn_btn` PyO3 | `tn-wasm` |
| `btn` recipient/read | `BtnGroupCipher.load` | `core/decrypt.ts decryptGroup` |
| `jwe` publish + recipient | `JWEGroupCipher` (pure Python, ECDH + AES-KW + AES-GCM) | **NOT IMPLEMENTED — throws** (`read_as_recipient.ts:64–70`, `node_runtime.ts:174–179`) |
| recipient seal (Ed25519→X25519, sealed-box) | `recipient_seal.py:69–110` libsodium | `core/recipient_seal.ts:134–150` @noble/curves — math match |

**JWE on TS is a known gap** documented in TS source. Blocks any TS
consumer using JWE-cipher ceremonies. Current rollout is BTN only,
so this hasn't bitten yet.

---

## §11. Subsystems missing entirely

| subsystem | Python | TS | severity |
|---|---|---|---|
| **CLI** (`tn init / add_recipient / rotate / absorb / read / streams / validate / show / bundle / wallet`) | full, ~86KB `cli.py` | absent | medium — operators run admin from a shell |
| **MCP server** (`tn-mcp-server`, `python -m tn.mcp`) | full | absent | low — only Python clients today |
| **Lint** (`tn.lint.engine`) | full | absent | low |

---

## §12. Browser implications (`tn-proto-web` and future in-browser DRM viewer)

- **R2** (key-bag) — yes, viewer holds N absorbed kits
- **R13** / cipher JWE — yes if any consumer in browser uses JWE
- **R3–R5** (path resolver) — partial; relative paths map to IndexedDB keys not filesystem
- **H** (atomic + flock keystore) — n/a (IndexedDB is transactional)
- **I3** (auto-cleanup) — n/a (page lifecycle, not process)
- **W1** (compile.ts wire-format break) — **yes**; the chrome-ext consumes the bespoke format today, so fixing W1 needs a coordinated chrome-ext bump too

---

## §13. Priority matrix (revised, with dependencies)

| id | item | TS effort | blocks |
|---|---|---|---|
| **W1** | unify compile.ts → universal signed manifest | medium (~300 LOC + chrome-ext bump) | **all bundle interop** |
| **W2** | add identity_seed to TS KNOWN_KINDS | trivial (~5 LOC) | future hardening |
| **W3** | port project_seed absorb to Python | medium (~250 LOC) | dashboard / vault → Python interop |
| **W4** | watch pollInterval unit naming | trivial | porting-trap |
| **R2** | TS key-bag read | medium (~180 LOC + agent-runtime parity test) | **witness, vault TS rewrite** |
| **H** | TS Node keystore atomic + CAS + flock (PR #51 port) | medium (~300 LOC + concurrent-writer test) | **every Node multi-process consumer** |
| **L4** | re-export `vault_client` HTTP client | small | **witness** |
| **L5** | wallet verbs (especially `wallet.restore`) | **large (~1500 LOC)** | **vault TS rewrite** |
| **H8** | durable outbox infrastructure (better-sqlite3) | **large (~800 LOC)** | **any kafka/s3/delta on TS** |
| **R3–R5** | port `_log_targets.py` to TS (cwd-first, admin alias, template glob) | small (~250 LOC) | demo / dashboard polish |
| **R1** | `read_all` cross-file merge | small | nice-to-have |
| **C1**/JWE cipher recipient path | medium (~500 LOC + byte-compare tests) | only JWE-cipher ceremonies |
| **A** | drop `$TN_HOME` from TS discovery chain | trivial | parity polish |
| **I3** | `process.on("beforeExit")` auto-cleanup | small | parity polish |
| **L1** | TS init keyword sugar (`name`, `stream`, `link`, `identity`, `project`) | small | parity polish |
| **L3** | `admin.addAgentRuntime` | small | maybe |
| **L6** | `scope()` context manager | small | nice-to-have |
| **L11** | `bootstrap_from_api_key` (TS challenge half) | medium | dashboard onboarding |
| **H1** | `file.timed_rotating` handler | small | nice-to-have |
| **H6** | `vault.sync` handler | medium | maybe |
| **P** | `stdout` profile | trivial | parity polish |
| **Q** | error taxonomy alignment | small | parity polish |
| **B1** | TS `tn.export(kind="identity_seed")` producer | medium (~200 LOC) | wallet creation |
| **B5** | multi-recipient export (`to_dids`) | small | bundle batching |
| **B11**/**B13** | `replaced_kit_paths` + kit-replacement sidecar | small | re-absorb safety |
| **B15**/**B16**/**B18** | offer / compile_enrolment return-shape parity | small each | caller portability |
| **B17** | port `contacts.py` to TS | medium (~400 LOC) | only if TS clients need local contact storage |
| **C3**/**C11** | template validation for PEL + admin_log_location yaml fields | small | catch broken yaml at load time |
| **C5** | TS JWE-cipher ceremony support (config + handlers) | medium-large | only if JWE ceremonies need TS |
| **I18**/**I19** | `bootstrap_from_api_key` writes sync_state.json | small | post-bootstrap provenance |

---

## §14. What survived verification (and what didn't)

Spot-verified the agents' highest-severity wire-format claims against
actual source. Recorded so we don't relitigate:

- ✅ **`compile.ts` bespoke manifest** — verified. Major break. (§3 W1)
- ✅ **TS `KNOWN_KINDS` missing identity_seed** — verified. (§3 W2)
- ✅ **`project_seed` exists on TS, absent on Python** — verified. (§3 W3)
- ✅ **Watch poll-interval unit mismatch** — verified. (§3 W4)
- ❌ **Timestamp format mismatch (`Z` vs `+00:00`)** — agent claimed Python writes `...Z` and TS writes `...+00:00`. Verified Python `_now_iso` returns `+00:00` (`export.py:56–58`); TS `nowIsoMillis` does `Z → +00:00` (`core/tnpkg.ts:259–263`). **Match.** NOT a drift item.
- ❌ **Canonical JSON separator drift** — agent flagged. Python uses `separators=(",", ":")`, `sort_keys=True` (`canonical.py:65`); TS routes through `tn-wasm`'s `canonicalBytes` (Rust-backed, documented to match). **Match.** Trust the wasm — but add cross-language byte-compare CI if not already present.
- ❌ **HKDF salt order** — agent flagged. Both compute `eph_pub || recipient_x_pub`. **Match.**
- ⚠️ **Ed25519→X25519 birational map** — Python uses libsodium, TS uses `@noble/curves`. Math is identical (well-known map). Worth a one-off byte-compare CI test on the derived X25519 pubkey if not already present.

### Sections I'm still NOT confident about

- **Handler wire shape** (`vault_push.ts` vs `vault_push.py`, `fs_drop.ts` vs `fs_drop.py`): I scanned the lists but didn't byte-compare the wire envelopes. Vault rewrite may need these to match exactly.
- **Watch chain validation across rotation**: TS `watch.ts:74–77` clears state; Python `_watch_impl.py:149–153` does the same. The exact rotation-boundary behavior (does prev_hash carry over the rotated file's last row?) is the same in concept but I didn't test it cross-language.
- **Config loader edge cases**: I have a 15-item list but there are surely more — `extends:` cycle detection, malformed yaml error messages, schema mismatch reporting, etc.
- **Profile handler chain bytes**: I confirmed the names match for 4/5 profiles but didn't diff the handler stack inside each.
- **Agents namespace**: `tn.agents.PolicyDocument` / `PolicyTemplate` exist on both sides. Whether the field shapes match (defaults, validation) is unverified.

---

## §15. Browser-extension implications

The Chrome extension currently consumes `compile.ts`'s `CompiledManifest`
shape. If we fix W1 by routing TS through the universal signed manifest,
the chrome-ext needs a coordinated bump or it breaks.

**Migration path** (one PR per step):
1. Add universal-manifest reader to chrome-ext alongside the bespoke
   `CompiledManifest` reader. Detect by presence of
   `manifest_signature_b64` field.
2. Switch `compileKitBundle` in `compile.ts` to route through the
   universal pipeline (signing, snake-case wire form, signed manifest).
3. Bump `tn-protocol`'s ts-sdk minor version; release chrome-ext
   update.
4. Add deprecation warning in `compile.ts` when reading old format
   bundles. Remove old-format reader in next major.

---

## §16. Rollout dependencies — critical path

Per session context, the next consumers of the ts-sdk are:

- **Witness server** (new) — needs **R2** (key-bag read), **L4**
  (vault HTTP client), **H** (Node-side keystore safety), **W1** (if
  it ever absorbs kit_bundles from TS publishers)
- **Vault TS rewrite** — needs **L5** (wallet flows), **R2**, **H**,
  **L4**, **B1** (identity_seed producer), **W1**, **W3** (project_seed
  absorb on Python receiving side)
- **Admin / plug-in tooling** — needs namespace fills (**L3**, **L4**,
  **L6**) + **W1**
- **In-browser DRM viewer** (`tn-proto-web`) — needs **R2**, JWE if
  used, **W1** coordinated with chrome-ext

**Critical-path bundle**: W1 + R2 + H + L4 + L5 unblock both witness
and vault. Without them, the witness re-implements foreign-log reading
and a vault HTTP client; the vault rewrite re-implements wallet
onboarding; AND any TS-produced kit bundle silently doesn't work on
Python consumers.

---

## §17. Open questions for human review

1. **W1 priority** — fix `compile.ts` before any consumer ships
   TS-produced kit bundles to Python? Or accept the break and ship a
   shim that translates between the two formats?
2. **`tn.scope()` worth porting?** Python has it; not yet a known
   external consumer. Could be dead surface.
3. **JWE on TS — defer or do?** Current rollout is BTN-only. One PR,
   not blocking.
4. **CLI on TS — `@tnproto/cli` separate package?** Splits cleanly.
5. **MCP server on TS — separate package?** Likely `@tnproto/mcp-server`.
6. **Outbox protocol** — `persist-queue` (Python, SQLite) →
   `better-sqlite3` (TS)?  Or defer kafka/s3/delta entirely until a
   consumer asks?
7. **`project_seed` direction** — port handler to Python (W3) or
   confirm it's TS-only by design?
8. **Run-id env stamping** (I1) — do we need TS to also stamp some
   process-wide handle so multi-`Tn`-instance read filtering matches
   Python's default? Or is the per-instance scoping actually the right
   semantics and Python's is the legacy bug?

---

## §18. What to do with this doc

Three options, unchanged from v2:

1. **Open as a PR for review**, ratchet down to a tracked set of
   GitHub issues once we agree on scope.
2. **Use as a planning doc**, file individual issues per item
   immediately.
3. **Treat as a snapshot** — re-run the audit every release to track
   drift over time.

Recommendation: **option 2** — file issues for **W1 / W2 / W3 / W4** as
the must-fix wire-format set, **R2 + H + L4 + L5** as the
witness/vault-rewrite blockers, and leave the rest as roadmap.
W1 specifically needs a coordinated chrome-ext bump, so file it with a
linked dependency on the chrome-ext repo.

---

---

## §19. The wasm boundary — why TS keeps drifting

The single most consequential thing I missed in v1 / v2: **the wasm
binding surface is structurally undersized compared to the PyO3
binding surface, and that asymmetry is the root cause of most drift in
§4–§8.**

### The three Rust bindings

| crate | binding | line count | surface |
|---|---|---|---|
| `crypto/tn-core` | (none — pure Rust) | ~310 KB across 21 .rs files, `runtime.rs` alone is 148 KB | Full `Runtime` API: ~40 public methods on `Runtime` + admin/cipher/handlers/pkg/storage submodules |
| `crypto/tn-core-py` | PyO3 | 856 LOC `lib.rs` + admin submodule | `PyRuntime` exposing **~25 methods** of the `Runtime` API (init, emit, read, secure_read, admin_*, vault_*, bundle_for_recipient, close, etc.) + `PyAdminStateCache` |
| `crypto/tn-wasm` | wasm-bindgen | 621 LOC `lib.rs` | **24 free functions + 1 class** (`BtnPublisher`). **No `Runtime` struct exposed.** |

### What's exposed via wasm-bindgen

From `crypto/tn-wasm/pkg/tn_wasm.d.ts` (the actual TS-visible surface):

- **Canonicalization** — `canonicalBytes`, `canonicalJson`
- **Signing** — `generateDeviceKey`, `deviceKeyFromSeed`, `deriveDidKey`, `signMessage`, `verifyDid`, `signatureB64`, `signatureFromB64`
- **Chain primitives** — `computeRowHash`, `zeroHash`, `buildEnvelope`
- **Indexing** — `deriveGroupIndexKey`, `indexToken`
- **Admin reducer kernel** — `adminReduce`, `adminCatalogKinds`, `adminValidateEmit`
- **btn cipher** — `BtnPublisher` (new / fromBytes / toBytes / mint / encrypt / revokeByLeaf / revokeKit / publisherId / epoch / treeHeight / maxLeaves / issuedCount / revokedCount), `btnDecrypt`, `btnCiphertextPublisherId`, `btnKitPublisherId`, `btnKitLeaf`, `btnTreeHeight`, `btnMaxLeaves`

**That's it.** Notably **NOT exposed**:

- `Runtime::init` / `Runtime::ephemeral` / `Runtime::close`
- `Runtime::emit` / `emit_with` / `emit_override_sign` / `emit_with_override_sign` / `info` / `warning` / `error` / `debug` / `log`
- `Runtime::read` / `read_all_runs` / `read_with_verify` / `read_raw` / `secure_read` / `read_raw_with_validity` / `read_from`
- `Runtime::admin_add_recipient` / `admin_revoke_recipient` / `admin_revoked_count` / `admin_add_agent_runtime` / `recipients` / `admin_state`
- `Runtime::bundle_for_recipient`
- `Runtime::vault_link` / `vault_unlink`
- `Runtime::add_handler` / `handler_count`
- `Runtime::set_level` / `set_level_value` / `get_level` / `is_enabled_for`
- The `handlers/` submodule (fs_drop, fs_scan, stdout, vault_pull, vault_push)
- The `pkg/` / `tnpkg.rs` / `runtime_export.rs` modules (universal manifest writers)
- `storage.rs`, `log_file.rs`, `keystore_backend.rs` (Rust-side keystore safety)
- `read_as_recipient.rs` (Rust-side recipient read)
- `admin_cache.rs` (the cache layer, separate from the reducer kernel)

`crypto/tn-wasm/Cargo.toml` is honest about this: the comment reads
`# Pure-compute modules only. No fs feature, no filesystem I/O.`

### Why this matters

`ts-sdk/src/runtime/node_runtime.ts` is **2604 lines** because it has
to re-implement everything `tn-core::Runtime` does — yaml loading,
keystore management, log file rotation, chain state per event_type,
multi-group field routing, admin event reduction orchestration, secure
read, recipient bundle assembly, vault link state — **all in
TypeScript, calling into wasm only for the cryptographic primitives
that ARE exposed.**

Compare to Python's `tn/__init__.py` (1214 LOC) + `_dispatch.py` (495):
Python's dispatch layer routes most behavior through
`PyRuntime` (i.e. `tn-core::Runtime`) and fans out to extra Python
handlers. The Rust core does the heavy lifting; Python adds
ergonomics. **TS has to do the heavy lifting twice** — once in
`tn-core::Runtime` (for the PyO3 consumer) and once in `node_runtime.ts`
(for the TS consumer).

This is why every drift item in §4–§8 exists: when Python's `Runtime`
gains a behavior (PR #51's keystore safety, PR #61's key-bag read,
PR #52's templated log paths, PR #55's discovery-chain refactor), it
flows to Python automatically because Python calls the Rust runtime.
TS has to reimplement the same behavior in `node_runtime.ts` by hand.
Nothing forces the implementations to stay in sync except cross-language
byte-compare tests, which are sparse.

### What IS shared correctly through wasm

The byte-format-load-bearing operations DO go through wasm:

- `core/canonical.ts:24` → wasm `canonicalBytes` ✓
- `core/chain.ts:4` → wasm `computeRowHash`, `zeroHash` ✓
  (with a `@noble/hashes` SHA-256 fallback at line 19 for
  "before tn-wasm has been initialized — notably browser bundles
  loaded before the .wasm file is fetched")
- `core/envelope.ts:1` → wasm `buildEnvelope` ✓
- `core/signing.ts:9` → wasm `signMessage` / `verifyDid` /
  `signatureB64` / `signatureFromB64` ✓
- `core/indexing.ts:1` → wasm `deriveGroupIndexKey` / `indexToken` ✓
- `core/decrypt.ts:7` → wasm `btnDecrypt` ✓
- `raw.ts` → re-exports `BtnPublisher` for `node_runtime.ts` to
  publish-side encrypt ✓

So the **cryptographic byte format is shared** — row_hash, signature,
canonical bytes, envelope NDJSON line, btn ciphertext.

### What is NOT shared through wasm — wire-format risk

- **Recipient seal Ed25519 → X25519 derivation**: `core/recipient_seal.ts:30`
  uses `@noble/curves`' `edwardsToMontgomeryPub` / `edwardsToMontgomeryPriv`.
  Python uses libsodium (`nacl.bindings.crypto_sign_ed25519_pk_to_curve25519`).
  Rust uses `curve25519-dalek`. **Three independent implementations of
  the same birational map.** The math is well-defined and identical
  in spec; whether all three produce identical bytes needs a
  cross-language byte-compare CI test if not already present.
- **HKDF-SHA256 / AES-256-GCM / AES-KW** for recipient seal:
  `@noble/hashes/hkdf` + WebCrypto `crypto.subtle` on TS side; Python's
  `cryptography` library; Rust's `aes-gcm` / `aes-kw` crates. Standard
  algorithms; should match given identical inputs but worth byte-compare.
- **STORED zip encoding**: `ts-sdk/src/compile.ts` and
  `ts-sdk/src/pkg/tnpkg_archive.ts` both hand-roll a minimal STORED-zip
  encoder. Python uses the stdlib `zipfile.ZipFile(compression=ZIP_STORED)`.
  Bytes should match (STORED is a simple format), but file-name
  ordering inside the central directory could differ.
- **Universal manifest canonical bytes**: routed through wasm
  `canonicalize`, so this IS shared. ✓
- **`compile.ts`'s bespoke `CompiledManifest`**: written as
  `JSON.stringify(manifest, null, 2) + "\n"`, NOT canonical bytes.
  This is the W1 wire-format break in §3.

### Fix options

**(a) Widen the wasm surface** — add `WasmRuntime` to
`crypto/tn-wasm/src/lib.rs` exposing the same ~25 methods PyO3 wraps
(`init`, `emit*`, `read*`, `admin_*`, `vault_*`, `close`,
`bundle_for_recipient`). The Rust code already exists in
`tn-core::Runtime`; only the wasm-bindgen wrappers are missing.

**Tricky parts**:
- `Runtime::init(yaml_path: &Path)` reads from disk. Browser has no
  filesystem; would need a storage abstraction trait so the same
  `Runtime` API can run against IndexedDB-backed storage in browser
  and `fs`-backed storage in Node. Roughly: extract a
  `trait Storage { read/write/list/delete }` from
  `tn-core/src/storage.rs`, implement it for `tn-wasm` over JS
  callbacks, plumb through.
- `add_handler` accepts trait objects (`Arc<dyn TnHandler>`). Not
  expressible across the wasm boundary directly; would need an
  envelope-callback shape `(envelope: any) => Promise<void>` registered
  from TS.
- Async handler outboxes (issue H8) — Rust uses `persist-queue`-equivalent
  in `tn-core`; bring along too.

Concrete effort: ~500–800 LOC across `tn-wasm/src/` + storage trait +
TS shim. Eliminates most of `node_runtime.ts` (the orchestration
layer), keeps the TS handler implementations (which are Node-fs and
JS-network calls).

**(b) Accept the dual implementation** but invest in cross-language
byte-compare CI on every primitive AND every public verb. Current
state: byte-compare exists for some primitives (canonical, row_hash)
but not for full flow (no test asserts "TS-emitted envelope decrypts
byte-identical to Python-emitted envelope under the same kit"). This
is the path we're on by default; expensive to keep in sync.

**(c) Hybrid** — widen wasm to expose the chain validation kernel +
emit pipeline (the byte-format-load-bearing parts) but leave I/O in TS.
This is roughly the design intent today; the boundary just isn't drawn
where the comment in `tn-wasm/Cargo.toml` claims. Move emit / read /
admin orchestration to Rust; keep storage / handler / config-load in
TS. ~300 LOC.

### Recommendation

For the witness + vault TS rewrite + browser-DRM rollout: **(c)
hybrid is the most pragmatic.**

- Expose `WasmRuntime::emit` / `read` / `admin_reduce_envelope` /
  `recipients` / `admin_state` / `bundle_for_recipient_canonical_bytes`
  from `tn-wasm`. These are the methods where byte-format drift is
  most dangerous and where most of node_runtime.ts's complexity lives.
- Keep storage + handler + yaml config in TS (where they need to
  call Node `fs` / `chokidar` / `https` anyway).
- Add a cross-language interop CI test that emits N envelopes from
  TS and reads them with Python, plus the reverse, asserting Entry
  shapes match field-for-field.

For the browser viewer specifically: option (a) is the only path
that scales. Without it, the browser-side TS re-implementation grows
unbounded as `tn-core::Runtime` does.

### Drift items added by this analysis

| id | item | severity | action |
|---|---|---|---|
| **WASM1** | `tn-wasm` exposes no `Runtime` — TS reimplements 2604 LOC of orchestration | structural | option (c) or (a); see above |
| **WASM2** | Recipient seal Ed25519→X25519 derivation uses three independent crypto libs (libsodium / @noble / curve25519-dalek) without an enforced cross-language byte-compare CI test | medium | add a 30-line CI test that asserts the derived X25519 pubkey matches across all three sides for a known Ed25519 seed |
| **WASM3** | HKDF + AES-GCM + AES-KW used in recipient seal not byte-compared cross-language | medium | extend the WASM2 test to cover the wrapped BEK bytes |
| **WASM4** | STORED-zip encoder hand-rolled in two places on TS side (`compile.ts` and `pkg/tnpkg_archive.ts`) with no cross-platform byte-compare | low | once W1 lands, only one encoder remains; add a byte-compare test against Python's `zipfile.ZipFile` output |
| **WASM5** | `core/chain.ts` has a `@noble/hashes` fallback for SHA-256 in case wasm hasn't loaded yet — this fallback path silently bypasses the byte-tested wasm `computeRowHash` | low | document explicitly that the fallback is byte-equivalent (it is — both are SHA-256), and add a CI test that confirms the fallback path produces identical output |
| **WASM6** | `tn-wasm` exposes `BtnPublisher` (the encrypt side) and `btnDecrypt` but NOT the `tn-core::cipher::btn::PublisherState::from_bytes(x).to_bytes()` round-trip stability invariant that PR #51 fixed Python-side. TS-side `BtnPublisher.toBytes()` / `fromBytes` round-trip stability is unverified | medium | port the PR #51 stability test to TS |
| **WASM7** | TS path uses `@noble/curves` x25519 for one operation and wasm BtnPublisher for the same family of operations — two crypto stacks shipped together; security audit surface 2× | structural | acceptable for now (both audited libraries); flag for review if a single primitive is ever found to drift |

---

*This doc replaces v1 and v2. Diff against `1edd426` working tree.*
*See §14 for items I verified against actual code vs items I'm still
relying on agent reports for, and §19 for the wasm-boundary root-cause
analysis.*
