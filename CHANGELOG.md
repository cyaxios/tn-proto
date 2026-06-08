# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.6a1] - 2026-06-07 -- Internal refactor: tn-core module splits

Maintenance release. No API or wire-format changes — the Rust core was
reorganized for readability and the build is byte-identical to 0.5.5a1
(the full Rust golden/interop suite passes unchanged at 311 tests).

* **`runtime.rs` split.** The 1,935-line `runtime.rs` was decomposed into
  focused submodules (`cipher_build`, `chain_seed`, `log_session`,
  `entry_shape`, `helpers`, alongside the earlier `emit`/`admin`/`init`/
  `read`), leaving the parent at ~735 lines of structs + `impl Runtime`.
* **`admin_cache.rs` split.** Per-event-type envelope handlers and LKV
  snapshot save/load moved into `admin_cache/handlers.rs` and
  `admin_cache/persist.rs`; the parent drops from 1,273 to ~491 lines.
* **Dead code cleared.** Removed the vestigial `GroupState.index_key`
  field and the unwired `discover_retired_btn_states` reader (intent
  tracked in #118); `tn-core` now builds warning-free.

## [0.5.5a1] - 2026-06-06 -- CLI parity (both directions) + day-1 vault sync + real seal-for-recipient

A large CLI-parity and vault-sync release, all verified against a live dev vault.

* **Full Python <-> TS CLI parity.** Every verb now exists and is callable on
  both sides. Python gained `seal`, `verify`, `canonical`, `info`, `compile`,
  `vault link/unlink`, and a new `invite` verb (mints a real `tn-invite-*.zip`).
  TS gained `bundle`, `add_recipient`, `group add`, `absorb`, `wallet sync`,
  `wallet status`, `wallet pull-prefs`, `wallet export-mnemonic`,
  `show profiles`, `firehose stats/list/get`, and `inbox accept/list-local`.
* **Day-1 single-user vault lifecycle (live-vault tested).** Backup -> restore
  round-trips byte-for-byte (keystore + yaml + groups + log), the restored
  ceremony reads its prior entries and writes new ones; negatives (wrong
  passphrase, stale If-Match conflict) are enforced. Python `wallet sync` push
  now rides the **AWK/BEK whole-body** model, replacing the deprecated per-file
  `upload_file` path.
* **Two-device group sync (both languages).** A group's key material now rides
  the account-inbox merge path (sealed `full_keystore`/`scope=group_keys`
  snapshot), so a group created on one device becomes usable on another;
  concurrent group adds union with no clobber. (Concurrent main-log content
  writes under a shared device key remain last-write-wins -- a separate,
  documented limitation.)
* **Real `--seal-for-recipient` in TS.** `bundle`/`add_recipient` now seal a
  bundle to a recipient DID for real: the named recipient decrypts, a different
  recipient cannot (mutation-proven cryptographic binding). Previously they
  refused it; one path silently shipped an unsealed bundle.
* **Bug fixes.** TS `seal`/`verify` were broken at HEAD (the device_identity
  naming flip missed the CLI); `tn bundle` arg name; `inbox accept` kit entry
  name (`<group>.btn.mykit`); `compile --label` persistence; `cli_info` `_sign`
  type; `wallet pull-prefs --help` crash; `pushCeremonyBody` missing `nonce_b64`.
* **Tests.** Real round-trip + tamper coverage: real `seal -> verify` chain,
  `secure_read` forged-signature + chain-break rejection, `absorb` on-disk
  install + recipient read-back, and a full multi-device account-sync capstone
  (both languages + Python->TS cross-impl) -- all against a live dev vault.

## [0.4.3a2] - 2026-05-22 -- CLI receive-side parity + CF 1010 UA fix

Three CLI/SDK additions to close the dashboard receive-side parity
gap, plus a small but important fix for non-CF egress clients:

* **tn account connect <code>**: new CLI verb that redeems a
  one-shot tn_connect_<random> code minted from the vault dashboards
  Identities tab. Signs sha256(code) with the local Ed25519 device
  key and POSTs {code, did, signature_b64} to
  /api/v1/account/connect-codes/redeem. On success the device DID
  joins the human OAuth accounts minted_dids[], and subsequent
  vault calls from that DID resolve to the human account_id (via the
  vault-sides connect-bound-DID-first lookup in deps.py).
* **tn wallet sync --pull**: drains the vault accounts inbox into a
  local staging dir. Uses the dashboard-shaped
  GET /api/v1/account/inbox aggregator so a CLI operator sees the
  same listing the browser does. Stops at staging; tn absorb is
  the separate materialization step (observable + scriptable).
* **tn absorb**: when absorbing a kit_bundle tnpkg and the
  ceremony is account-bound, also POSTs the manifest + body to
  /api/v1/account/received-kits so the dashboards /projects
  Received tab shows the CLI-absorbed kit alongside browser-absorbed
  ones. Best-effort + non-fatal -- local materialization is the
  source of truth.

* **CF 1010 fix**: every outbound HTTP call in tn.bootstrap and
  tn.vault_client now sets User-Agent: tn-protocol/<version>.
  The default Python-urllib/3.x UA was getting 403d at the CF
  edge with body error code: 1010 before requests reached the
  vault application, blocking bootstrap_from_api_key from any
  non-CF-trusted egress (local dev, CI, AWS / GCP / Azure). Auth
  boundary stays at the DID signature on /auth/verify; UA is purely
  for routing past the Browser Integrity Check.

* **tn absorb error visibility**: the best-effort POST to
  /received-kits now surfaces the real failure (typed exception
  name + first 120 chars of response body) instead of a generic
  vault auth failed. Failures still swallow into a WARNING; local
  absorb still wins.

## [0.4.3a1] - 2026-05-20 — identity-naming flip + btn rotation hook

Single coordinated cut of the identity-and-key naming spec
(`docs/superpowers/specs/2026-05-20-identity-and-key-naming.md`),
flipping the canonical vocabulary from `did` / role-suffixed
`*_did` fields to `device_identity` / `*_identity`. Pre-`0.4.3a1`
logs and yamls are not loadable in this release; the project has
no production data to preserve so no migration tool ships.

The 0.4.3 btn cipher rotation (separate spec) was originally
queued as its own release; that work is still pending and will
land on this same branch before tag.

### Wire format

- **Envelope top-level field** flips from `"did": "..."` to
  `"device_identity": "..."`. row_hash and signature math are
  byte-identical across the rename (the hasher consumes field
  *values*, not field *names*) so pre-rename signed logs remain
  signature-verifiable — only the envelope JSON shape changes.
  This contradicts handover land-mine #1 but is provable from
  `chain_golden` passing byte-identically after the flip.
- **`compute_row_hash` parameter** (Python + Rust) renamed
  `did=` → `device_identity=`. All four Python call sites
  (`logger.py`, `reader.py` ×2, `_dispatch.py`) updated.

### Admin event payload field names

Catalog + reducer + emit-site rename across all 11 admin events:

```
device_did      → device_identity     (tn.ceremony.init)
publisher_did   → publisher_identity  (tn.group.added)
recipient_did   → recipient_identity  (tn.recipient.added/.revoked)
to_did          → recipient_identity  (tn.coupon.issued; collapsed)
peer_did        → peer_identity       (tn.enrolment.compiled)
from_did        → publisher_identity  (tn.enrolment.absorbed; collapsed)
vault_did       → vault_identity      (tn.vault.linked/.unlinked)
envelope_did    → envelope_device_identity (tn.read.tampered_row_skipped)
```

### yaml schema

- Top-level `me: {did: ...}` block renamed to
  `device: {device_identity: ...}`. The yaml loader rejects the
  legacy `me:` block at structural validation with a pointer to
  this entry.
- Group recipient list entries `{"did": "did:key:z..."}` flipped
  to `{"recipient_identity": "did:key:z..."}` for both the yaml
  shape and the JWE sidecar (`<group>.jwe.recipients`).

### Python API

- `DeviceKey.device_identity` is now the canonical dataclass
  field; `DeviceKey.did` is a `@property` returning the same
  string for back-compat. Code that did `cfg.device.did`
  continues to work indefinitely; new code should reach for
  `cfg.device.device_identity`.
- `RotateGroupResult.cipher_actually_rotated` (shipped in
  0.4.2a10) is still `False` for btn until the cipher rotation
  spec lands on this branch; flips to `True` then.

### `LooseRotationWarning` (0.4.2a10 stopgap)

Still raised on btn `tn.admin.rotate(...)`. Removal is bundled
with the cipher rotation work (`docs/superpowers/specs/
2026-05-20-btn-cipher-rotation.md`), pending land on this
branch before tag.

### Cascade still in flight on this branch

- TS SDK + wasm envelope/admin reads — Phase G of the handover;
  not yet committed. Until landed, the
  `secure_read_interop::{python,ts}_admin_events_byte_compare`
  Rust tests fail (they compare against TS/Python committed
  reference output that doesn't yet carry the new shape).
- tnpkg manifest field rename
  (`signer_did`/`from_did`/`to_did` on the kit_bundle /
  enrolment / offer / identity_seed manifest wire format) —
  not in this commit; queued as a follow-on.
- tn_proto_web mongo schema + API column rename — cross-repo;
  Phase H of the handover, not yet committed.
- Python maturin wheels need rebuild (`nox -s build_core
  build_btn`) before `pip install` picks up the new
  `tn_core` / `tn_btn` field shapes; otherwise tests that
  import the extension fail with `ModuleNotFoundError` cleanup.

Status at tag time: 44/47 Rust test suites green; remaining 3
are scoped to phases G + tnpkg manifest follow-on.

## [0.4.2a6] - 2026-05-19

One bug filed against `0.4.2a5`. Python-only — no Rust changes;
`tn-core` stays at `0.2.0a5`. TS package version bumps for tag
parity only.

### Fixed

- **Auto-init via `tn.info()` (no explicit `tn.init()` first) now
  produces the same flat `.tn/default/{admin,keys,logs,vault}/`
  layout as explicit `tn.init()`.** Previously auto-init dispatched
  through `tn.init(<canonical_yaml_path>)`, which routed
  `config.create_fresh` without a `keystore_dir` override and fell
  back to the legacy `<yaml_dir>/.tn/<yaml_stem>/...` rule —
  producing the nested `.tn/default/.tn/tn/{admin,keys,logs}/`
  layout (and silently dropping the `vault/` subdir that the
  multi-ceremony path creates). The ceremony worked, but the layout
  diverged from explicit init.

  Fix: when auto-init creates a fresh ceremony at the canonical
  `<cwd>/.tn/default/tn.yaml` location, dispatch through the no-arg
  `tn.init()` so both paths converge on `_create_default_ceremony`
  → flat layout. Existing yamls (`was_created=False`) and explicit
  `TN_YAML=...` overrides keep their literal paths and behaviour.

### Tests

- `python/tests/test_autoinit_layout.py` (2 cases): pin the
  layout equivalence between auto-init and explicit init, and an
  anti-regression check that the nested `.tn/default/.tn/tn/`
  shape never reappears.

Full Python suite: 851 passed, 0 regressions, 8 documented xfails.

## [0.4.2a5] - 2026-05-19

Two follow-up bugs filed against `0.4.2a4`. Python-only — no Rust
changes; `tn-core` stays at `0.2.0a5`.

Released in Python as `tn-protocol 0.4.2a5` and in TS as
`@tnproto/sdk 0.4.2-alpha.5` (tag parity, no TS code changes).

### Fixed

- **W6 (real bug): `tn.watch(log='admin', since=<historical>)` was
  silently dropping admin entries that lack `run_id`.** The Rust
  read pipeline correctly produced all 6 of 6 entries from the admin
  log, and `tn.read(log='admin')` (using `Entry.from_raw`) yielded
  all of them. But `tn.watch` (using `Entry.from_flat`) hard-rejected
  any envelope without a `run_id` field — and admin events emitted
  by runtime verbs (`ensure_group`, `rotate`, etc.) legitimately
  lack one (the row was minted outside a run context).
  `Entry.from_raw` already defaulted `run_id` to `""` in that case
  (and the comment on that path explicitly mentions admin events);
  `Entry.from_flat` was the strict outlier. Fix removes `run_id`
  from `from_flat`'s required-fields tuple so both constructors
  share the same leniency.

- **W5: `tn.watch()` from a no-ceremony directory now raises the
  same friendly "no ceremony found" error as `tn.read()`.**
  Previously watch called `current_config()` directly, which
  raised the less-helpful "no active runtime" message (and in
  states where a stale runtime was loaded from a prior init in a
  different directory, watch silently tailed that runtime's log
  instead of erroring). `_watch_impl` now calls
  `tn._maybe_autoinit_load_only()` first — same as `tn.read` —
  so both verbs share the discovery-chain error path.

### Tests

- `python/tests/test_watch_bugs_w5_w6.py` (5 cases): pins the W5
  symmetric-error behavior, the W6 admin-watch yields-all-six
  behavior, the `Entry.from_flat` leniency for missing `run_id`,
  and a boundary test confirming other required envelope fields
  still raise on absence.

Full Python suite: 849 passed, 0 regressions, 8 documented xfails.

## [0.4.2a4] - 2026-05-19

Four follow-up items filed against `0.4.2a3`. `#10` is the actual
fix; `#21` / `#22` / `#23` are CLI/stdout polish.

Released in Python as `tn-protocol 0.4.2a4` (+ `tn-core 0.2.0a5`) and
in TS as `@tnproto/sdk 0.4.2-alpha.4`. No TS code changes; tag parity
only.

### Changed

- **`tn.read()` (default `verify=False`) is now resilient to
  per-row corruption.** Previously a single malformed entry (corrupt
  base64 ciphertext from a partial write, disk corruption) raised
  `ValueError` and killed the iterator mid-stream — clean entries
  before and after the bad one never reached the caller. Now the
  default skips the bad row and continues; `result.stats.skipped_parse`
  ticks (callers who want a count can read it post-iteration), and
  the optional `on_skip` callback still fires with a `parse:`-prefixed
  reason. `verify=True` still raises (the explicit fail-loud
  contract); `verify='skip'` still emits the admin event and fires
  the callback.

- **`tn show` with no subverb dispatches to `tn show env`** instead
  of an argparse usage error (DX review #21). Friendly first
  impression; explicit `tn show env` / `tn show profiles` are
  unchanged.

- **Stdout handler filters `tn.*` admin events by default** (DX
  review #23). A fresh `tn.init()` + `tn.info('hello', x=1)` now
  prints exactly one stdout line, not four. Both the Rust-native
  stdout handler (the auto-registered one) and the Python
  `StdoutHandler` apply the filter. Opt back in via
  `TN_STDOUT_INCLUDE_ADMIN=1` (process-wide) or `include_admin=True`
  on a per-handler basis (`StdoutHandler(stream=..., include_admin=True)`
  and the yaml `handlers: [{kind: stdout, include_admin: true}]` form).

### Added

- **`tn show profiles` CLI** (DX review #22). Prints the 5-profile
  catalog with `encrypts` / `signs` / `chains` / `flush` /
  `default_sink` columns + `intended_use` blurbs. `--format json`
  for tooling. The catalog metadata already lived in
  `tn._profiles._CATALOG`; this verb gives it a public CLI surface.

### Tests

- `python/tests/test_read_skip_observability.py::test_verify_false_yields_around_parse_error`
  — pins the new `verify=False` resilience behaviour with a corrupt
  middle row.
- `python/tests/test_show_and_stdout_polish.py` (6 cases): `tn show`
  no-args, `tn show profiles` (human + json), stdout admin filter
  (default-off, env opt-in, per-handler kwarg).

## [0.4.2a3] - 2026-05-18

Follow-up fix to the DX review batch in 0.4.2a2. The cross-process init
lock landed in `0.4.2a2` made `tn.yaml` / keystore consistent under
concurrent workers, but exposed a second-order chain-integrity bug:
each worker's runtime kept a process-local view of the chain tip, so
parallel emits raced on `prev_hash` and the on-disk chain branched.
A 4-worker × 50-emit stress test was rejecting ~65% of entries on
`tn.read(verify=True)` after `0.4.2a2`; this release closes that gap.

Released in Python as `tn-protocol 0.4.2a3` (+ `tn-core 0.2.0a4`) and
in TS as `@tnproto/sdk 0.4.2-alpha.3`. The TS SDK has no Rust runtime
changes — same source as `0.4.2-alpha.2`, version bump only for tag
parity.

### Fixed

- **Cross-process emit chain integrity.** Every emit now bookends
  steps 4–9 of the runtime pipeline (chain advance, row-hash,
  signing, envelope serialize, log append, chain commit) with an
  advisory file lock on a sentinel adjacent to the target log
  (`<log>.emit.lock`). Under the lock, the runtime re-reads the log
  tail to derive the disk-truth `(seq, prev_hash)` for this
  `event_type` and seeds `ChainState` before `advance` runs. The
  in-memory chain becomes a cache; the file is the authority.

  The fix preserves the gunicorn/uvicorn/celery multi-worker use
  cases that the `0.4.2a2` init-lock work was scoped for. Lock cost
  is ~1 ms per emit on local FS — negligible for non-hot paths;
  hot-path batching is out of scope for this release.

  Wasm consumers inherit the trait's no-op lock impl (single-process,
  single-threaded — no race to coordinate).

- **`tn.read(verify='skip')` survives parse errors mid-stream.**
  Previously, a malformed entry (corrupt base64 ciphertext from a
  partial write, disk corruption, schema mismatch) raised out of
  the read iterator and clean entries before/after the bad one
  were never yielded. Now the Rust read pipeline (`read_from`,
  `read_from_with_validity`) catches per-row failures and yields a
  sentinel envelope (`event_type == "<parse-error>"`); the Python
  verify loop routes those into `stats.skipped_parse` (distinct
  from `skipped_verify`) and fires the `on_skip` callback so
  observability stays intact. Verification semantics elsewhere are
  unchanged: `verify=True` still raises after the callback,
  `verify=False` still raises on parse errors (the documented
  fail-loud contract).

### Changed

- **`tn-core` dependency floor in `tn-protocol`** raised to
  `>=0.2.0a4` (was `>=0.2.0a1`). Earlier `tn-core` wheels lack the
  emit lock; tightening the floor guarantees that
  `pip install tn-protocol==0.4.2a3` always pulls in a runtime that
  serialises emit across processes.

### Tests

- `python/tests/test_concurrent_emit_chain.py` (3 cases): 4 workers
  × 50 emits, 8 workers × 25 emits, and 5-iteration stress all yield
  every entry with `tn.read(verify=True)` succeeding. 2000/2000
  rows across 10 iterations on the development box.
- `python/tests/test_read_parse_resilience.py` (3 cases): pin the
  spec the tester filed — clean entries before and after a
  parse-failing row both surface; `stats.skipped_parse=1`;
  `on_skip` fires once with a `parse:`-prefixed reason.
- `crypto/tn-core/src/chain.rs` `chain_tip_tests` (3 cases): unit
  tests for the new `chain_tips_from_ndjson` helper that powers the
  under-lock disk refresh.

## [0.4.2a2] - 2026-05-18

DX review batch — 10 numbered findings closed (criticals through nits)
plus the profile-catalog audit and matrix tests. The papercut cycle
that started in 0.4.2a1 continues; the install / verify / read /
ceremony create paths are noticeably less surprising. See `DX_FIXES.md`
in the repo for per-finding root cause + verify command + risks.

Released in Python as `tn-protocol 0.4.2a2` and in TS as
`@tnproto/sdk 0.4.2-alpha.2`.

### Added

- **Polymorphic `recipient=` kwarg on `tn.admin.add_recipient` and
  `tn.admin.revoke_recipient`** (Python + TS). Single named argument
  accepts a DID string, an int leaf_index, a 32-byte X25519 public
  key, an `AddRecipientResult` from the matching `add_recipient`
  call, a contacts.yaml row dict, or any object with
  `recipient_did` / `leaf_index` / `public_key` attributes. Existing
  `recipient_did=` / `leaf_index=` / `public_key=` kwargs keep
  working and override the resolved fields. TS exposes branded
  helpers (`did()`, `leafIndex()`, `publicKeyBytes()`) for
  compile-time narrowing alongside the runtime resolver.

- **btn `tn.admin.revoke_recipient` accepts `recipient_did=`**
  (resolves automatically via `tn.admin.recipients(group)`). Closes
  the long-standing asymmetry where btn revoke required a
  `leaf_index` while jwe revoke used the did.

- **`tn.log` gains an optional `level=` kwarg** (DX review #13). Use
  it to stamp non-standard levels (`"trace"`, `"audit"`, foreign
  logger spellings) or bridge from another logging system.
  Default level is `""` (severity-less, unchanged). `tn.log` always
  emits regardless of threshold — distinct from the named-level
  verbs.

- **`tn.read` returns a stats-bearing iterator + `on_skip` callback**
  (DX review #10 / #11). The returned object has a `.stats`
  attribute (`ReadStats` — `yielded`, `skipped_parse`,
  `skipped_verify`, `skipped_reasons`) that ticks incrementally
  during iteration. Pass `on_skip=lambda env, reason: ...` to be
  notified per skipped row under `verify="skip"`, or once before
  the `VerifyError` propagates under `verify=True`. Iteration
  protocol is preserved — `for e in tn.read(): ...` works
  unchanged.

- **`tn validate` catches yaml.me.did vs keystore.local.public
  mismatch** (DX review #2). Non-zero exit + diagnostic naming both
  DIDs. The very condition the runtime refuses to load is now
  surfaced by the validator that should be guarding it.

- **`tn.init(link=False)` produces a `mode: local` ceremony**
  (DX review #5). Previously a silent no-op; now writes
  `ceremony.mode: local` + empty `linked_vault` for air-gapped
  deployments. `link=True` / `link=None` preserve the linked
  default.

- **DX_FIXES.md at repo root** — patch notes for testers with root
  cause, copy-pasteable verify commands, and risks/regressions per
  finding.

### Changed

- **Profiles drive `ceremony.sign` + handler list** (DX review #4
  + profile audit). `tn.init(profile="telemetry")` now writes
  `sign: false` to yaml AND drops the file.rotating handler — both
  for the default ceremony and per-stream yamls. The Rust runtime
  already honoured `sign: false`; signature-verify on read now
  respects it too (DX review #6 — see below). The `chains` and
  `flush` profile axes remain Rust-runtime gaps; documented in
  `python/tests/test_profile_full_matrix.py` as xfailed tests.

- **`tn.read(verify=True)` no longer always raises on `sign:false`
  ceremonies** (DX review #6). When the ceremony was minted with
  `sign: false` (e.g. profile=telemetry), the signature axis is
  dropped from the integrity check so entries don't fail
  verify-by-design. Other checks (`chain`, `row_hash`, decrypt)
  still fire.

- **`tn.info` / `.warning` / `.error` / `.debug` / `.log` reject
  extra positionals with `TypeError`** (DX review #3). Previously
  the positional tail was silently folded into a joined `message`
  field, destroying the caller's structured intent. The new error
  message names the dropped args and points at the kwargs +
  `message=` migrations.

- **`tn.admin.ensure_group` hot-reloads the live runtime**
  (DX review #8). After writing the new group to yaml, the
  in-process runtime now picks up the new routing without needing
  a `flush_and_close() + tn.init()` round-trip.

- **`tn.read(verify=...)` type narrowed** to
  `bool | Literal["skip", "raise"]` (DX review #17). IDEs
  autocomplete the legal string values. Runtime accepts the same
  four values (`False`, `True`, `"skip"`, `"raise"`).

- **README "Reading: all runs, this run, admin"** updated to match
  the actual default (`all_runs=True` since 0.4.1a3). New
  contract test pins the default so any future flip ships with a
  coordinated doc update (DX review #7).

- **README "Profiles" section** added — catalog table + one
  example per profile + wired-vs-gap matrix.

- **README "Project identity and named streams"** section added
  (DX review #14) — explains why `tn.init('billing')` also mints
  `.tn/default/` (named ceremonies share the project identity via
  `extends:`), and points at the `yaml_path=` form for callers who
  want a truly self-contained ceremony.

- **`tn-protocol` base deps now declare `pydantic>=2` explicitly.**
  `tn._entry.Entry` is a pydantic `BaseModel`; today this dep
  arrived transitively via `mcp`. Declared directly to keep the
  install working regardless of what pulls in pydantic.

### Fixed

- **Concurrent `tn.init()` across processes no longer corrupts the
  ceremony** (DX review #1). A per-name cross-process lock
  (`O_CREAT | O_EXCL` sentinel under `.tn/.init.<name>.lock`,
  60 s stale-reap) serialises the create branch. The
  gunicorn/uvicorn-workers/celery race that previously left an
  on-disk yaml whose `me.did` didn't match the keystore is closed.

## [0.4.2a1] - 2026-05-17

Four follow-up fixes surfaced by the white-glove suite run against
0.4.1a3. Picks up where the read / absorb default flips left off.

Released in Python as `tn-protocol 0.4.2a1` and in TS as
`@tnproto/sdk 0.4.2-alpha.1`.

### Changed

- **CLI `tn read` defaults to `--all-runs`.** Matches the Python API
  change from 0.4.1a3. A fresh `tn read` invocation now returns every
  entry on disk. Restrict to the current process run with
  `tn read --no-all-runs`.

- **`tn.init(stream='<name>')` rebinds the module singleton.** Before
  0.4.2a1, passing `stream=` returned a per-stream handle but left
  module-level `tn.info(...)` calls bound to the default ceremony, so
  emits silently landed in `default` instead of the named stream. The
  rebind now matches the docstring ("focus on `<name>` for subsequent
  module-level calls"). The handle return value is unchanged.

### Added

- **`tn.KeystoreConflictError`** at the package top level. Re-export
  of the Rust-bound runtime exception so callers can write a stable
  `except tn.KeystoreConflictError:` instead of importing from the
  private `tn_core._core` module.

- **`tn.is_keystore_diverged(exc)`** predicate. The runtime
  exception class is shared across many failure modes; this helper
  returns `True` only when the exception message carries the
  divergence marker, so deploy scripts can safely retry the admin
  verb after a concurrent writer race::

      try:
          tn.admin.add_recipient(group="default", recipient_did=did)
      except tn.KeystoreConflictError as exc:
          if tn.is_keystore_diverged(exc):
              # safe to re-read state + retry
              ...
          else:
              raise

- **`--seal-for-recipient` flag on `tn bundle` and `tn add_recipient`.**
  Wraps the bundle body under a per-export key only the named recipient
  DID can unwrap. Previously the seal-for-recipient feature lived only
  in the Python `tn.export(...)` call; operators following `tn --help`
  could not discover it.

### Notes

- TS parity: TS gets the read default flip in tandem (already shipped
  in 0.4.1-alpha.3). The stream-singleton fix, exception export, and
  CLI seal flag are Python-only this round; TS callers already use
  `Tn.init({stream: ...})` returning a focused handle by convention,
  so the per-stream emit issue does not surface in TS.

- `TN_NO_STDOUT=1` env-var suppression was re-verified across fresh
  ceremonies, existing ceremonies, and admin-event emit paths. Works
  as documented in 0.4.2a1; the D1 white-glove finding was not
  reproducible in this build.

- JWE CLI surface (offer / enrolment handshake) is intentionally
  deferred to a later release. Today's JWE recipient onboarding still
  flows through the Python `tn.offer(...)` + `tn.admin.add_recipient(
  ..., public_key=...)` path.

## [0.4.1a3] - 2026-05-17

Two papercuts removed from the day-one user journey.

Released in Python as `tn-protocol 0.4.1a3` and in TS as
`@tnproto/sdk 0.4.1-alpha.3`.

### Changed (Python and TS)

- **`tn.read()` now defaults to "all runs on disk".** A fresh process
  calling `tn.read()` returns every entry on disk, which is what most
  callers want on first contact. The old behavior is still reachable
  by passing `all_runs=False` (Python) / `{allRuns: false}` (TS).
  Same flip applied to the MCP `ReadInput` schema.

### Changed (Python)

- **`tn.absorb()` auto-creates a ceremony when none exists.** Calling
  `tn.absorb(<bundle>)` as the very first verb no longer raises
  `RuntimeError` for kit_bundle and similar non-bootstrap kinds. The
  standard autoinit banner fires (the same one `tn.info(...)` triggers
  today) so the caller sees that a fresh identity was minted in the
  cwd. Set `TN_AUTOINIT_QUIET=1` to silence.

### Notes on TS parity

- The TS SDK keeps its existing absorb split: `Tn.absorb(source)` (the
  static method) auto-bootstraps for `project_seed` / `identity_seed`
  kinds, while non-bootstrap kinds (kit_bundle, admin_log_snapshot)
  flow through `await Tn.init(yamlPath)` then `tn.pkg.absorb(source)`.
  Aligning TS absorb with the Python "any kind autoinits" model is a
  follow-up.

- Both Python and TS changes are alpha-cycle adjustments to defaults.
  Behavior is flipped at the public surface; private internal helpers
  keep their existing defaults.

## [0.4.0a4] - 2026-05-09

Python-only packaging patch.

- **`tn` console script now installs.** The 0.4.0a3 wheel declared
  `tn-mcp-server` under `[project.scripts]` but not `tn` itself, so
  `pip install tn-protocol` left users running `python -m tn.cli ...`
  even though the cli.py docstring promised `tn [verb] ...`. Fixed:
  `tn = "tn.cli:main"` is now in pyproject.toml. `tn rotate`,
  `tn init`, `tn bundle`, `tn absorb`, `tn read`, `tn wallet ...`
  all work as advertised after install. No source-code changes —
  pure packaging fix.

No TS changes; `@tnproto/sdk` stays at `0.4.0-alpha.3`.

## [0.4.0a3] - 2026-05-09

CI-shaped CLI surface: rotation as a deploy primitive + non-TTY safe init.
Same release in Python (`tn-protocol` 0.4.0a3) and TS (`@tnproto/sdk`
0.4.0-alpha.3).

### Rotation as the deploy primitive

- **`tn rotate [<group>] [--groups a,b,c] [--out path]`** (Python CLI)
  and **`tn-js admin rotate ...`** (TS CLI). No-arg form rotates every
  non-internal group in the ceremony — the deploy-shaped default. Per-
  group it bumps `index_epoch`, regenerates the publisher state, renames
  the prior key material to `.revoked.<UTC_TS>`, and emits
  `tn.rotation.completed` to the admin log.
- **Per-recipient `.tnpkg` artifacts**: after rotation the verb mints a
  fresh `kit_bundle` for every surviving recipient and writes one
  `.tnpkg` per recipient under `./rotated_<UTC_TS>/` by default
  (override via `--out <dir>` or `--out <single>.tnpkg`). CI uploads
  the directory as a build artifact and the publisher hands the
  individual files to recipients out-of-band.
- **Vault path is free**: `tn.admin.rotate` already calls
  `_maybe_autosync(cfg)` post-rotation; vault-linked ceremonies push
  the new state automatically and the vault drives recipient
  notification from there. Vault-less ceremonies use the artifact
  channel.
- **TS BTN rotation now actually works**: pre-0.4.0a3 the TS
  `tn.admin.rotate(group)` threw `"btn cipher does not support in-band
  rotation"`. It now mirrors Python end-to-end (mint a fresh
  `BtnPublisher`, swap on disk, bump epoch, attest). JWE rotation
  remains Python-only.

### Non-TTY safe `tn init`

- `tn init <project>` no longer requires a TTY for first-time
  provisioning. In CI / containers / scripts it auto-skips the
  "Press Enter" prompt, suppresses the mnemonic banner (would have
  leaked into CI logs), and persists the mnemonic into
  `identity.json`. The operator treats `identity.json` as the
  secret-handling boundary and can recover the mnemonic later via
  `tn wallet export-mnemonic`.

### Documentation

- README and CLI top-of-file docstrings updated to cover the new
  verbs and CI-shaped behavior.
- `docs/sdk-parity.md` gains a CLI parity table.

## [0.4.0a2] - 2026-05-08

Cross-language dirt-easy lifecycle. Same release in Python (`tn-protocol`
0.4.0a2) and TS (`@tnproto/sdk` 0.4.0-alpha.2).

### Lifecycle UX

- **`tn.absorb('bundle.tnpkg')` now bootstraps a runtime when nothing is
  bound yet.** For self-contained bundle kinds (`project_seed`,
  `identity_seed`) the absorb writes the layout to disk *and* binds the
  runtime to the freshly-absorbed `./tn.yaml`. The user can immediately
  call `tn.info(...)` / `tn.read()` without a separate `tn.init()` step.
- **`tn.init()` no-args discovery chain expanded** to walk
  `$TN_YAML` → `./tn.yaml` → `./.tn/default/tn.yaml` → `~/.tn/tn.yaml`,
  then mint a fresh `.tn/default/` ceremony if nothing is found.
- **Top-level `tn.absorb` / `tn.export` aliases** (Python) and
  **`Tn.absorb(source)` static factory** (TS) returning a usable Tn
  bound to the absorbed dir.

### Cross-language interop

- **`project_seed` and `identity_seed` absorb** is wired up in both
  languages with shared manifest-kind handlers. Closes the gap where the
  deployed dashboard at `https://vault.tn-proto.org` could mint these
  bundles but neither SDK could install them.

### Type surface

- `tn.absorb(source)` narrows to `AbsorbReceipt`; legacy
  `tn.absorb(cfg, source)` narrows to `AbsorbResult` (Python @overload).
- `tn.read()` narrows to `Iterator[Entry]`; `tn.read(raw=True)` narrows
  to `Iterator[dict[str, Any]]` (Python @overload).
- TS: `Tn.absorb()` returns `Promise<Tn>` instead of a receipt-or-Tn
  union.

### Cleanup

- Drop dead `_absorb_offer` / `_absorb_enrolment` / `_extract_peer_did`
  legacy compat helpers (no in-tree importers).
- Correct `_emit_via` / `_emit_with_splice` annotation from
  `-> dict[str, Any]` to `-> None` (stale since the dispatch refactor).
- Widen `_open_zip` / `_read_manifest` `source:` to also accept `str`.

## [0.3.0a3] - 2026-05-05

Dispatch refactor + stdout cosmetic cleanup. Requires `tn-core` 0.2.0a2.

### Python SDK (tn-protocol)

- `DispatchRuntime` no longer disables the Rust path when custom Python
  handlers are registered. Btn ceremonies stay on Rust; user-registered
  handlers (kafka, S3, vault.sync, fs.drop, etc.) are fanned out
  post-Rust-emit. Closes the long-standing limitation where mixing
  custom handlers with btn admin verbs (`add_recipient_btn` etc.)
  raised `NotImplementedError`.
- The post-emit fan-out skips handlers whose write target Rust has
  already covered: `StdoutHandler`-class instances (Rust auto-registers
  its native one) and file handlers whose `path` resolves to Rust's
  `cfg.logs.path` (Rust's internal log_writer wrote it). The skip rule
  is path-equality + class-match, replacing the imprecise
  `_tn_default` flag that incorrectly swallowed multi-file-handler
  fan-outs.
- `StdoutHandler` default format is now a terse single line:
  `HH:MM:SS.mmm LEVEL  seq=N  event_type`. No DID, no hashes, no
  signatures, no ciphertext on a developer's terminal. Opt back into
  the canonical NDJSON envelope via `TN_STDOUT_FORMAT=json` env var or
  `format: json` on the yaml stdout entry. Same setting honored by the
  Rust-side `StdoutHandler`.

### Bug fixes

- `examples/ex06_multi_handler.py`: parse-replace-dump yaml instead of
  appending a duplicate top-level `handlers:` key (latent bug — the
  prior append-string pattern produced malformed yaml that strict
  parsers reject; only worked before because the user-handler gate
  forced the whole dispatch to Python's lenient yaml loader).

[0.3.0a3]: https://github.com/cyaxios/tn-proto/releases/tag/v0.3.0a3

## [0.2.0a2] - 2026-05-01

Loosened sub-package version constraints for rapid alpha iteration.
Functionally identical to 0.2.0a1.

### Changed

- `tn-btn` / `tn-core` deps now `>=0.2.0a1,<0.3` (was `==0.2.0a1`).
  Patches to either wheel flow into tn-protocol installs without
  forcing a coordinated bump. Tighten back to `==` for stable.

[0.2.0a2]: https://github.com/cyaxios/tn-proto/releases/tag/v0.2.0a2

## [0.2.0a1] - 2026-05-01

First public alpha. Initial release of tn-proto under the `cyaxios`
namespace.

### Python SDK

- Cipher-agnostic admin verbs: `tn.admin.add_recipient`,
  `tn.admin.revoke_recipient`, `tn.admin.rotate`. Each branches
  internally on the group's cipher and returns a structured dataclass
  (`AddRecipientResult`, `RevokeRecipientResult`, `RotateGroupResult`).
- New subpackages: `tn.admin`, `tn.pkg`, `tn.vault`, `tn.admin.cache`.
- Protocol primitives in `canonical`, `chain`, `indexing`, `signing`,
  `sealing`, `tnpkg`, `contacts`, `filters`, `identity`, `classifier`,
  `reconcile`, `wallet_restore*` are now underscore-prefixed and not
  part of the SemVer-public set.
- The 18 flat aliases (`tn.admin_*`, `tn.cached_*`, `tn.vault_*`,
  `tn.export`, `tn.absorb`, `tn.bundle_for_recipient`, top-level
  `add_recipient` / `revoke_recipient` / `rotate` / `recipients`) are
  removed without deprecation aliases.
- `tn/__init__.py` reduced from 1844 to 845 LOC; private impls live in
  `tn/_session_impl.py`, `tn/_pkg_impl.py`, `tn/_vault_impl.py`,
  `tn/_read_impl.py`.

[0.2.0a1]: https://github.com/cyaxios/tn-proto/releases/tag/v0.2.0a1
