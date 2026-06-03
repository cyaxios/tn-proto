# SDK Unification Plan (Direction A: finish the core unification)

> Decision: the Rust core owns each high-level verb; PyO3 and wasm expose
> it identically; the SDKs become thin pass-throughs. Python is the
> primary consumer, both SDKs stay first-class. The goal is one
> implementation and less surface area, so parity stops being something we
> maintain by hand.

## Why (the diagnosis this work is fixing)

The core already owns the crypto and wire format (tn-btn, manifests,
envelopes, the admin `reduce` step). What it does NOT own are the
high-level verbs, which are re-orchestrated independently in Python and in
TypeScript on top of the core. That is three layers kept in lockstep by
hand, and it is the parity tax. The reason the SDKs cannot just call the
core today is that the core's high-level layer is incomplete or
inconsistent across the two bindings (enumerated below). Completing it,
verb by verb, removes the duplicate orchestration and makes parity
structural.

Evidence (from the 2026-06-03 audit + rewire attempt):
- WASM `adminState` / `recipients` read the main log only, not the
  dedicated admin PEL where recipient events live. So both SDKs reimplement
  the dual-log replay.
- The monolithic WASM `bundle_for_recipient` / `admin_add_agent_runtime`
  emit a different bundle shape than the contract needs. So both SDKs loop
  per-kit and assemble in their own layer.
- `export` / `absorb` are PyO3-only (absent from wasm). So TS reimplements
  packing/signing via Rust helpers.
- Routing `addRecipient` through wasm broke reconcile-during-init
  (`init_idempotence` slice2): the core write verb is not yet safe to call
  from the init/reconcile sequence. The fix belongs in the core, not a
  best-effort try/catch in the SDK.

## Method: vertical slices, one verb at a time

For each verb, take it all the way down before starting the next:

0. **Golden fixture.** Capture Python's canonical output for the verb
   (kit bytes, on-log events, returned state) as a cross-impl fixture in
   `regression/` or `tools/`. This is the parity bar. Python is primary,
   so Python's output is the contract.
1. **Complete the core verb** in `crypto/tn-core` to hit that bar (e.g.
   read both logs; emit the canonical bundle shape; be callable during
   init).
2. **Expose identically** in `crypto/tn-core-py` (PyO3) and
   `crypto/tn-wasm` (wasm), same method name + shape.
3. **Thin both SDKs**: replace the Python and TS orchestration with a call
   to the core verb. Delete the duplicated reducer/loop/packer.
4. **Golden test as the gate**: same seed/input -> byte-identical output
   across Python and TS, run in CI.

Each slice must be green (full ts-sdk + python + cargo suites) before the
next. Surface area drops with every slice.

## Backlog (rough order: safest first)

| # | Verb(s) | Core gap to close | Risk |
|---|---------|-------------------|------|
| 1 | `adminState` / `recipients` | core must replay main log + admin PEL across runs, with the ceremony-from-config fallback and active-first / leaf-ascending sort, matching Python's `tn_core.admin.reduce` + post-processing | low (read-only) |
| 2 | `addRecipient` / `revokeRecipient` / `revokedCount` | core write verb must be safe to call during init/reconcile (no re-entrant attach, deterministic outbox kit path); SDK cache invalidation contract documented | medium (write + init ordering) |
| 3 | `bundleForRecipient` / `agents.addRuntime` | core verb must emit the canonical N+1 bundle (groups + tn.agents, dedup) the contract + tests expect, OR the SDKs keep looping the core `addRecipient` (decide per fixture) | medium (bundle shape) |
| 4 | `export` / `absorb` | add to the wasm binding (PyO3 already has them); byte-identical artifacts | medium (new wasm surface) |
| 5 | `read` | dual-log merge + `asRecipient` foreign-keystore + templated-glob expansion in the core, so TS `read` collapses to a call | high (largest TS orchestration) |
| 6 | `vault_link` / `vault_unlink` | single core path both SDKs call (today both emit; the dedicated binding is unused) | low |

Out of scope for unification (no Rust binding; SDK-layer by design):
`rotate`, `ensure_group`. Known Python-only TS gaps tracked separately:
`wallet`, `vault_client`, `classifier`, `is_keystore_diverged`.

## Pilot slice (1): `adminState` / `recipients`

The clearest "core does not own it" case, and read-only so the blast
radius is small.

- **0 fixture**: a btn ceremony with a dedicated `protocol_events_location`
  admin PEL + a few `tn.recipient.added` / `revoked` events; capture
  Python `tn.admin.state()` / `recipients()` output as the golden JSON.
- **1 core**: make `tn_core::Runtime::admin_state` / `recipients` (and the
  reduce path) read BOTH the configured main log and the admin PEL tree
  across runs, apply the ceremony-from-config fallback + the canonical
  sort. Today they read `read_from(self.log_path)` only.
- **2 bindings**: confirm `adminState` / `recipients` on both PyO3 and
  wasm return the same shape (snake_case keys mapped to each SDK's type).
- **3 thin**: Python `admin.state` / `recipients` call the PyO3 method
  (drop the Python `_AdminStateBuilder` accumulation); TS
  `NodeRuntime.adminState` / `recipients` call wasm (drop the TS
  `AdminStateReducer`), keeping only the type mapping.
- **4 gate**: a cross-impl golden test asserting Python and TS
  `admin.state()` are byte-identical for the fixture; wire it into CI and
  into the upgraded `tools/check_parity.py` route matrix (status flips from
  "output-parity, independent reducers" to "Rust-backed (both)").

When this slice is green end to end, the pattern is proven; repeat for #2-6.

## Parity gate evolution

`tools/check_parity.py` already emits a verb-centric route matrix across
five surfaces (+ browser) with throw-stub detection. As each slice lands,
its row moves to "Rust-backed (both)" and the golden test enforces
byte-identity. The end state: a verb cannot regress to per-SDK
orchestration without failing CI.

## Done criteria

- Every backlog verb is Rust-backed-both or a documented exception.
- The Python and TS orchestration layers for those verbs are deleted.
- Golden cross-impl tests gate each verb in CI.
- `docs/sdk-parity.md` route matrix shows no "output-parity via independent
  reducers" rows remaining (those become "Rust-backed (both)").
