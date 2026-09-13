# SDK read-path verification consistency (TypeScript + C#)

- **Status:** design snapshot, 2026-07-16
- **Date:** 2026-07-16
- **Scope:** align verification behavior while preserving the SDK defaults
  recorded in this design snapshot — see §2.

## 1. Context & problem

TN records carry a top-level Ed25519 `signature` over `row_hash`, verified
against the public key embedded in `device_identity`. `row_hash` binds the
record's content. Verified attribution rests on two independent checks: (a) the
signature verifies against the record's DID and the `row_hash` recomputes from
content, and (b) that DID is an allowlisted writer (own DID + `trust.writers` +
verified publishers).

The SDKs are inconsistent along **two independent axes**:

1. **The verification machinery diverges.** Even when a caller *explicitly asks*
   to verify, the SDKs do not agree:
   - **TypeScript (Node)** runs a parallel pure-TS reader
     (`node_runtime.ts::_decodeReadEnvelope`) that computes `signature`/`row_hash`
     into advisory flags but has **no trusted-writer allowlist at all** — even
     `verify:true` accepts a self-signed row from any DID
     ([tn.ts:1629-1630](../../../ts-sdk/src/tn.ts) `_finishReadRow` has no
     writer-trust term; `verified_publishers` is consulted only in enrollment).
   - **C#** is a thin FFI wrapper whose native read enforces the full policy when
     asked, but C# does not surface read rejections as a typed error the way it
     does for `unseal`.
   - **Python / Rust / WASM** enforce the full policy (signature, row_hash,
     chain, allowlist) — the reference behavior.

2. **The no-arg default diverges.** TS/C# default to not-enforcing; Python/Rust
   default to fail-closed (`verify="auto"` → raise).

This spec addresses **axis 1 only**. It preserves each SDK's default behavior;
changing those defaults is **out of scope** (§2).

## 2. Goals / non-goals

**Goal: make the verification *machinery* identical across all SDKs, so that for
any given verify setting, every SDK reaches the same accept/reject decision —
without changing any SDK's current default.**

Concretely:
- One verification implementation (the Rust core), reached by every SDK.
- TS's verified path gains the writer-trust allowlist it lacks, so `verify:true`
  in TS means exactly what it means in Python/Rust.
- C# read rejections surface as a typed exception with reasons.
- A single validity metadata shape across SDKs.
- A cross-SDK conformance harness that pins identical per-setting behavior.

**Explicit non-goals.**
- **No default is changed.** Each SDK keeps the no-arg default recorded in this
  design snapshot (§6).
- The `telemetry` / `transaction` / `audit` / `governed` profile taxonomy — a
  separate design track.
- `seal`/`unseal` trust semantics (deliberately trust-free — §7).
- Key-material-at-rest hardening.
- No wire-format or sealed-object schema change; no Python/Rust/browser reader
  change beyond what a shared conformance harness requires.

## 3. Principle: one verification implementation

Every SDK's verified read routes through `tn_core`'s policy engine
(`Runtime::read_with_policy_options` → `default_read_policy`): signature-over-
`row_hash`, `row_hash` recompute, chain, and the trusted-writer allowlist,
verify-before-decrypt. No SDK re-implements the policy.

- **C#** already routes through it (FFI → `Tn::read`).
- **TS-node** will route through it via the wasm companion it already attaches.
  The parallel pure-TS verification is deleted.
- **Browser / Python / Rust** already route through it (reference).

## 4. C# changes

C# `ReadAsync` → `NativeMethods.RuntimeRead` → FFI `tn_runtime_read` →
`Tn::read(ReadOptions { verify })` ([lib.rs:1198](../../../crypto/tn-core-ffi/src/lib.rs)).
At `verify=1` the native path already runs the full policy incl. the allowlist
and raises on the first bad row. So:

1. Surface the native read-rejection as a typed `TnVerifyException` carrying the
   reason list — extend the existing `VerifyError:` → `TnVerifyException`
   mapping ([NativeBridge.cs:208-250](../../../csharp-sdk/src/TnProto/Native/NativeBridge.cs))
   from `unseal` to cover read rejections. Note: `tn_runtime_read` currently sets
   a plain `err.to_string()` with no structured prefix; the FFI read error
   surface likely needs to emit recognizable, reason-carrying errors so C# maps
   them to a typed exception rather than a generic `TnException`.
2. **Default unchanged** (`ReadOptions.Verify` stays as-is). This means
   `Verify=true` in C# now behaves identically to `verify:true` elsewhere; the
   default is untouched.
3. **Deferred:** `skip` mode — the FFI read is bool-only; `skip`/`on_skip`
   remain a follow-up.

## 5. TypeScript changes

### 5.1 New wasm read binding

The wasm reads are argument-less today (`read()`, `readAllRuns()`,
`readWithVerify()`, `secureRead(onInvalid)`) — they use the runtime default
policy (which includes the allowlist) but accept no per-call overrides. The Rust
core already has `Runtime::read_with_policy_options(ReadPolicyOptions)`; it is
not exposed to JS. Add one binding:

```
WasmRuntime.readWithPolicy(optionsJson) -> { entries, report }
```

mapping a JSON options bag onto `ReadPolicyOptions` (verify mode,
`require_signature`, `allow_unauthenticated`, `trusted_writers`,
`allow_unknown_writers`, `all_runs`, `as_recipient`/`group`) and returning flat
entries plus the read report (`scanned`/`yielded`/`skipped`/`cursor`) for
`.stats`. Binding surface + option marshaling only — no new policy logic.

### 5.2 Rewire node's verified read

`node_runtime.ts` already attaches an fs-backed `WasmRuntime`
([node_runtime.ts:2293](../../../ts-sdk/src/runtime/node_runtime.ts)) and routes
`emit` through it. Verified reads follow suit:

- **Delete** the pure-TS verify/decrypt loop (`_decodeReadEnvelope`). The parallel
  policy implementation — and its missing-allowlist gap — goes away entirely.
- **All** reads route through the wasm companion, so the pure-TS reader can be
  fully removed:
  - the enforcing setting → `readWithPolicy(...)` / `secureRead(...)` (raises /
    drops), where `verify:true` in TS now enforces the writer-trust allowlist —
    the gap is closed by construction;
  - the non-enforcing default → `readWithVerify()` (attaches honest validity and
    does **not** raise), preserving today's non-enforcing default behavior.
- **Keep in TS only non-security post-processing:** `event_type`/`level`
  filtering, the `where` predicate, the `raw:true` output shape, the `on_skip`
  callback, and `.stats` accounting (from the report).
- **`watch`:** node keeps its file-tail loop; each new batch goes through the same
  wasm read.
- **Default unchanged (behavior).** The default stays non-enforcing — it does not
  raise. This pass changes what happens *when verification runs*, not whether it
  runs by default. One additive note: routing the default through the core makes
  its advisory `_valid` shape complete (it will now also carry the writer-trust
  result that pure-TS never computed) — richer metadata, still non-enforcing
  (see §9).

### 5.3 `as_recipient` caution

`as_recipient` reads should use the same policy path, but the SDKs currently
**diverge** — Python enforces the policy on `tn.read(as_recipient=)`, while the
Rust core's low-level `read_as_recipient` is advisory. The target and whether
core work is needed is an open question (§9); the priority here is the ordinary
log read. (This is the *read* verb; distinct from the trust-free `unseal` verb
that shares the kwarg name — §7.)

## 6. Defaults are explicitly deferred

No SDK default changes in this pass. After it:
- Any explicit verify setting behaves identically across all four SDKs.
- Each SDK's *no-arg default* is exactly what it is today (TS/C# permissive,
  Python/Rust fail-closed). That remaining inconsistency is intentional and
  isolated to a single decision.

A future change to SDK defaults would be checked against the conformance
harness. An alternative outside this design is **compute-and-attach honest
validity but do not raise**, with a later choice of telemetry-skip or
transaction-raise. This option is recorded but not adopted here.

## 7. `seal`/`unseal` boundary and the chain invariant (unchanged, guarded)

`seal`/`unseal` is a confidentiality on-ramp/off-ramp, **not** a trust boundary,
and is not modified by this work. Recorded so the read rewiring does not disturb
it:

- **No trust in unseal.** Unseal keeps its non-trust integrity gate and consults
  no allowlist and no expected-signer. Attribution is *available* (the object is
  always signed) for out-of-band verification; that is data availability, not a
  decision unseal makes.
- **No chain in unseal — ever.** The unseal integrity gate is **signature +
  row_hash only**. A sealed object has no chain: `prev_hash` is `""` and
  `sequence` is `0`, excluded from the `row_hash` preimage. Verified across all
  four SDKs: `SealedValid {signature, row_hash}` / `verify_sealed`
  ([sealed_object.rs:76-83,222-276](../../../crypto/tn-core/src/sealed_object.rs));
  `RowHashInput` has no `sequence` field
  ([chain.rs:30-47](../../../crypto/tn-core/src/chain.rs)); Python `valid =
  {signature, row_hash}` ([seal.py:310](../../../python/tn/seal.py)); TS
  `_verifySealed` returns `{signature, row_hash}`, no `core/chain.ts` import
  ([core/sealed_object.ts:568-609](../../../ts-sdk/src/core/sealed_object.ts));
  C# `UnsealValidity {Signature, RowHash}`
  ([UnsealResult.cs:9-32](../../../csharp-sdk/src/TnProto/UnsealResult.cs)).
- **The seam to preserve.** The invariant holds because sealed verification is a
  separate function from the chain-enforcing read policy engine (`ChainInvalid`,
  under `runtime/read/`). The read rewiring in §5 must stay confined to the read
  verb:
  - Do **not** route `unseal` through `read_with_policy_options` / `secureRead` /
    the new `readWithPolicy` binding.
  - Keep sealed verify on `verify_sealed` / `_verifySealed`.
  - Do **not** dedupe `unseal`'s `as_recipient` candidate-loaders with the read
    path's ([seal.py:409](../../../python/tn/seal.py) vs
    [reader.py:590,764](../../../python/tn/reader.py)) — that duplication keeps
    `verify_chain_link` out of the sealed path.

## 8. Testing — the anti-drift guarantee

A shared forged-envelope fixture set, run identically against Python, Rust,
TS-node, and C#, asserting the same accept/reject decision **for the same
explicit setting** (not "the default raises"):

Under an explicit verify/enforce setting:
1. attacker-DID self-signed (valid sig + row_hash, untrusted writer) → rejected
   `WriterUntrusted`.
2. victim-DID + wrong key → rejected `SignatureInvalid`.
3. tampered header (`event_type`/`level`/`timestamp`) → rejected `RowHashInvalid`.
4. unsigned row on a signed profile → rejected `SignatureRequired`.
5. genuine own-DID row → accepted, decrypted.
6. plaintext never returned for 1–4 under the enforcing setting.

Under an explicit non-enforcing setting: 1–5 all returned (with the audit event
where applicable).

Plus:
- Direct unit test of the `readWithPolicy` binding (option marshaling,
  `trusted_writers` override, raise/skip, report accounting).
- A `watch` test (tampered row appended mid-tail).
- An invariant test: `unseal` of a chain-mangled / `sequence`-mangled sealed
  object still succeeds and never raises on chain (guards §7).

The harness is what makes "consistent" durable: it pins per-setting behavior so
the machinery cannot silently drift again, independent of what any default is.

## 9. Open questions / risks

- **wasm read-surface completeness:** confirm `readWithPolicy` can express every
  option the TS `read`/`watch` API exposes (verify modes, `trustedWriters`,
  `allowUnknownWriters`, `require_signature`, `allow_unauthenticated`,
  `as_recipient`, cursor). Any gap becomes part of the binding work.
- **`on_skip` fidelity:** the report must carry per-skipped-row reasons for the
  TS `on_skip` callback; confirm `ReadReport` exposes this or extend it.
- **C# FFI error surface:** confirm `tn_runtime_read` can emit structured,
  reason-carrying rejections for the typed C# exception.
- **`as_recipient` enforcement divergence:** Python enforces the policy; the Rust
  core's `read_as_recipient` is advisory. Decide the parity target and whether
  this pass addresses it or defers it.
- **Default advisory-shape change (additive):** routing the non-enforcing default
  through the core enriches its `_valid` metadata to include the writer-trust
  result TS never computed. This is additive metadata with no enforcement change;
  confirm no consumer keys off the *absence* of that field.
- **SDK defaults (out of scope):** this design preserves each SDK's no-arg
  default. Any future change must be checked against the shared conformance
  harness.
