# Read-verification consistency — progress (overnight 2026-07-16)

Branch: `sdk-read-verification-consistency` (off `btn-python-surface`).
Spec: `2026-07-16-sdk-read-verification-consistency-design.md`.

## HEADLINE DISCOVERY — the C# read-verify "consistency" IS the deferred posture decision

Working the C# slice surfaced that "make C# reads consistent" is **not** a
mechanical fix. It collides head-on with the telemetry-vs-transaction posture
that was explicitly deferred.

Evidence, in code:
- **C# SDK design = attach-flags (telemetry/forensic).** `ReadOptions.Verify`
  is documented *"Include verification metadata"*
  (`csharp-sdk/src/TnProto/ReadOptions.cs:14`). `EmitReadTests` expects
  `ReadAsync(Verify=true)` to **return** rows with a populated `Validity` block
  — valid rows `IsValid=true` (passes), tampered rows `IsValid=false`
  (`EmitReadTests.cs:201-208, 234-238`). i.e. attach flags, never raise.
- **Core/FFI = raise (transaction).** `tn_runtime_read(verify=1)` maps to
  `Tn::read(verify:true)` → `VerifyMode::Auto` → `Raise`, which raises on the
  first rejected record. This was true at base commit `95d40f1` (verified),
  unchanged by this branch.
- **Result:** `EmitReadTests.ReadAsyncVerifyFlagsTamperedRows` is a
  **pre-existing failure** (red at base): the SDK expects attach-flags, the
  core raises. Full C# suite is 321 pass / 1 fail, that one test, both at base
  and now.

**This is the telemetry vs transaction/audit decision the user deferred.** It
cannot be settled here.

### The decision, and the (small) implementation each way

The C# default is `Verify=false` and is **not** in question. The question is
only what `Verify=true` should do:

- **Telemetry / forensic (matches the C# SDK's documented design + the
  telemetry-first lean):** `tn_runtime_read(verify=1)` should call
  `read_with_verify()` (attach the `_valid` block, no raise). One-line FFI
  change. Fixes `ReadAsyncVerifyFlagsTamperedRows`. Reads never raise; the
  caller inspects `entry.Validity`.
- **Transaction / audit:** keep `tn_runtime_read(verify=1)` raising, and update
  `EmitReadTests.ReadAsyncVerifyFlagsTamperedRows` to expect a
  `TnVerifyException` (the typed error this branch already produces).

I did **not** pick a side. A C# test that presumed the raise side was written
and then reverted (`46e4bc0`) so nothing pre-decides it.

## What landed (committed, verified, posture-agnostic)

| commit | what | verification |
| --- | --- | --- |
| `12ecb1c` | design spec | — |
| `338090b` | typed read-policy rejection in core + FFI (+ rust-sdk mapping) | `cargo test -p tn-core -p tn-core-ffi -p tn-proto` green; `cargo check --workspace` green |
| `3115ba4` | C# managed read-verify test | (superseded) |
| `46e4bc0` | revert of `3115ba4` — it pre-decided the deferred posture | — |

`338090b` is kept because it only sharpens the **existing** raise path: a
rejected `secure_read(OnInvalid::Raise)` / `Tn::read(verify:true)` now raises
`Error::ReadRejected` carrying the stable snake-case reasons
(`writer_untrusted`, `signature_invalid`, `row_hash_invalid`,
`signature_required`, `chain_invalid`), the rust-sdk promotes it to
`Error::Verify`, and the FFI renders it on the shared `VerifyError:` channel
(so IF a read raises, it raises typed — same as unseal). It changes **no
default** and does not decide whether reads raise. `tn-core` tests that assert
the rejection error were updated to the new variant and prove `writer_untrusted`
end-to-end.

Files (all outside the in-flight WIP set):
- `crypto/tn-core/src/error.rs`, `crypto/tn-core/src/runtime/read.rs`
- `crypto/tn-core/tests/{secure_read,secure_default_read}.rs`
- `rust-sdk/src/error.rs`
- `crypto/tn-core-ffi/src/lib.rs` (+ `ffi_read_rejection_verifyerror_prefix` test)
- `csharp-sdk/src/TnProto/Native/NativeBridge.cs` (shared `MapVerbError`)

## Consistency status by SDK

- **Rust core / FFI / C#** — share one engine; can't diverge on the *decision*
  once the posture is set. The raise path now carries typed reasons.
- **Browser / WASM / Python** — already route through the core / already
  fail-closed (reference). Unaffected.
- **TypeScript (Node)** — **DEFERRED.** Pure-TS reader has no writer-trust
  allowlist, and `node_runtime.ts` is under active edit by the enrollment/HIBE
  WIP (uncommitted). Rewiring now would collide. Also blocked on the same
  posture decision above.

## Nothing here changes a default

Per the spec's non-goal. `Verify`/`verify` defaults are untouched. The posture
decision (what `verify=true` *does*, and the global default) is still open.

## Next steps
1. **User decides the posture** (telemetry attach-flags vs transaction raise).
   The C# fix is one line either way (above).
2. TS-node rewire, once WIP contention on `node_runtime.ts` clears and the
   posture is set: route reads through the wasm companion (`read()` /
   `secureRead()` already enforce the allowlist), delete the pure-TS reader.

## Guardrails re-confirmed
- `seal`/`unseal` never verifies chain and can raise no chain error (all four
  SDKs). Do not route `unseal` through the read policy engine; do not dedupe the
  `as_recipient` candidate-loaders across the read/seal boundary.
