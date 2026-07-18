# Foundation Task 1 Post-Commit Review Findings

Commit `79b8872` is not yet an accepted dependency. Fix every item test-first in
a follow-up commit, then regenerate the review package and re-review.

## Important

1. Real Rust emission fails because `Runtime::emit_inner` injects `run_id`
   before strict catalog validation. Add a real-runtime regression in the
   baseline-clean `crypto/tn-core/tests/runtime_emit.rs`. Preserve strict caller
   payload validation while allowing established runtime/envelope metadata.
   Prove the event can be emitted, serialized, and replay-validated.

2. Rust catalog/reducer validation accepts unknown operation strings, unknown
   relaxation strings, and an empty relaxation array. Route the five payload
   fields through the typed `UnsafeOperationNotice` contract (or an equally
   single-sourced strict validator), reject all three cases, and keep sorted,
   de-duplicated serialization. Add focused catalog/reducer/notice tests.

3. `challenge_unknown_field` and `challenge_unsupported_version` mutate signed
   content without re-signing, so they also have invalid signatures. Re-sign
   every non-`signature_invalid` statement vector after mutation and make the
   generator contract test verify valid Ed25519 signatures for all such cases.

## Minor

4. Add a public `verify=True` read-policy vector resolving to `raise`, plus a
   parameter-error vector proving the internal-only string `"disabled"` is
   rejected. Preserve `verify=False` as the public input for internal disabled
   mode.

## Scope

- Existing Foundation-owned paths remain approved.
- `crypto/tn-core/tests/runtime_emit.rs` is baseline-clean and explicitly added
  to Foundation ownership for the real emission regression.
- Do not touch unrelated dirty files.
