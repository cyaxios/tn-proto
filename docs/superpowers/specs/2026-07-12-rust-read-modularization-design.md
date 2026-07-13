# Rust Read Modularization Design

**Status:** Approved in conversation

**Date:** 2026-07-12

**Scope:** Native Rust read path in `tn-core` and `tn-proto`

## Purpose

Land the secure-default Rust read slice without preserving the current
2,153-line `runtime/read.rs` as a monolith. The refactor keeps `Tn::read` as the
main API, preserves its secure defaults and tuning parameters, and makes the
read pipeline accept cipher implementations through a narrow internal boundary.

This design refines Rust Workstream B from the 2026-07-11 trusted-enrollment and
secure-read design. It does not broaden this slice into JWE cryptography,
enrollment, HIBE authority management, rotation, or revocation.

## Production-code constraints

These limits apply to production Rust code in the read slice. Tests are not
subject to them.

1. Every read-focused production source file contains at most 609 lines.
2. Production functions and methods target at most 50 lines.
3. A longer function requires a named, documented structural exemption.
4. No production function or method may exceed 200 lines.
5. The initial landing targets zero exemptions.
6. Existing unrelated production files are not pulled into this refactor, but
   every production function changed by this slice follows these limits.

A source-shape regression test enforces these rules for the read modules. Any
future exemption must name the file and symbol and include its reason in the
test; an anonymous numeric allowlist is not acceptable.

## Current problem

`crypto/tn-core/src/runtime/read.rs` currently owns all of these concerns:

- trust-policy resolution and decisions;
- source normalization, snapshots, bounded scanning, and cursors;
- envelope parsing, row-hash recomputation, chain checks, and signatures;
- group decryption and decryption sentinels;
- flat and secure result projection; and
- foreign-reader material discovery and BTN-specific dispatch.

It also contains two similar decryption loops and embeds cipher-specific
foreign-read decisions in the main read implementation. Splitting the file
without changing those boundaries would preserve the coupling and duplication.

## Public API

The public API remains stable:

- `Tn::read(ReadOptions) -> Result<Vec<Entry>>` remains the main surface.
- `ReadOptions::default()` remains secure and fail-closed.
- `Tn::read_with_options` continues to expose accounting and a lossless cursor.
- watch implementations consume the same `ReadOptions` and `ReadCursorV1`.
- explicit weakening remains possible and produces one warning plus one
  best-effort administrative audit event.

The SDK implementation moves its read-specific types and `impl Tn` methods out
of the general `tn.rs` lifecycle module into a private child read module. Public
exports remain at their existing paths.

## Core module structure

The core `runtime::read` module becomes a directory with focused files:

- `read/mod.rs` — public `Runtime` read methods and short orchestration only;
- `read/policy.rs` — `ReadTrustPolicy` resolution and per-record decisions;
- `read/source.rs` — source IDs, path normalization, snapshots, bounded lines,
  byte cursors, and scan progress;
- `read/record.rs` — envelope parsing, group-input extraction, row hashes,
  chains, signatures, and prepared record state;
- `read/decrypt.rs` — cipher-neutral group decryption and typed outcomes;
- `read/projection.rs` — validity metadata plus flat and secure projections;
  and
- `read/foreign.rs` — reader-material discovery and construction of decryptors
  for foreign logs.

Read-specific public data types may remain in `runtime/types.rs` while that file
stays within the production limit. Moving types is permitted only when it makes
one of the boundaries above clearer; it is not a goal by itself.

## Cipher boundary

The scanner and policy engine never branch on `btn`, `hibe`, or `jwe`. They
receive a group decryptor that accepts a group name, ciphertext bytes, and AAD,
and returns one of these semantic outcomes:

- decrypted JSON bytes;
- no reader capability for the group;
- authenticated decryption failure; or
- malformed plaintext.

Configured-runtime reads adapt the runtime's existing `GroupCipher` instances
to this boundary. Consequently, BTN and feature-enabled native HIBE use the same
pipeline today, and another cipher implementing `GroupCipher` requires no
scanner or policy changes.

Foreign-log reads build the same decryptor set from discovered reader material.
This slice wires BTN and the existing feature-enabled HIBE implementation.
Cipher-specific file names and key construction stay inside `foreign.rs` and
the cipher builders. JWE reader material produces a precise unsupported-cipher
error until native Rust JWE exists; adding JWE later is a loader/backend change,
not a read-pipeline rewrite.

Possessing reader material does not authorize the publisher. Signature
verification and receiver-local exact-DID writer trust remain independent gates.

## Data flow

1. Resolve `ReadOptions` into one frozen trust policy and source context.
2. Open a fixed-length source snapshot and validate the incoming cursor.
3. Read one bounded record and advance source position independently of whether
   that record will be returned.
4. Parse and verify the envelope before releasing plaintext.
5. Reject immediately when pre-decryption trust checks fail.
6. Decrypt group blocks through the cipher-neutral decryptor.
7. Apply AAD and required-recipient decisions.
8. Project accepted records into the existing flat `Entry` shape.
9. Return accounting and the cursor at the captured snapshot boundary.

`VerifyMode::Raise` stops at the first rejected record. `VerifyMode::Skip`
advances the cursor, increments skip accounting, and emits the existing
best-effort tamper event when writable. `VerifyMode::Disabled` relaxes integrity
and writer-authorization gates but never bypasses parsing or authenticated group
decryption.

## Error behavior

The refactor preserves existing stable rejection reasons and does not include
plaintext in an error. Optional unreadable groups remain hidden groups. An
explicitly required unreadable group becomes `not_a_recipient`. Malformed
ciphertext or authenticated decryption failure remains a decryption/AAD failure,
not an unknown-writer result.

Unsupported foreign-reader cipher material fails at decryptor construction with
the cipher and group identified. It does not fall through to BTN or silently
return an empty result.

## Testing

Implementation follows red-green-refactor cycles:

1. Add the production source-shape test and observe it fail on the current
   2,153-line file and oversized functions.
2. Add a cipher-neutral read test using a second test decryptor and observe the
   current BTN-specific foreign path fail it.
3. Split modules and introduce the decryptor boundary without changing public
   result shapes.
4. Run secure-default read, trust-provider, cursor, watch, raw-read, and
   projection tests after every extraction.
5. Run native HIBE read tests with the HIBE feature enabled.
6. Run the default Rust SDK suite, the `tn-core` suite, formatting, and scoped
   lint checks before committing the implementation.

Tests may be longer than the production limits, but shared helpers should still
keep security assertions readable and avoid duplicating fixture mutation logic.

## Success criteria

The slice is ready to land when:

1. no read-focused production Rust file exceeds 609 lines;
2. no changed production function exceeds 50 lines without a named reason, and
   no production function exceeds 200 lines;
3. the initial exemption list is empty;
4. `Tn::read` and watch retain their current public shapes and secure defaults;
5. configured BTN and native HIBE reads share the same scanner, policy, and
   decryptor path;
6. foreign cipher selection is isolated from scanning and policy;
7. missing native JWE support is reported precisely at the loader boundary;
8. read, trust, cursor, watch, and HIBE-focused tests pass; and
9. only files belonging to this Rust read slice are included in its
   implementation commits.
