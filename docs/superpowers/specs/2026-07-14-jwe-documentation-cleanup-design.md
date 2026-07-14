# JWE documentation cleanup design

## Goal

Every tracked description of tn-proto presents JWE as a standards-compliant
cipher. Documentation reflects the current RFC 7516
General JSON implementation in Rust, tn-wasm, TypeScript, Python, and the
available C# runtime surfaces.

## Scope

The normalization includes live guides, READMEs, reference documents,
historical plans and specifications, source documentation, and test comments.
Each surface states the current architecture directly and keeps useful security
and operational constraints.

## Current implementation statement

Documentation will consistently describe these facts:

- tn-core implements standard RFC 7516 JWE General JSON Serialization.
- tn-wasm exposes JWE primitives and runtime seal, unseal, emit, and read.
- TypeScript exposes ordinary JWE verbs and BTN/JWE primitive namespaces,
  using Rust/WebAssembly cryptographic primitives where applicable.
- Python supports JWE through its normal logging and sealed-object verbs.
- C# exposes the ordinary runtime verbs and JWE decryption support, with each
  concrete usability boundary scoped to the affected operation.
- JWE private reader keys stay with readers and are never ordinary reader-kit
  exports; public-key enrollment is the supported ceremony.

## Rewrite rules

1. State current availability and architecture directly in every tracked file.
2. Name the standard wire format as RFC 7516 General JSON and the implementation
   surfaces as Rust, WebAssembly, and their language bindings.
3. Preserve legitimate protocol validation language such as unsupported JWE
   header members, unsupported artifact versions, not-yet-valid timestamps,
   and pending-recipient lifecycle states. Those phrases describe rejected
   inputs or active state, not feature availability.
4. Preserve accurate limitations such as reader-owned private keys, rotation
   requiring re-enrollment, and specific SDK convenience gaps.
5. Do not change runtime behavior as part of this work.

## Verification

After rewriting, a repository-wide scan verifies that every JWE architecture
statement matches the current Rust/WebAssembly-backed RFC 7516 implementation.
Any restriction must identify the exact input, state, or operation it governs.

The documentation contract tests will run, followed by formatting or build
checks only where generated documentation or source files require them. The
final diff must contain documentation/comment changes only.
