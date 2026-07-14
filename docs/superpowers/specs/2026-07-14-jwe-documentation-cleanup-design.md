# JWE documentation cleanup design

## Goal

Every tracked description of tn-proto must present JWE as an implemented,
standards-compliant cipher. Documentation must reflect the current RFC 7516
General JSON implementation in Rust, tn-wasm, TypeScript, Python, and the
available C# runtime surfaces.

## Scope

The cleanup includes live guides, READMEs, reference documents, historical
plans and specifications, source documentation, and test comments. Existing
files and links remain in place unless a file is exclusively about an obsolete
wire format and has no current technical value.

The cleanup removes or rewrites descriptions that characterize JWE as pending,
future work, unavailable in Rust or WebAssembly, limited to a pure-JavaScript
implementation, or dependent on an obsolete TN-specific wrapper.

## Current implementation statement

Documentation will consistently describe these facts:

- tn-core implements standard RFC 7516 JWE General JSON Serialization.
- tn-wasm exposes JWE primitives and runtime seal, unseal, emit, and read.
- TypeScript exposes ordinary JWE verbs and BTN/JWE primitive namespaces,
  using Rust/WebAssembly cryptographic primitives where applicable.
- Python supports JWE through its normal logging and sealed-object verbs.
- C# exposes the ordinary runtime verbs and JWE decryption support; wording
  must describe concrete usability boundaries without implying JWE is absent.
- JWE private reader keys stay with readers and are never ordinary reader-kit
  exports; public-key enrollment is the supported ceremony.

## Rewrite rules

1. Rewrite availability and architecture statements in place instead of
   leaving historical claims quoted or marked only as superseded.
2. Remove obsolete names and designs, including `tn-jwe-v1`, TN-wrapped JWE,
   Biscuit-based JWE, and pure-JavaScript-only descriptions.
3. Preserve legitimate protocol validation language such as unsupported JWE
   header members, unsupported artifact versions, not-yet-valid timestamps,
   and pending-recipient lifecycle states. Those phrases describe rejected
   inputs or active state, not feature availability.
4. Preserve accurate limitations such as reader-owned private keys, rotation
   requiring re-enrollment, and specific SDK convenience gaps.
5. Do not change runtime behavior as part of this work.

## Verification

After rewriting, a repository-wide case-insensitive scan will check JWE-adjacent
uses of `not implemented`, `unsupported`, `not supported`, `pending`, `planned`,
`future`, `not yet`, `out of scope`, `pure JS`, and obsolete JWE design names.
Each remaining match must describe a legitimate input/state restriction.

The documentation contract tests will run, followed by formatting or build
checks only where generated documentation or source files require them. The
final diff must contain documentation/comment changes only.
