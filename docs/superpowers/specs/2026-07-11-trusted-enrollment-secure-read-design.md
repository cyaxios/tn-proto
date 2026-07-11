# Trusted Enrollment and Secure-Default Read Design

**Status:** Approved in conversation; written-spec review complete

**Date:** 2026-07-11

**Scope:** Python, Rust, TypeScript, and C# SDKs

**Workstreams:** A — trusted principals and enrollment; B — secure-default reads

## Purpose

TN already has the cryptographic pieces for signed packages, JWE reader keys,
HIBE grants, row hashes, chains, and record signatures. The missing layer is a
consistent trust decision connecting those pieces to a real principal.

This design makes a complete Ed25519 `did:key` the trust anchor for both JWE and
HIBE ceremonies, completes the JWE reader-enrollment lifecycle, and makes
`read()` the secure-by-default primary read surface. It preserves deliberate
escape hatches, but every weakening operation is explicit, observable, and
excluded from claims of authentication or authorization.

## Goals

1. Bind every admitted JWE X25519 public key to a real reader DID.
2. Complete a usable JWE flow from reader key creation through the reader's
   first successful decrypt.
3. Bind HIBE authority material and path updates to a real authority DID.
4. Require a real reader DID and recipient-sealed delivery for normal HIBE
   grants.
5. Keep `read()` as the main API while making its default behavior verify
   integrity, require signatures where appropriate, and authorize writers.
6. Produce identical wire bytes, trust decisions, and reason codes in Python,
   Rust, TypeScript, and C#.
7. Allow workstreams A and B to execute concurrently without new dependencies
   between them.

## Non-goals

- This work does not constitute the external cryptographic audit required
  before production HIBE use.
- It does not make a HIBE reader key non-transferable. A `.hibe.sk` remains a
  bearer capability after delivery.
- It does not make public HIBE sealing authenticate a writer. Record signatures
  and receiver-local writer policy provide that boundary.
- It does not add general DID resolution. Version 1 accepts self-contained
  Ed25519 `did:key` identities only.
- It does not implement DID rotation, organization-wide PKI, certificate
  chains, or delegated writer policy.
- It does not silently preserve unverified JWE recipients across rotation.

## Definitions and invariants

### Real DID

A real DID in this design is a complete Ed25519 `did:key` that:

1. decodes without lossy normalization;
2. contains the Ed25519 multicodec prefix and exactly 32 public-key bytes;
3. is byte-for-byte equal to the DID derived from the signing public key; and
4. successfully verifies the relevant canonical statement signature.

Placeholders, abbreviations, other DID methods, wrong multicodecs, unrelated raw
signing keys, and merely well-shaped strings are not real DIDs for these flows.

### Authentication and authorization

- **Authentication** proves that a real DID signed a statement.
- **Authorization** is a receiver-local decision that the authenticated DID may
  perform the requested action.
- An incoming package, record, or manifest may present authentication evidence;
  it cannot authorize itself.

### Atomicity

Any trust failure occurs before persistent mutation. Replaying the identical
accepted artifact is an idempotent no-op. Reusing a nonce or scope with different
canonical bytes is a conflict and is rejected.

## Architecture

### Workstream A: trusted principals and enrollment

Workstream A owns:

- canonical signed key-binding statements;
- publisher-issued enrollment challenges;
- the complete JWE offer/enrollment lifecycle;
- HIBE authority assertions and monotonic path epochs;
- fail-closed HIBE reader-grant delivery; and
- explicit unsafe compatibility paths.

Its trust verifier returns a `VerifiedPrincipal` only after cryptographic,
identity, scope, freshness, digest, and local-policy checks pass.

### Workstream B: secure-default reads

Workstream B owns:

- receiver-local `ReadTrustPolicy`;
- secure automatic defaults for `read()`;
- writer authorization after cryptographic verification;
- stable rejection reasons and existing skip/raise behavior;
- security warnings and audit events for explicit weakening; and
- parity across read/watch implementations.

Workstream B uses the existing Ed25519 DID verification primitive. It does not
depend on Workstream A's enrollment state or new package APIs.

### Shared contract

Both workstreams share only:

- canonical JSON rules already used by TN;
- strict Ed25519 `did:key` parsing and signature verification;
- stable reason-code naming; and
- cross-SDK fixture conventions.

The DID verifier interface is frozen before parallel implementation begins.

## Canonical signed statements

Every statement is canonical JSON, UTF-8 encoded, with lexicographically sorted
object keys and no insignificant whitespace. The signature covers the complete
object with the `signature_b64` member omitted. Unknown versions and all unknown
fields in a version 1 security statement are rejected rather than ignored.

All timestamps are UTC RFC 3339 strings. Binary values use standard padded
base64 unless an existing TN wire field explicitly requires base64url.

### Package body digest index

Every newly written `.tnpkg` manifest carries a `body_sha256` object whose keys
are the exact normalized `body/...` member paths and whose values are
`sha256:<lowercase hex>`. The map is part of the manifest signing domain. The
writer computes it from the final stored member bytes before signing. A reader
verifies that the archive contains exactly the indexed body members and that
every digest matches before parsing, decrypting, or applying a body.

All producers use one `sign_manifest_with_body` builder that validates body
paths, computes the final digest index, and only then signs. Verified readers
enforce resource limits, read and verify the bounded manifest signature, then
stream/read bounded body members to verify the exact index before returning any
body to kind-specific code. A low-level unverified inspector is never used by an
absorb/apply path.

Security-sensitive version-1 offers, enrollment responses, and HIBE grants
without this index fail closed. Other legacy packages may enter only through the
named unsafe legacy-import path; that path emits the common unsafe-operation
warning and audit event and never marks the package or installed principal as
verified.

### `KeyBindingProofV1`

Common fields:

```json
{
  "version": 1,
  "purpose": "jwe-reader | hibe-reader | hibe-authority",
  "subject_did": "did:key:z...",
  "audience_did": "did:key:z...",
  "ceremony_id": "...",
  "group": "default",
  "issued_at": "2026-07-11T14:00:00Z",
  "expires_at": "2026-07-11T14:10:00Z",
  "nonce_b64": "...",
  "binding": {},
  "signature_b64": "..."
}
```

For `purpose: jwe-reader`, `binding` is:

```json
{
  "algorithm": "X25519",
  "public_key_b64": "<32 raw bytes>",
  "challenge_digest": "sha256:..."
}
```

`challenge_digest` is required for pre-authorized automatic enrollment. It is
`null` only for an unsolicited offer that cannot reconcile until an
administrator approves that offer's exact canonical digest.

For `purpose: hibe-authority`, `binding` is:

```json
{
  "algorithm": "TN-BBG-HIBE-BLS12-381",
  "mpk_sha256": "sha256:...",
  "max_depth": 3,
  "id_path": "org/fraud/case-17",
  "path_epoch": 4
}
```

For `purpose: hibe-reader`, `binding` is:

```json
{
  "algorithm": "Ed25519-did-key",
  "delivery": "recipient-seal-v1",
  "challenge_digest": "sha256:..."
}
```

The HIBE authority issues the scoped challenge. A previously verified reader
contact may satisfy this requirement with its retained, unexpired proof for the
same authority, ceremony, and group.

The proof signature must verify using the Ed25519 public key embedded in
`subject_did`. An unrelated `signer_verify_pub_b64` is never sufficient.

### `EnrollmentChallengeV1`

The publisher signs a challenge containing:

- version and kind;
- publisher DID;
- expected reader DID;
- ceremony ID and group;
- random 256-bit nonce;
- issued and expiry timestamps; and
- one-time challenge identifier.

The reader verifies the publisher signature against the expected publisher DID
before producing a JWE key-binding proof. A publisher may create the challenge
from a pre-authorized reader record or during an explicit administrative
approval flow.

### `EnrollmentResponseV1`

The publisher's accepted-enrollment response is a canonical signed statement:

```json
{
  "version": 1,
  "kind": "tn-enrollment-response",
  "publisher_did": "did:key:z...",
  "reader_did": "did:key:z...",
  "ceremony_id": "...",
  "group": "default",
  "accepted_offer_digest": "sha256:...",
  "x25519_public_key_sha256": "sha256:...",
  "group_epoch": 1,
  "issued_at": "2026-07-11T14:01:00Z",
  "expires_at": "2026-07-11T14:11:00Z",
  "signature_b64": "..."
}
```

The response uses the same strict version/field/canonicalization rules as the
challenge and proof. The reader verifies it against the expected publisher DID
and its retained offer before changing local publisher metadata.

### Verified JWE binding

Every verified-principal value retains the subject DID, purpose, audience DID,
ceremony ID, group, proof digest, issuance time, and expiry. APIs that accept a
verified principal re-check this retained scope against their own receiver,
ceremony, and group.

Successful JWE proof verification produces a typed binding containing that
verified principal, the 32-byte X25519 public key, its SHA-256 digest, the proof
digest, and the optional challenge digest. Promotion returns one
`AcceptedOffer` containing the binding, exact offer digest, and retained
artifact digest. Recipient registration and enrollment-response compilation
consume that single value; callers cannot pair one valid binding with another
offer's digest.

`offer_digest` is SHA-256 over the canonical inner offer statement bytes,
including its signature. It is stable across compliant `.tnpkg` containers.
`artifact_digest` is SHA-256 over the exact retained `.tnpkg` bytes and protects
the receiver's stored artifact. Both use the `sha256:<lowercase hex>` form.

## JWE enrollment lifecycle

### 1. Reader key creation

The reader creates one static X25519 keypair per group. The private key is
persisted atomically in the reader keystore with owner-only permissions or a
private Windows ACL. It is never exported. Re-running creation reuses the exact
existing key unless the caller explicitly requests reader-key rotation.

### 2. Publisher pre-authorization

The publisher either:

- records the exact real reader DID as expected and issues a signed challenge;
  or
- receives an unsolicited authenticated offer that remains pending until an
  administrator explicitly approves its exact digest.

An authenticated but unsolicited offer is not automatically authorized.

### 3. Reader offer

The reader returns a signed JWE `KeyBindingProofV1` carrying the challenge
digest when a challenge was issued. An unsolicited reader may instead send a
proof with `challenge_digest: null`; that proves the scoped key binding but
cannot authorize or auto-promote itself. The surrounding `.tnpkg` manifest and
inner proof must agree on signer, recipient, ceremony, group, purpose, and body
digest.

### 4. Publisher verification and pending state

Before writing pending state, the publisher verifies:

1. outer manifest signature and every body-member digest;
2. outer signer DID equals inner `subject_did`;
3. outer recipient equals the local publisher DID;
4. complete Ed25519 DID and DID-bound inner signature;
5. exact ceremony, group, publisher, purpose, and expected-reader scope;
6. X25519 algorithm and 32-byte public-key length;
7. challenge signature, digest, nonce, expiry, and unused status when a
   challenge is present, otherwise the requirement for explicit exact-digest
   approval; and
8. receiver-local authorization for the reader DID or exact offer digest.

Pending offers are keyed by `(ceremony_id, group, reader_did, offer_digest)`,
not by DID alone. The complete signed artifact is retained so reconcile can
re-verify rather than trusting a filename or reduced JSON cache.

Enrollment state version 1 uses one private state root with separate
`challenges/`, `offers/`, `approvals/`, and `consumed/` trees plus one
`enrollment.lock`. Challenge consumption, exact-digest approval, and promotion
are serialized under that cross-process advisory lock. Writes use same-directory
temporary files, file/directory synchronization where supported, and atomic
replacement. Concurrent exact repeats converge on one accepted state; a
different artifact for a used nonce/challenge returns `replay_conflict`.

### 5. Reconcile and registration

Reconcile re-verifies the retained artifact and promotes only an exact,
authorized match. Registration persists the authenticated DID-to-X25519 binding
and proof digest with the recipient entry. No mutation occurs before all checks
pass.

The public `approve/reconcile` operation performs exact-digest approval,
re-verification, challenge consumption, promotion, and registration atomically
and returns the resulting `AcceptedOffer`. Every SDK exposes this operation;
response compilation accepts only that returned value.

The low-level `add_recipient(did, public_key)` path requires a valid proof. Its
legacy raw form remains available only as
`unsafe_unverified=True`, emits a warning and administrative audit event, and
stores the recipient as unverified so it cannot be silently promoted to trusted
state.

SDKs whose primary typed registration accepts only `AcceptedOffer` also expose
an explicitly named raw compatibility call taking the DID, 32-byte X25519 public
key, and `unsafe_unverified=true`. The flag is mandatory; omitting it is a hard
parameter error.

### 6. Publisher enrollment response

The publisher signs an enrollment response binding:

- publisher and reader DIDs;
- ceremony and group;
- accepted offer digest;
- X25519 public-key digest;
- resulting group epoch; and
- issuance/expiry metadata.

The reader verifies exact recipient, publisher trust, scope, and offer digest
before installing public publisher metadata. Its local `.jwe.mykey` must already
exist and must derive the public key named in the response.

### 7. First decrypt

The next seal contains a recipient block for the authenticated X25519 key. The
reader opens it using its retained private key. A cross-SDK end-to-end test must
exercise the complete lifecycle rather than manually copying keystore files.

### Rotation boundary

JWE rotation continues to reset the active audience to publisher-only.
Authenticated prior bindings become a re-enrollment plan, not automatic active
recipients. Re-enrollment requires a fresh challenge/proof when reader-key
rotation is intended. Silently restoring an old public key is not part of this
milestone.

## HIBE trusted-principal behavior

### Authority assertion

An external HIBE authority distributes its MPK with a `hibe-authority`
`KeyBindingProofV1`. A writer must be configured with the expected real authority
DID or a receiver-local exact-DID trust entry. Before persisting or sealing, it
verifies:

- authority DID and signature;
- MPK bytes against `mpk_sha256`;
- encoded MPK depth against asserted `max_depth`;
- configured path depth against `max_depth`;
- exact ceremony/group scope; and
- non-decreasing `path_epoch`.

The writer atomically persists authority DID, MPK fingerprint, maximum depth,
path, epoch, and assertion digest. A conflicting MPK at the same epoch and an
epoch rollback are rejected. An expired assertion cannot authorize a new seal;
it does not prevent opening already-held ciphertext under existing reader keys.

The authority API signs the initial assertion and every path/epoch update. The
reader-contact API issues a scoped HIBE challenge and verifies the resulting
`hibe-reader` proof. External writers expose one explicit
accept-and-pin/update operation and cannot seal merely because raw MPK bytes and
an `id_path` are present.

Python, Rust, TypeScript, and C# each expose all four operations: reader
challenge issuance, reader proof creation/verification, authority assertion
issue/install, and path rotation returning the new higher-epoch signed
assertion.

### Path update

A path update is a new signed authority assertion with a strictly greater epoch.
It is accepted only under the already pinned authority DID. This authenticates
updates and prevents rollback; it does not give an offline writer knowledge that
an unseen update exists. Operational fencing or ingestion policy remains
required until every external writer acknowledges the new epoch.

### Reader grant

Normal `grant_reader` requires a real, resolvable Ed25519 `did:key` plus a valid
`hibe-reader` proof (or a retained verified-reader record for the exact scope).
The package body is recipient-sealed and the final manifest binds every
encrypted body digest. An invalid, unproved, expired, or mismatched DID is a hard
error; there is no implicit plaintext fallback.

`unsafe_plaintext=True` is the only plaintext compatibility path. It emits a
security warning and audit event and labels the artifact as unsafe bearer
delivery.

Exact-path grants are the default. Minting an ancestor grant requires
`allow_subauthority=True`, and the result explicitly records that it grants
subtree delegation within the remaining depth. No API or documentation calls an
ancestor grant an ordinary reader grant.

## Secure-default `read()`

### Primary surface

`read()` remains the primary read API and retains its iterator, entry, stats,
callback, and log-selection shapes. `secure_read()` becomes a convenience wrapper
that delegates to strict `read()` parameters; it is not a competing policy
engine. It rejects caller-supplied parameters that would weaken strict
verification, authentication, or authorization.

### Default policy resolution

The default `verify` value becomes `"auto"` (represented internally by a
sentinel, not `False`). Under that default policy, `read()` performs these checks
before returning plaintext:

1. parse and canonical-shape validation;
2. row-hash recomputation when the record carries or requires a row hash;
3. chain verification when chaining applies;
4. signature presence when required;
5. Ed25519 signature verification against the complete `device_identity` DID;
6. writer authorization against receiver-local trust; and
7. group decryption/AAD validation.

The verified DID is authorized only after all applicable cryptographic checks
pass.

`"auto"` resolves to raise-on-first-rejection after context-dependent signature
requirements and trust defaults are resolved. It never silently drops a bad or
unauthorized row. Callers that want verified continuity choose
`verify="skip"` and use the existing stats/callback observability.

### Signature requirement

`require_signature` defaults to automatic:

- records for an explicitly unsigned active profile are allowed unsigned;
- records from the local ceremony follow that ceremony's explicit profile;
- foreign or context-free records require a signature unless the caller passes
  `require_signature=False`.

An empty signature does not become acceptable merely because the local reader
ceremony happens to have `sign: false`.

An allowed unsigned record has no authenticated writer. `allow_unauthenticated`
defaults to true only when reading the active ceremony's own log under an
explicitly unsigned profile; it defaults to false for foreign or context-free
logs. Returning an unsigned foreign record therefore requires both
`require_signature=False` and `allow_unauthenticated=True`.

### Writer trust

The default receiver-local trusted-writer set contains:

- the active local device DID;
- authenticated publisher DIDs installed through verified packages; and
- configured exact-DID trust entries.

Each SDK exposes the same receiver-local `ReadTrustProvider` boundary:

- `trusted_writer_dids(context) -> exact-DID set`; and
- `source_for(did) -> local-device | verified-package | explicit-config | null`.

The default adapter combines the active device DID, verified publisher records
under the ceremony's private state directory, and the ceremony configuration's
explicit `trust.writers` list. Workstream B can use an in-memory provider and the
local-device/config sources without enrollment state. Workstream A later adds
verified publisher records through this interface; read-policy evaluation never
imports or depends on enrollment state types.

`trusted_writers=` supplies an explicit set for the call. Unknown writers are
rejected by default even when their self-asserted signature is cryptographically
valid. `allow_unknown_writers=True` deliberately relaxes only authorization; it
does not disable signature or integrity verification.

An unsigned record cannot satisfy `trusted_writers`, because its envelope DID is
not authenticated. Read validity metadata distinguishes
`writer_authenticated` from `writer_authorized`; neither is inferred from an
unsigned `device_identity` field.

### Existing tuning parameters

- `verify="raise"`: fail on the first integrity, authentication, or
  authorization rejection.
- `verify="skip"`: skip rejected records and report stable reasons through
  existing stats/callback mechanisms.
- `verify=True`: compatibility alias for `"raise"`.
- `verify=False`: explicitly disable record-integrity verification.
- `require_signature=False`: allow intentionally unsigned input while retaining
  other enabled checks.
- `allow_unauthenticated=True`: allow an unsigned record to be returned without
  claiming writer authentication or authorization.
- `trusted_writers={...}`: replace the call's writer allowlist.
- `allow_unknown_writers=True`: allow verified but locally unauthorized DIDs.

Combinations that would claim authorization without verification are invalid.
For example, `verify=False` with `trusted_writers` raises a parameter error rather
than treating an unverified envelope DID as trusted.

`verify=False` disables row-hash, chain, signature, and writer-authorization
gates only. Canonical parsing and authenticated group decryption/AAD validation
remain mandatory; a malformed record, failed required-recipient lookup, or AEAD
failure is never returned as plaintext.

Validity metadata carries an ordered, de-duplicated `reasons` array in the same
order as the default checks above. Compatibility callbacks and exceptions use
the first reason as their primary reason. `not_a_recipient` applies only when an
explicitly requested/required group or recipient-mode decryption cannot find a
fitting recipient block/key. A hidden optional group does not reject an
otherwise readable row and remains represented through the existing hidden-group
metadata.

Watch/report plumbing uses one `ReadCursorV1` token:

```json
{
  "version": 1,
  "sources": {
    "<canonical-source-id>": {
      "kind": "byte_offset | sequence | opaque",
      "value": "123"
    }
  }
}
```

Source IDs are canonical and the map is serialized in sorted order. `value` is
a decimal or opaque string so every SDK preserves it losslessly. Read reports
carry both a scanned-row count for observability and this cursor for resumption;
watchers persist the cursor, never derive progress from yielded-entry count.

The canonical source ID is `source:sha256:<lowercase hex>` over a UTF-8 source
descriptor:

- file: `file\0` plus the lexically absolute path anchored at the ceremony YAML
  directory, with `.`/`..` removed, separators changed to `/`, and only a
  Windows drive letter lowercased; symlinks and the remaining path are not
  case-folded;
- configured handler: `handler\0<kind>\0<configured-id>` using the exact
  validated configuration strings; and
- detached bytes/address: `detached\0sha256:<content-or-address digest>`.

The NUL separators are literal single zero bytes. Shared cursor fixtures cover
Windows, POSIX, handler, detached, and multi-source sorting cases.

### Weakening observability

Explicitly weakening defaults emits:

1. a structured security warning; and
2. an administrative audit event when a writable active ceremony is available.

Audit emission is guarded against recursion and is skipped for read-only or
detached readers. It never changes the result of the requested read.

All SDKs use the event type `tn.security.unsafe_operation` with this exact
non-secret payload:

```json
{
  "operation": "read | watch | jwe_add_recipient | hibe_grant | legacy_package_import",
  "relaxations": ["verification_disabled"],
  "group": null,
  "subject_did": null,
  "artifact_digest": null
}
```

`relaxations` is a sorted, de-duplicated array drawn from
`verification_disabled`, `signature_not_required`,
`unauthenticated_allowed`, `unknown_writer_allowed`,
`unverified_key_binding`, `plaintext_bearer_delivery`, and
`legacy_signer_mismatch`. The structured warning exposes the same fields. SDKs
whose normal API returns a warning/result collection include it there; SDKs with
language warning facilities use those facilities. Every SDK applies a
thread/task-local recursion guard and treats audit failure as best effort.

Ownership is single-shot: the outer language-facing SDK wrapper emits exactly
one language warning, while the mutation/read-owning runtime layer emits exactly
one best-effort admin audit event. A native-backed wrapper never emits a second
audit; a pure-language runtime combines the two responsibilities but still
produces one warning and one event. Tests count both.

## Stable rejection reasons

Common signed-statement reasons:

- `statement_invalid` — malformed canonical JSON, an unsupported version, or
  an unknown field in a versioned security statement;
- `statement_expired` — an otherwise valid proof or authority assertion is
  outside its acceptance window; and
- `signature_invalid` — the signature does not verify under the complete
  Ed25519 DID named by the statement or package.

Package/enrollment reasons:

- `did_invalid`
- `did_signer_mismatch`
- `outer_inner_signer_mismatch`
- `wrong_recipient`
- `scope_mismatch`
- `body_digest_mismatch`
- `challenge_missing`
- `challenge_expired`
- `challenge_replayed`
- `replay_conflict`
- `binding_invalid`
- `untrusted_principal`
- `epoch_rollback`
- `epoch_conflict`

Read reasons:

- `record_invalid`
- `row_hash_invalid`
- `chain_invalid`
- `signature_required`
- `signature_invalid`
- `writer_untrusted`
- `aad_invalid`
- `not_a_recipient`

SDK-specific exception text may add context, but the machine-readable reason is
identical across SDKs.

These mappings are exhaustive for version 1. Outer-manifest, challenge, proof,
and authority-assertion signature failures use `signature_invalid`. Unknown
versions and unknown fields use `statement_invalid`. Invalid algorithms, key
lengths, key digests, or MPK/depth bindings use `binding_invalid`. A conflicting
MPK or path assertion at the already-pinned epoch uses `epoch_conflict`; a lower
epoch uses `epoch_rollback`. Read parse and canonical-shape failures use
`record_invalid`.

## Compatibility and migration

- Valid packages whose signing key already matches their claimed real DID
  continue to work after full scope/digest validation.
- Legacy packages with unrelated signing keys or no signed body index are
  rejected by default and may be imported only with
  `unsafe_legacy_signer=True`; the import remains unverified and emits the
  common unsafe-operation warning/audit event.
- Raw JWE DID-plus-key enrollment requires `unsafe_unverified=True`.
- Implicit plaintext HIBE grant fallback is removed; use
  `unsafe_plaintext=True` explicitly.
- `read()` changes from insecure `verify=False` to secure automatic behavior.
  Existing callers may request old behavior with explicit parameters and receive
  a warning.
- Telemetry/stdout and other intentionally unsigned profiles remain supported
  through explicit profile metadata or the explicit
  `require_signature=False, allow_unauthenticated=True` combination.
- Wire version 1 is additive. Unknown future versions fail closed.

## Cross-SDK implementation requirements

Python, Rust, TypeScript, and C# must share:

- canonical statement fixtures;
- positive and negative signature fixtures;
- reason-code fixtures;
- enrollment lifecycle fixtures;
- read-policy decision matrices; and
- replay/epoch state-transition fixtures.

No SDK is considered complete if it accepts an artifact another SDK rejects for
identity, scope, digest, freshness, or authorization reasons.

Each SDK exposes public challenge/proof verification, offer creation, package
absorption/pending approval, accepted-response verification, JWE recipient
registration, HIBE assertion pin/update, and fail-closed HIBE grant controls.
Cross-SDK lifecycle tests rotate producer/consumer roles so the complete JWE
ceremony and first decrypt do not depend on one language's private state format.

The established JWE architecture remains library-per-language and outside the
Rust native runtime/wasm cipher dispatch. Python, TypeScript, and C#'s managed
JWE layer participate in first-decrypt tests. Rust participates in canonical
statement, package, replay/epoch, approval, and enrollment-artifact interop but
keeps its documented JWE runtime `NotImplemented` sentinel; this milestone does
not add a hand-rolled JOSE implementation to `tn-core`.

## Testing strategy

### Workstream A

Tests cover:

- real and invalid Ed25519 DIDs;
- substituted signing and X25519 keys;
- outer/inner signer mismatch;
- wrong publisher, reader, ceremony, group, or purpose;
- missing/expired/replayed challenges;
- exact replay versus conflicting replay;
- multi-group offers from one DID without filename collision;
- concurrent enrollment with atomic state;
- body-member substitution and digest failure;
- no publisher private-key export;
- JWE first-decrypt end to end across SDKs;
- HIBE MPK substitution, depth mismatch, and epoch rollback;
- fail-closed HIBE grant delivery; and
- explicit ancestor/subauthority grants.

### Workstream B

The read matrix covers every relevant combination of:

- row hash valid/invalid/absent;
- chain valid/invalid/disabled;
- signature valid/invalid/absent;
- signed and unsigned profiles;
- trusted, unknown, and explicitly supplied writer DIDs;
- authenticated, authorized, and explicitly unauthenticated writer states;
- `auto`, `raise`, `skip`, and `False` verification modes;
- signature and unknown-writer overrides;
- AAD valid/invalid; and
- local, authenticated foreign, and context-free logs.

Tests assert that plaintext is never returned before all required checks pass.

### Performance and robustness

- Verification remains streaming and memory-bounded.
- Watch cursors advance by scanned source position/sequence rather than the
  count of accepted rows, so a skipped row is neither replayed nor allowed to
  hide a later row.
- APIs that intentionally materialize a complete result list may accumulate
  that result, but verification adds only bounded per-row working memory.
- Trust lookup is constant-time per exact DID after configuration load.
- Challenge and pending-state writes are atomic and concurrency tested.
- Malformed packages and records have bounded input sizes and stable failures.
- Performance gates compare secure-default reads against the existing verified
  read path, not against the intentionally insecure `verify=False` path.

## Parallel delivery

After the written spec and implementation plan are approved:

- **Foundation:** freeze canonical statement/DID interfaces, reason mappings,
  the deterministic fixture generator, all shared fixture files, the common
  unsafe-operation catalog event, and language-level warning payload/event
  surfaces;
- **Track A1:** DID-bound package verification and cross-SDK trust adapters;
- **Track A2:** complete JWE enrollment lifecycle and state machine;
- **Track A3:** HIBE authority assertions and fail-closed grants; and
- **Track B:** secure-default `read()` and writer policy.

The Foundation is a short contract-freeze barrier. Immediately after it lands,
Track B starts in parallel with A1-A3 and does not wait for enrollment state or
package APIs. A2 and A3 share A1's verifier contract. After Rust/core and
TypeScript track-local APIs for A and B pass, one joint bridge integration task
adds all FFI functions, C# native declarations, and SDK root exports before
C# lifecycle/read GREEN gates run. One later joint documentation/verification
task owns shared guides/readmes. No other task edits those shared paths.

## Success criteria

The design is complete when:

1. a reader can complete JWE enrollment without copying private material;
2. the publisher can prove the enrolled X25519 key belongs to the admitted DID;
3. a HIBE writer can prove and pin which real authority DID signed its MPK and
   current path epoch;
4. normal HIBE grants cannot silently become plaintext;
5. `read()` rejects invalid, unsigned-when-required, and unauthorized records by
   default;
6. explicit weakening remains possible and observable;
7. all four SDKs pass the same wire and decision fixtures; and
8. the documentation continues to state that HIBE requires external
   cryptographic review before production use.
