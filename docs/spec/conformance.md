# Conformance

This document defines what it means to **conform** to the TN wire
protocol: who the requirements bind, and how an implementation proves
it satisfies them. It is the contract the rest of the spec is written
against. Read it before the surface specs.

## Requirement keywords

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**,
**SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and
**OPTIONAL** in this specification are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

A capitalized keyword is normative. The same word in lower case
("a reader should expect…") is descriptive prose and carries no
conformance weight.

## Authority

This specification is authoritative. An implementation conforms to the
specification; where an implementation and this document disagree, the
specification governs and the implementation has a defect to fix.

The wire format is defined here in language-neutral terms. It is not
defined by reference to any one implementation's source.

## Conformance classes

An implementation does not conform "in general." It conforms as one or
more of the roles below, and a claim of conformance MUST name the
class(es) claimed.

### Producer

A **producer** emits wire artifacts: [envelopes](./envelope.md),
[manifests](./manifest.md), and [sealed bodies](./body-encryption.md).

A conforming producer MUST, for every artifact it emits:

- Serialize all hashed, signed, or compared values through the
  [canonical bytes](./canonical-bytes.md) rule, byte for byte.
- Compute [`row_hash`](./row-hash.md), [signatures](./signing.md), and
  [index tokens](./indexing.md) exactly as specified.
- Produce output byte-identical to the corresponding
  [conformance vector](#test-vector-conformance) for every vector input
  it can represent.

A conforming producer MUST NOT emit an artifact that a conforming
verifier would reject as malformed.

### Verifier

A **verifier** (reader) consumes wire artifacts and validates their
integrity: recomputing `row_hash`, checking signatures, decrypting
recipient wraps.

A conforming verifier MUST:

- Accept every artifact a conforming producer can emit.
- Recompute the `row_hash` from the artifact's own fields and reject
  the artifact on mismatch.
- Verify the [signature](./signing.md) against the stated
  `device_identity` and reject on failure.
- Reject, not silently repair, any artifact that violates a structural
  MUST in the surface specs.

A conforming verifier MUST NOT treat an unverifiable artifact as
verified, and MUST NOT raise an unrequested exception into the host
program on malformed input — it contains the failure and surfaces it as
a validation result.

Decryption is a **capability, not a separate class.** A verifier that
holds a group's recipient key MAY additionally decrypt that group's
contents; a verifier that does not still verifies integrity and reads
the artifact, treating each group it cannot open as opaque. The wire
requirements — recompute `row_hash`, verify the signature — are
identical in both cases.

### Artifact

A single record can be checked for conformance independent of any
implementation. An **envelope**, **manifest**, or **`.tnpkg`** is
conformant when it satisfies every structural and cryptographic MUST in
its surface spec, regardless of what produced it.

Artifact conformance is what the conformance vectors encode: each
vector is a conformant (or, for negative vectors, deliberately
non-conformant) artifact paired with its expected validation outcome.

### Transport is not an actor

A component that only moves or stores artifacts — a relay, an inbox, a
backup store — is **not** a conformance actor. It neither produces nor
verifies; it handles artifacts as opaque bytes, holds no keys, and
inspects no plaintext. The wire format is content-blind to transport by
design.

Such a component has exactly one wire obligation: it MUST preserve
artifact bytes exactly. It is not required to (and cannot, without keys)
validate what it carries; any mutation it introduces is detected and
rejected downstream, because it breaks the `row_hash` and signature a
verifier checks.

## Coverage of optional and evolving surfaces

This specification describes the complete wire format, including
surfaces an implementation MAY choose not to support (for example, a
verifier-only library need not implement body-sealing).

- A requirement marked MUST is normative for every implementation
  claiming the relevant class, whether or not a given implementation
  currently satisfies it.
- A surface an implementation MAY omit is marked OPTIONAL in its
  surface spec. Omitting an OPTIONAL surface does not forfeit
  conformance for the classes an implementation does claim.

The level of support each implementation currently provides is tracked
outside this specification, in the project's implementation notes. That
status is an engineering detail; it neither relaxes a MUST nor
weakens this document.

## Test-vector conformance

Each normative algorithm is anchored by **conformance vectors**:
language-neutral `(input, expected output)` data that an implementation
runs through its own code.

| Surface | Vector file |
|---|---|
| [Canonical bytes](./canonical-bytes.md) | `canonical_vectors.json` |
| [row_hash](./row-hash.md) | `row_hash_vectors.json` |
| [Signing](./signing.md) | `signing_vectors.json` |
| [Envelope](./envelope.md) | `envelope_vectors.json` |
| [Indexing](./indexing.md) | `index_token_vectors.json` |

Requirements:

- Every normative algorithm MUST have a conformance vector file.
- Every implementation claiming **producer** or **verifier**
  conformance MUST run the vectors for the surfaces it implements and
  MUST pass them in its own CI.
- A vector file is a shared contract. It MUST NOT encode
  implementation-private detail; an input only one language can
  represent belongs in that language's local tests, not the shared
  vectors.

## Versioning

The wire format is versioned **independently of any implementation
package**. Package releases include changes that touch zero wire bytes;
the wire version moves only when the bytes on the wire change.

The wire version is a **monotonic integer** written `wire/N`:

- It starts at **`wire/1`**, currently marked **`(draft)`**. While in
  draft the format MAY change without a version bump.
- It increments to `wire/2`, `wire/3`, … only on a change a conforming
  [verifier](#verifier) could observe: a different byte layout, a new
  required field, an altered hash or signature preimage, a changed
  cipher. There are no minor or patch components.
- The `(draft)` marker is dropped when the format is frozen. After
  that, every observable change MUST bump the integer.

Each surface file carries the stamp `Wire format: wire/1 (draft)` near
the top. A consumer MUST read the wire version before assuming
compatibility, and MUST NOT assume forward compatibility across an
integer bump.
