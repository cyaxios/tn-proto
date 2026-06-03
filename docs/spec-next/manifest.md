# Manifest Contract

This is the next contract for `.tnpkg` manifests. It is intentionally small
and fixture-driven so Python, TS/JS, Rust, and WASM can converge without
reinterpreting the package format independently.

## Wire Shape

A manifest is a JSON object stored at the root of a `.tnpkg` as
`manifest.json`.

Required fields:

- `kind`: string package discriminator
- `version`: integer manifest schema version
- `publisher_identity`: DID of the signing device
- `ceremony_id`: protocol/runtime id for the package source
- `as_of`: ISO/RFC3339 timestamp string

Optional fields with defaults:

- `scope`: string, default `"admin"`
- `clock`: object, default `{}`
- `event_count`: integer, default `0`
- `recipient_identity`: string
- `head_row_hash`: string
- `state`: object
- `manifest_signature_b64`: standard base64 Ed25519 signature

Optional fields are omitted from canonical output when unset. `null` optional
fields are treated as absent unless a future fixture says otherwise.

## Known Kinds

The shared v1 catalog is:

- `admin_log_snapshot`
- `offer`
- `enrolment`
- `recipient_invite`
- `kit_bundle`
- `full_keystore`
- `contact_update`
- `identity_seed`
- `project_seed`

All SDK type catalogs must include this exact list. Runtime policy for unknown
kinds can be revisited later; for this slice, typed parsers should reject
unknown kinds and loose/inspection readers may preserve the raw string only
when they are explicitly documented as inspection-only.

## Signing Bytes

`manifest_signature_b64` is never part of the signing domain.

Signing bytes are:

1. Convert manifest to the snake_case wire JSON object.
2. Remove `manifest_signature_b64` if present.
3. Omit unset optional fields.
4. Canonicalize JSON with sorted object keys and compact separators.
5. UTF-8 encode the canonical JSON text.

The fixture
`tests/fixtures/manifest/project_seed_unsigned.json` and expected bytes in
`tests/fixtures/manifest/project_seed_unsigned.canonical.hex` are the first
cross-language golden for this rule.

The signed fixture `tests/fixtures/manifest/project_seed_signed.json` uses the
deterministic Ed25519 seed
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.
`project_seed_signed.canonical.hex` is the signature domain. Every
implementation must verify that signature and reject any mutation of signed
fields.

## Signature

Manifest signatures are Ed25519 over the signing bytes.

`manifest_signature_b64` uses standard base64 with padding. This differs from
envelope row signatures, which may use URL-safe no-padding encoding.

Verification must happen before trusting package body contents.

## First-Slice Acceptance

Python, TS/JS, and Rust must all:

- expose the same known-kind catalog
- parse the shared `project_seed` fixture
- produce the exact fixture canonical bytes
- strip `manifest_signature_b64` from signing bytes
- verify the signed fixture and reject tampering
- reject missing required fields
