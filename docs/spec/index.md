# TN wire protocol

This directory is the authoritative specification of the TN wire
protocol: the bytes that producers emit and verifiers validate.
Implementations conform to this specification; where an implementation
and the spec disagree, the spec governs.

The format is defined in language-neutral terms. It is exercised by
implementations in Rust (`crypto/tn-core/`, with a wasm build for the
browser and TypeScript), Python, and the TypeScript SDK.

Wire format: **wire/1 (draft)**.

## Reading order

1. [**Conformance**](./conformance.md) — what it means to conform: the
   requirement keywords, the conformance classes, and the
   conformance-vector contract. Read this first.
2. [**Canonical bytes**](./canonical-bytes.md) — the JSON encoding rule
   everything else stands on.
3. [**Signing**](./signing.md) — Ed25519, `did:key:z…`, the base64
   conventions.
4. [**Envelope**](./envelope.md) — the wire shape of an attested event.
5. [**row_hash**](./row-hash.md) — the chain-link hash inside each
   envelope.
6. [**Indexing**](./indexing.md) — equality tokens over encrypted
   fields.
7. [**Manifest**](./manifest.md) — `.tnpkg` archive metadata and
   signature.
8. [**Body encryption**](./body-encryption.md) — AES-256-GCM sealed
   bodies.
9. [**Recipient wraps**](./recipient-wraps.md) — ECDH + HKDF + AES-GCM
   BEK seal.

## Conventions

The requirement keywords (MUST, SHOULD, MAY, …) are defined in
[conformance.md](./conformance.md#requirement-keywords) and interpreted
per RFC 2119.

Field names are **wire names** — snake_case as they appear in JSON. An
implementation that uses a different internal casing (for example
camelCase in TypeScript) MUST map to and from these wire names at its
serialization boundary.

## Versioning

The wire format carries an independent version, `wire/N`, defined in
[conformance.md](./conformance.md#versioning). It is decoupled from any
implementation package version and bumps only when the bytes on the
wire change. It is currently `wire/1 (draft)`.

## What this spec is not

- **Not a tutorial.** SDK how-tos live in each implementation's own
  documentation.
- **Not an API reference.** This spec defines what is on the wire, not
  the language-level surface of any SDK.
