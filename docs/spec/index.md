# TN protocol spec

This directory is the **single source of truth** for the TN wire
protocol. Libraries are conformant implementations; when a library
and the spec disagree, the spec wins.

Today there are three implementations:

| Side | Language | Source |
|---|---|---|
| Python | `python/tn/` | The original; widest verb surface |
| Rust core | `crypto/tn-core/` | Performance-critical primitives |
| Rust wasm | `crypto/tn-wasm/` | Browser + TS-via-pkg consumption |
| TS SDK (Node) | `ts-sdk/src/` | Node consumers, wraps tn-wasm |
| TS SDK (browser) | `ts-sdk/src/browser/` | Browser bundle |

Where they agree, this spec records the agreement. Where they
disagree, see [`discrepancies.md`](./discrepancies.md) — every known
drift is named, with file:line evidence, so spec-faithful new
implementations don't pick the wrong side by accident.

## Reading order

For new implementers, top-to-bottom:

1. [**Canonical bytes**](./canonical-bytes.md) — the JSON encoding rule everything else stands on.
2. [**Signing**](./signing.md) — Ed25519, `did:key:z…`, the two base64 conventions.
3. [**Envelope**](./envelope.md) — the wire shape of an attested event.
4. [**row_hash**](./row-hash.md) — the chain-link hash inside each envelope.
5. [**Manifest**](./manifest.md) — `.tnpkg` archive metadata + signature.
6. [**Body encryption**](./body-encryption.md) — AES-256-GCM sealed bodies.
7. [**Recipient wraps**](./recipient-wraps.md) — ECDH + HKDF + AES-GCM BEK seal.
8. [**Vault HTTP**](./vault-http.md) — the REST endpoints clients talk to.
9. [**Env vars**](./env-vars.md) — `TN_*` runtime configuration knobs.
10. [**Discrepancies**](./discrepancies.md) — known implementation drift; read before writing a new port.

## Conventions

Throughout this spec:

- **MUST / MUST NOT** — required for conformance. A claim that an
  implementation is "TN-conformant" implies it follows every MUST.
- **SHOULD / SHOULD NOT** — strongly recommended; deviations are
  legal but the implementation must document them prominently.
- **MAY** — explicitly allowed variation.

Field names are **wire names** (snake_case for JSON, matches Python).
TS uses camelCase internally; when this spec says `device_identity`,
TS code reads it via `manifest.fromDid` after the
`fromWireDict`/`toWireDict` rename layer.

## Golden vectors

Canonical-bytes correctness is anchored by
`crypto/tn-core/tests/fixtures/canonical_vectors.json` — every
implementation MUST produce identical bytes for every vector. The
Rust test `crypto/tn-core/tests/canonical_golden.rs` runs the vectors;
the Python+TS implementations exercise them via
`crypto/tn-wasm/test/py_cross_check.py` and
`ts-sdk/test/tn_py_helper.py`.

When a new section of this spec lands a behavioral claim, the test
fixtures get extended in lockstep.

## What this spec is NOT

- **Not a tutorial.** See `ts-sdk/docs/api-quick-reference.md` for
  the SDK how-tos and the README files in each implementation for
  worked examples.
- **Not version-locked.** When the protocol changes, this spec
  changes; consumers MUST read the spec version (top of each section)
  before assuming compatibility.
- **Not an API reference.** TSDoc on each public symbol + Python
  docstrings cover the language-level surfaces. This spec defines
  what's on the wire.

Spec version: **0.4.3a3** (covers the wire format as of
`js-browser-tn` branch / PRs #78 #79 #80).
