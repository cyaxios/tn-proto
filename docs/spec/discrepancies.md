# Implementation discrepancies

Known drifts between the Python, Rust, and TS implementations. This
page is the **acknowledgment of imperfection** — the spec calls these
out so new implementations don't accidentally pick the wrong side.

Each entry: what differs, where, why it matters, and the
spec-preferred behavior. When the spec preference says "Python wins"
(or "Rust wins" or "TS wins"), that's the canonical answer for new
implementations.

Open at the top, fixed-side at the bottom.

---

## OPEN — drift to resolve

### canonical-bytes-public-api

**Python exports the canonicalization primitives as PRIVATE** (`_canonical_bytes`, `_compute_row_hash`, `_signature_b64`, `_derive_group_index_key`, `_index_token`). **Rust/wasm exposes them as PUBLIC** (`canonicalBytes`, `computeRowHash`, ...). The cross-check test `crypto/tn-wasm/test/py_cross_check.py:54-57` imports the unprefixed Python names — those don't exist; the test would error.

**Spec preference**: PUBLIC. Other ports (Go, Java) MUST expose these as part of their public surface; Python's underscore convention reflects implementation-detail anxiety that hasn't aged well. Track unprefixing in Python as a follow-up.

**Sources**: `python/tn/canonical.py:60`, `crypto/tn-wasm/src/lib.rs:327`, `crypto/tn-wasm/test/py_cross_check.py:54-57`.

### manifest-kinds

The set of recognized [manifest kinds](./manifest.md#kinds) differs across implementations:

| Implementation | Recognised kinds | Missing |
|---|---|---|
| Python `tnpkg.py::KNOWN_KINDS` | 8 (incl. `identity_seed`) | `project_seed` |
| Rust `ManifestKind` enum | 7 | `identity_seed`, `project_seed` |
| TS `ManifestKind` type | 7 | `identity_seed`, `project_seed` |
| TS runtime accepted (in `absorb_bootstrap.ts`) | + `identity_seed`, `project_seed` | — |
| Python code paths | + `project_seed` (in absorb, not in KNOWN_KINDS) | — |

In practice all three implementations handle `identity_seed` and `project_seed`, but the type-level recognition lags. A Rust-only consumer cannot process these kinds at all.

**Spec preference**: include `identity_seed` and `project_seed` in every implementation's kind enum. Track adding them to Python's `KNOWN_KINDS` and the Rust + TS type unions.

**Sources**: `python/tn/tnpkg.py:64`, `crypto/tn-core/src/tnpkg.rs:48-61`, `ts-sdk/src/core/tnpkg.ts:29-49`.

### rust-no-body-encryption

**Rust has no body-encryption module.** Sealed `.tnpkg` bundles
(`state.body_encryption.recipient_wraps[]` + AES-GCM body) can be
produced and consumed by Python and TS, but a Rust-only consumer
cannot decrypt them. The Rust core has `tnpkg.rs` for manifests but
no equivalent of `body_encryption.ts`.

**Spec preference**: port to Rust. The body cipher itself (AES-256-GCM,
12-byte nonce, empty AAD, STORED-zip plaintext) is straightforward;
recipient wraps (Ed25519 → X25519 birational map + HKDF + AES-GCM)
need the `curve25519-dalek` + `ed25519-dalek` crates which already
exist in the Cargo workspace.

This is the single biggest cross-implementation drift today.

**Sources**: `python/tn/export.py:798`, `ts-sdk/src/core/body_encryption.ts`, `crypto/tn-core/src/` (nothing).

### legacy-decrypt

Python's `decrypt_body_blob` accepts a **pre-2026-04-29 legacy binary
frame** as a fallback when the AES-GCM-decrypted plaintext doesn't
start with the `PK\x03\x04` STORED-zip magic. TS explicitly REFUSES
this fallback ("Pre-2026-04-29 legacy binary frame is not supported
on the TS side."). Rust has no body decrypt at all.

**Spec preference**: the legacy frame is dead — Python should drop it
after the next "state wipe" (Python's TODO comment). Existing legacy
bundles should be re-sealed once. TS's refusal is correct.

**Sources**: `python/tn/export.py:888-899`, `ts-sdk/src/core/body_encryption.ts:233-247`.

### secp256k1-verify

Python's `DeviceKey.verify` accepts secp256k1 DIDs (`0xe7 0x01`
multicodec) for ATProto interop. Rust's `verify_did` returns
`Ok(false)` for the same input without erroring. TS delegates to
wasm — same behavior as Rust.

**Spec preference**: secp256k1 support is OPTIONAL. Implementations
MAY accept it for ATProto interop; MUST NOT error on encountering it
(return false / unverified is the right move). Document the
implementation's choice prominently.

**Sources**: `python/tn/signing.py:177-191`, `crypto/tn-core/src/signing.rs:6, 90`.

### env-truthiness

**The Python codebase has FOUR different truthiness conventions** across
the TN_* env-var set. See [env-vars.md#truthiness-conventions--summary](./env-vars.md#truthiness-conventions--summary)
for the full list.

**Spec preference**: new env vars MUST use the strict-mode convention —
`raw.strip().lower() in {"1", "true", "yes", "on"}`. Existing
variables stay on their original conventions for back-compat. The TS
SDK matches Python's per-variable convention exactly; new ports MUST
do the same to avoid silent behavior drift.

**Sources**: `python/tn/_autoinit.py:71` (strict pattern); `python/tn/logger.py:451, 578` + `python/tn/handlers/stdout.py:219` + `python/tn/admin/__init__.py:615` (exact "1"); `python/tn/reader.py:42` (`{"1","true","True"}`).

### row-hash-bytes

If a publisher puts `bytes` values into a public field (which the
envelope JSON shouldn't carry but the row_hash input might), Python
writes the raw bytes verbatim into the hash input. Rust has no
`Value::Bytes` variant; bytes would have to come in via the JSON
fallback (impossible in practice).

**Spec preference**: public fields are JSON-shaped — strings,
numbers, bools, null, arrays, objects. Raw `bytes` are NOT a valid
public field type. Implementations MAY reject at encode time. The
Python "raw bytes verbatim" path is a footgun.

**Sources**: `python/tn/chain.py:96`, `crypto/tn-core/src/chain.rs:112-125`.

### project-seed-recognition

Closely related to `manifest-kinds` above: `project_seed` is the
de-facto cold-start kind for the API-key flow, but its formal
recognition differs across implementations.

**Spec preference**: officialize `project_seed` in every kind enum
+ formally distinguish from `identity_seed` (which addresses a
different operator). See `manifest-kinds`.

### body-stored-zip-determinism

The inner STORED-zip plaintext inside `body/encrypted.bin` MUST
have sorted entries by name (otherwise the `ciphertext_sha256`
hash is non-deterministic and producer/consumer can't agree).
Python sorts (`export.py:835`); TS sorts (`body_encryption.ts:104`).
**Neither the manifest nor the spec previously documented this
requirement.**

**Spec preference**: this spec now declares it MANDATORY (see
[body-encryption.md#plaintext](./body-encryption.md#plaintext)). New
implementations MUST sort.

**Sources**: `python/tn/export.py:835`, `ts-sdk/src/core/body_encryption.ts:104`.

### signature-base64-split

[signing.md#base64-encoding---two-conventions](./signing.md#base64-encoding---two-conventions)
documents that envelope signatures use URL-safe-no-pad while
manifest signatures use standard-with-pad. The split is
intentional (the wire-shape historical reasoning is recorded in
the design docs), but it's a frequent source of producer bugs.

**Spec preference**: tooling SHOULD provide separate
`signatureB64` / `manifestSignatureB64` helpers so callers don't
mix them up. The TS SDK does (`signatureB64` from `@tnproto/sdk`
vs `manifest.manifest_signature_b64` set by `signManifest`); the
Python SDK uses `_signature_b64` and `tnpkg.sign_manifest` —
distinct enough.

**Sources**: `python/tn/signing.py:197`, `python/tn/tnpkg.py:181`,
`ts-sdk/src/core/signing.ts`.

---

## CLOSED — fixed on `js-browser-tn`

These were drifts at the start of the `js-browser-tn` work and are
now resolved (in PR #78 + dependents). Listed for completeness.

### identity-field-rename

The 0.4.3a1 rename `did` -> `device_identity` (envelope) and
`publisher_identity` (manifest) was incomplete: the Chrome
extension's vendored `Entry.js` still had the old `did` name.
Fixed in PR #80.

**Source**: `extensions/tn-decrypt/vendor/sdk-core/Entry.js`.

### ts-node-wasm-init

The Node TS SDK had no wasm-init step, leaving 190 of 296 tests
failing with `Cannot read properties of undefined (reading
'__wbindgen_malloc')`. Fixed in PR #78 commit 9fac2fa via
`src/runtime/_node_wasm_init.ts`.

### ts-run-id-stamp

Node TS didn't stamp `process.env.TN_RUN_ID` before wasm init, so
the JS + wasm sides emitted mismatched `run_id`s and
`wasm.read()`'s current-run filter dropped every entry. Fixed in
PR #78 commit 3e6eaae via `src/_run_id.ts::ensureProcessRunId` +
the `attachWasm` hook.

### ts-env-var-parity

The Node TS SDK was silently ignoring `TN_STRICT`,
`TN_STDOUT_INCLUDE_ADMIN`, `TN_VAULT_URL`, `TN_VAULT_DEFAULT_BASE`,
`TN_NO_LINK`, `TN_API_KEY`. Fixed in PR #78 commits 3e6eaae,
1954800, c3fe8a2.

### ci-swallowed-failures

`.github/workflows/ci.yml::ts-tests` had `npm test || true`,
silently swallowing failures. Fixed in PR #79.

### chrome-extension-vendor-stale

The Chrome extension's vendored sdk-core slice was stale relative
to the SDK. Fixed in PR #80 + CI guard now catches future drift.

---

## How to add a new entry

When a new drift is discovered:

1. Add a section under "OPEN — drift to resolve".
2. Include: what differs (with file:line evidence from each
   implementation), why it matters operationally, and the
   spec-preferred behavior.
3. Cross-link from the relevant spec section (e.g. body-encryption.md
   links to `discrepancies.md#rust-no-body-encryption`).
4. When the drift is resolved, move the entry to "CLOSED" with the
   fixing PR reference.
