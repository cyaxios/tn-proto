# TN Package Container

`.tnpkg` is the package communication unit for absorb, wallet sync, vault
transfer, reader kits, and project bootstrap.

The container is a ZIP archive. ZIP byte layout does not need to be stable, but
the logical member model does.

## Required Members

Every package has exactly one top-level manifest:

```text
manifest.json
```

Every other member is package body content and must live under:

```text
body/...
```

High-level `.tnpkg` readers and writers reject:

- missing or duplicate `manifest.json`
- root members other than `manifest.json`
- empty `body/`
- absolute paths
- `.` or `..` path segments
- backslash path separators

The low-level browser ZIP parser may remain generic. The `.tnpkg` reader/writer
layer enforces TN package structure.

## Manifest Trust Boundary

Readers parse `manifest.json` first, then parse the body index. Signature
verification is a separate explicit step today, but package-consuming verbs
must verify the manifest before trusting package body semantics.

Manifest signing bytes are the canonical manifest JSON with
`manifest_signature_b64` removed. See `docs/spec-next/manifest.md`.
Sealed packages use `body/encrypted.bin`; see
`docs/spec-next/body-encryption.md`.

## Sealed Package Shape

When a package body is encrypted, the outer `.tnpkg` body has exactly one
member:

```text
body/encrypted.bin
```

The outer ZIP must not expose plaintext package members such as
`body/default.btn.mykit`, `body/keys/local.private`, `body/tn.yaml`, or stream
YAML files. Those members are inside the encrypted inner body ZIP.

The manifest carries `state.body_encryption` with:

- `frame: "tn-encrypted-body-v2-zip"`
- `cipher_suite: "aes-256-gcm"`
- `nonce_bytes: 12`
- `ciphertext_sha256: "sha256:<hex sha256 of body/encrypted.bin>"`

Recipient-addressed sealed packages additionally carry
`recipient_wraps[]` in that same block, plus the legacy singular
`recipient_wrap` shadow when there is exactly one recipient. BYOK packages
such as init-upload do not carry recipient wraps because the BEK travels out
of band.

## Body Index

Body members are indexed by their full logical ZIP name, including the `body/`
prefix:

```text
body/admin.ndjson
body/tn.yaml
body/keys/local.private
body/encrypted.bin
```

Kind-specific handlers decide which body members are required or forbidden.
The container layer only enforces the root boundary and path safety.

## Application Logs

Application logs are not project backup content. A `project_seed` or future
project snapshot package must not include stream output such as:

```text
body/logs/default.ndjson
body/streams/api/logs/default.ndjson
```

See `docs/spec-next/project-backup.md` for the backup scope rule.

## Current Contract Tests

- Python: `python/tests/test_tnpkg_container_contract.py`
- Python sealed package shape: `python/tests/test_sealed_tnpkg_package_contract.py`
- TS: `ts-sdk/test/tnpkg_container_contract.test.ts`
- TS sealed package shape: `ts-sdk/test/init_upload.test.ts`
- Rust: `crypto/tn-core/tests/tnpkg_container_contract.rs`
