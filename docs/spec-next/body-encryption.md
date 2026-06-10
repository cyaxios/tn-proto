# Body Encryption Frame

Sealed `.tnpkg` packages replace plaintext body members with one member:

```text
body/encrypted.bin = 12-byte nonce || AES-256-GCM(ciphertext+tag)
```

The AES-GCM plaintext is a canonical STORED ZIP of the original body members.
AAD is empty. The signed manifest binds the ciphertext through:

```yaml
state:
  body_encryption:
    cipher_suite: aes-256-gcm
    nonce_bytes: 12
    frame: tn-encrypted-body-v2-zip
    ciphertext_sha256: sha256:<hash of body/encrypted.bin>
```

## Canonical Plaintext ZIP

SDKs must produce byte-identical plaintext ZIP bytes before encryption:

- entries sorted by full `body/...` member name
- compression method STORED
- DOS timestamp `1980-01-01 00:00:00`
- no extra fields
- no comments
- no root members outside `body/...`
- no path traversal, absolute paths, or backslash separators

The canonical ZIP writer is intentionally smaller than a general ZIP writer.
Platform ZIP libraries stamp different "made by" versions and file attributes,
which would break parity.

## Compatibility

Python still accepts the pre-2026-04-29 legacy custom binary plaintext frame
after AES-GCM decrypt. TS and Rust only accept the v2 STORED-ZIP frame.

## Current Contract Tests

- Python: `python/tests/test_body_encryption_zip.py`
- TS: `ts-sdk/test/body_encryption_contract.test.ts`
- Rust: `crypto/tn-core/tests/body_encryption_contract.rs`
