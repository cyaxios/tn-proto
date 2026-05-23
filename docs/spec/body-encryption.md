# Body encryption (sealed .tnpkg)

When a `.tnpkg` carries secrets — `project_seed`'s publisher keys,
`kit_bundle`'s recipient kits — the body is encrypted under a
**Body Encryption Key** (BEK). The BEK itself is wrapped per
recipient — see [recipient-wraps.md](./recipient-wraps.md).

Implementations: `python/tn/export.py::_encrypt_body_in_place` +
`decrypt_body_blob` is the reference. `ts-sdk/src/core/body_encryption.ts`
mirrors it. **Rust has no body encryption implementation** — Rust-only
consumers cannot read sealed bundles. See
[discrepancies.md#rust-no-body-encryption](./discrepancies.md#rust-no-body-encryption).

## Wire layout

Inside the outer tnpkg zip, the encrypted body sits at:

```text
body/encrypted.bin
```

Bytes:

```text
encrypted.bin = nonce(12) || ciphertext+tag
```

Where:

- `nonce(12)` — 12 random bytes (AES-GCM standard nonce size).
- `ciphertext+tag` — output of `AES-256-GCM.encrypt(BEK, nonce, plaintext)`
  with empty AAD. Last 16 bytes are the AEAD tag.

## Plaintext

The plaintext (inside the AEAD) is a **STORED zip** of the body
files at their original `body/<name>` keys, entries sorted by name.

Why a zip-inside-the-zip:

- Identifiable as a zip by stock tooling once decrypted (PK\x03\x04
  magic).
- Same format as the outer tnpkg, so receivers reuse their existing
  zip parser.
- STORED (no compression) keeps the format diff-able for tests.
- **Sorted entries** guarantee deterministic plaintext bytes for a
  given body — necessary for producers to compute the
  `ciphertext_sha256` integrity hash consistently.

## Manifest declaration

The sealed-body status is declared in `manifest.state.body_encryption`:

```json
{
  "cipher_suite": "aes-256-gcm",
  "nonce_bytes": 12,
  "frame": "tn-encrypted-body-v2-zip",
  "ciphertext_sha256": "sha256:<hex>",
  "recipient_wrap": { ... },           (optional; singular shadow for 1-recipient bundles)
  "recipient_wraps": [ { ... }, ... ]  (the canonical N-recipient form)
}
```

- `cipher_suite` MUST be `"aes-256-gcm"` for this frame.
- `nonce_bytes` MUST be `12`.
- `frame` MUST be `"tn-encrypted-body-v2-zip"` — distinguishes from
  the pre-2026-04-29 legacy binary frame Python still accepts but TS
  does not. See [discrepancies.md#legacy-decrypt](./discrepancies.md#legacy-decrypt).
- `ciphertext_sha256` is SHA-256 over the FULL `body/encrypted.bin`
  bytes (`nonce || ciphertext+tag`), formatted `"sha256:<hex>"`.
  This is the integrity binding — the manifest signature commits to
  this hash, so any tampering of the encrypted body fails verification
  even though the body AAD is empty.
- `recipient_wrap` is a singular shadow of `recipient_wraps[0]` for
  back-compat with single-recipient consumers; producers SHOULD emit
  both for one-recipient bundles, MUST emit `recipient_wraps[]` for
  multi-recipient.

Reference: `python/tn/export.py:846-855`,
`ts-sdk/src/core/body_encryption.ts`.

## Encryption procedure

Producer side:

1. Collect body files into a `{name: bytes}` dict.
2. Pack into a STORED zip with entries sorted by name. This is
   `plaintext`.
3. Generate a random 32-byte BEK.
4. Generate a random 12-byte nonce.
5. `ciphertext = AES-256-GCM.encrypt(BEK, nonce, plaintext, aad=b"")`.
6. `encrypted_bin = nonce || ciphertext`.
7. Write `encrypted_bin` to the outer tnpkg at `body/encrypted.bin`.
8. Compute `ciphertext_sha256 = "sha256:" + hex(SHA256(encrypted_bin))`.
9. Compute one or more recipient wraps for the BEK — see
   [recipient-wraps.md](./recipient-wraps.md).
10. Populate `manifest.state.body_encryption` with the values above.
11. Sign the manifest — see [manifest.md#signing](./manifest.md#signing).

The BEK is discarded after step 9 — only the wraps know how to
recover it.

## Decryption procedure

Consumer side:

1. Read `manifest.state.body_encryption`. If absent, the body is
   plaintext — proceed normally.
2. Verify the manifest signature — see [manifest.md](./manifest.md).
3. Walk `recipient_wraps[]` (or fall back to `recipient_wrap`),
   filter to entries whose `recipient_identity` matches OUR DID
   (derived from `seed`).
4. For each match, try `unseal_bek_from_wrap(wrap, seed, aad)`. The
   AAD is the canonical bytes of the manifest with
   `manifest_signature_b64` and `recipient_wrap[s]` removed — see
   [recipient-wraps.md#aad](./recipient-wraps.md#aad).
5. First successful unseal → BEK.
6. Read `body/encrypted.bin` from the outer zip.
7. Split: `nonce = bytes[:12]`, `ciphertext = bytes[12:]`.
8. `plaintext = AES-256-GCM.decrypt(BEK, nonce, ciphertext, aad=b"")`.
9. Verify `plaintext[:4] == b"PK\x03\x04"` (STORED-zip magic).
10. Parse the inner STORED zip → `{name: bytes}` body member map.
11. Hand the body to the kind-specific installer — `project_seed`
    writes `local.private`/`local.public`/`tn.yaml`; `identity_seed`
    likewise.

A failure at any step is a hard reject. The consumer MUST NOT install
partial state — either every step succeeds and the install proceeds,
or nothing changes on disk.

## Source pointers

| Implementation | File:line |
|---|---|
| Python (reference) | `python/tn/export.py:798` (`_encrypt_body_in_place`) + `:860` (`decrypt_body_blob`) |
| TS SDK | `ts-sdk/src/core/body_encryption.ts` |
| TS install path | `ts-sdk/src/runtime/absorb_bootstrap.ts::absorbSealedBootstrap` |
| Rust | — (none) |
