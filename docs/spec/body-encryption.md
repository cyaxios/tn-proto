# Body encryption (sealed .tnpkg)

When a `.tnpkg` carries secrets — a `project_seed`'s publisher keys, a
`kit_bundle`'s recipient kits — the body is encrypted under a **Body
Encryption Key** (BEK). The BEK is itself wrapped per recipient (see
[recipient-wraps.md](./recipient-wraps.md)).

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Wire layout

Inside the outer `.tnpkg` zip, the encrypted body is a single member:

```text
body/encrypted.bin = nonce(12) || ciphertext+tag
```

- `nonce(12)` — 12 bytes (AES-GCM standard nonce size).
- `ciphertext+tag` — the output of
  `AES-256-GCM.encrypt(BEK, nonce, plaintext)` with empty AAD; the last
  16 bytes are the AEAD tag.

## Plaintext

The plaintext inside the AEAD MUST be a **STORED zip** of the body
files at their original `body/<name>` keys, with **entries sorted by
name**.

Sorted entries are REQUIRED: they make the plaintext bytes
deterministic for a given body, which is what lets a producer compute a
stable `ciphertext_sha256`. The STORED-zip framing also keeps the
decrypted plaintext identifiable by the `PK\x03\x04` magic and reusable
by the same zip parser as the outer archive.

## Manifest declaration

A sealed body is declared in `manifest.state.body_encryption`:

```json
{
  "cipher_suite": "aes-256-gcm",
  "nonce_bytes": 12,
  "frame": "tn-encrypted-body-v2-zip",
  "ciphertext_sha256": "sha256:<hex>",
  "recipient_wrap": { },
  "recipient_wraps": [ { } ]
}
```

- `cipher_suite` MUST be `"aes-256-gcm"`.
- `nonce_bytes` MUST be `12`.
- `frame` MUST be `"tn-encrypted-body-v2-zip"`.
- `ciphertext_sha256` MUST be the SHA-256 over the **full**
  `body/encrypted.bin` bytes (`nonce || ciphertext+tag`), formatted
  `"sha256:<hex>"`. This is the integrity binding: the manifest
  signature commits to this hash, so any tampering of the encrypted
  body fails manifest verification even though the body AAD is empty.
- `recipient_wraps` is the canonical N-recipient form and MUST be
  present. `recipient_wrap` is an OPTIONAL singular shadow of
  `recipient_wraps[0]`; a producer SHOULD emit it for single-recipient
  bundles so older consumers can still unseal.

## Encryption procedure (producer)

1. Collect the body files into a `{name: bytes}` map.
2. Pack them into a STORED zip with entries sorted by name — the
   `plaintext`.
3. Generate a random 32-byte BEK.
4. Generate a random 12-byte nonce.
5. `ciphertext = AES-256-GCM.encrypt(BEK, nonce, plaintext, aad="")`.
6. `encrypted_bin = nonce || ciphertext`.
7. Write `encrypted_bin` to the outer archive at `body/encrypted.bin`.
8. `ciphertext_sha256 = "sha256:" + hex(SHA256(encrypted_bin))`.
9. Compute one [recipient wrap](./recipient-wraps.md) of the BEK per
   recipient.
10. Populate `manifest.state.body_encryption`.
11. Sign the manifest (see [manifest.md](./manifest.md#signing)).

After step 9 the BEK MUST be discarded; only the wraps can recover it.

## Decryption procedure (consumer)

1. Read `manifest.state.body_encryption`. If absent, the body is
   plaintext; proceed normally.
2. Verify the manifest signature (see [manifest.md](./manifest.md)).
3. Select the wraps whose `recipient_identity` matches the verifier's
   DID.
4. For each, attempt to unseal the BEK using the verifier's seed and
   the wrap AAD (see [recipient-wraps.md](./recipient-wraps.md#aad)).
5. On the first successful unseal, take the BEK.
6. Read `body/encrypted.bin`; split `nonce = bytes[:12]`,
   `ciphertext = bytes[12:]`.
7. `plaintext = AES-256-GCM.decrypt(BEK, nonce, ciphertext, aad="")`.
8. Verify `plaintext[:4] == PK\x03\x04`.
9. Parse the inner STORED zip into the body member map.
10. Hand the body to the kind-specific installer.

Any failure MUST be a hard reject, and the install MUST be atomic: the
consumer MUST NOT write partial state. Either every step succeeds and
the install proceeds, or nothing changes on disk.
