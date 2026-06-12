# Manifest (tnpkg)

A `.tnpkg` archive is a STORED (uncompressed) zip containing a
`manifest.json` plus a `body/` directory. The manifest declares what
the bundle is, who signed it, and how the body is processed.

Requirement keywords are normative per [conformance.md](./conformance.md).

Wire format: **wire/1 (draft)**.

## Archive layout

```text
bundle.tnpkg                     (STORED zip)
├── manifest.json                (the signed manifest)
└── body/
    ├── tn.yaml                  (kind-dependent)
    ├── keys/local.private
    ├── keys/local.public
    └── …                        (or body/encrypted.bin if sealed)
```

The archive MUST be STORED (no compression). This keeps inner zip
plaintexts identifiable by the standard `PK\x03\x04` magic.

## Manifest schema

```json
{
  "kind": "<kind>",
  "version": 1,
  "publisher_identity": "did:key:z...",
  "recipient_identity": "did:key:z...",
  "ceremony_id": "<string>",
  "as_of": "2026-05-22T14:30:00.123+00:00",
  "scope": "admin",
  "clock": { "<did>": { "<event_type>": <seq> } },
  "event_count": <int>,
  "head_row_hash": "sha256:...",
  "state": { "<kind-specific payload>" },
  "manifest_signature_b64": "<standard-base64>"
}
```

### Required keys

`kind`, `version` (currently `1`), `publisher_identity`,
`ceremony_id`, `as_of`, and — once signed — `manifest_signature_b64`.

### Optional keys

- `recipient_identity` — a logical addressing hint. Cryptographic
  recipients are addressed separately by the wraps in
  `state.body_encryption.recipient_wraps[]` (see
  [recipient-wraps.md](./recipient-wraps.md)).
- `scope` — defaults to `"admin"`.
- `clock` — a vector clock, for kinds that replay.
- `event_count`, `head_row_hash` — for replayable kinds.
- `state` — kind-specific payload, including `body_encryption` when the
  bundle is sealed (see [body-encryption.md](./body-encryption.md)).

## Kinds

`kind` MUST be one of the recognized values below. A verifier MUST
reject an unknown kind; it MUST NOT silently accept it.

| Kind | Purpose |
|---|---|
| `identity_seed` | Bootstrap a fresh device key into a clean keystore |
| `project_seed` | Bootstrap a project's publisher keys (cold start) |
| `admin_log_snapshot` | Sync admin events between vaults |
| `offer` | Bilateral read agreement |
| `enrolment` | Recipient enrollment in a publisher's groups |
| `recipient_invite` | Pre-enrollment invitation |
| `kit_bundle` | Pre-minted reader kits for one or more groups |
| `full_keystore` | Backup / wallet restore |
| `contact_update` | Contact record sync |

## Signing

The manifest is signed after all other fields are populated:

1. Build the manifest object with every field — including
   `state.body_encryption.recipient_wraps[]` when sealed — but WITHOUT
   `manifest_signature_b64`.
2. Compute the [canonical bytes](./canonical-bytes.md) of that object.
3. Sign: `sig = Ed25519.sign(seed, canonical_bytes(m_unsigned))`.
4. Encode `sig` as **standard base64 with padding** (distinct from
   envelope signatures — see [signing.md](./signing.md#base64-encodings)).
5. Set `manifest_signature_b64` to that string.

## Verification

A verifier MUST:

1. Read `manifest.json` from the archive.
2. Remove `manifest_signature_b64` and retain it.
3. Compute the canonical bytes of the remaining manifest.
4. Verify the signature against `publisher_identity`'s public key.
5. For a sealed bundle, locate a wrap addressed to its DID in
   `state.body_encryption.recipient_wraps[]` (see
   [recipient-wraps.md](./recipient-wraps.md)), recover the BEK, and
   decrypt `body/encrypted.bin` (see
   [body-encryption.md](./body-encryption.md)).
6. Dispatch the kind-specific install path.

A signature failure MUST be a hard reject. An unknown kind MUST be a
hard reject. A bundle whose wraps are not addressed to the verifier is
**not** a tampering signal — the bundle was not meant for this
recipient, and the verifier MUST surface a clear "not addressed to me"
outcome rather than a verification error.
