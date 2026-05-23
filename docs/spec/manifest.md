# Manifest (tnpkg)

A `.tnpkg` archive is a STORED zip containing a `manifest.json` plus
a `body/` directory. The manifest declares what the bundle is, who
signed it, and how the body is to be processed.

Implementations: `python/tn/tnpkg.py::TnpkgManifest` is the reference.
`crypto/tn-core/src/tnpkg.rs::Manifest` and
`ts-sdk/src/core/tnpkg.ts::Manifest` mirror it.

## Archive layout

```text
my_bundle.tnpkg                  (STORED zip)
├── manifest.json                (the signed manifest)
└── body/
    ├── tn.yaml                  (kind-dependent)
    ├── keys/local.private
    ├── keys/local.public
    └── ...                      (or body/encrypted.bin if sealed)
```

STORED = no compression. The producer MUST emit uncompressed; this
keeps inner zip plaintexts identifiable by the standard
`PK\x03\x04` magic for tooling.

Reference: `python/tn/tnpkg.py:246`.

## Manifest schema

```json
{
  "kind": "<kind>",
  "version": 1,
  "publisher_identity": "did:key:z...",
  "recipient_identity": "did:key:z...",         (optional; some kinds use it)
  "ceremony_id": "<string>",
  "as_of": "2026-05-22T14:30:00.123+00:00",     (ISO-8601, micro-precision)
  "scope": "admin",                              (default "admin"; "stream"/"public"...)
  "clock": { "<did>": { "<event_type>": <seq> } },  (vector clock; per kind)
  "event_count": <int>,
  "head_row_hash": "sha256:...",                 (optional; head pointer)
  "state": {                                     (kind-specific payload)
    "body_encryption": { ... },                  (only when sealed; see body-encryption.md)
    "<other kind-specific keys>"
  },
  "manifest_signature_b64": "<standard-base64>"  (Ed25519 over canonical(manifest minus signature))
}
```

### Required keys

- `kind`
- `version` (currently `1`)
- `publisher_identity`
- `ceremony_id`
- `as_of`

Plus `manifest_signature_b64` once signed.

### Optional keys

- `recipient_identity` — sender-side `to`. The wrap inside
  `state.body_encryption.recipient_wraps[]` separately addresses
  cryptographic recipients; this top-level field is a logical hint.
- `scope` — defaults to `"admin"`.
- `clock` — vector clock for kinds that need it
  (admin_log_snapshot in particular).
- `event_count` — for replay-able kinds.
- `head_row_hash` — for replay-able kinds.
- `state` — kind-specific. See below.

## Kinds

`tnpkg.json` recognises a fixed set of kinds. **There is currently
implementation disagreement on which kinds are known** — see
[discrepancies.md#manifest-kinds](./discrepancies.md#manifest-kinds).

The de-facto kind set:

| Kind | Purpose |
|---|---|
| `identity_seed` | Bootstrap a fresh device key into a clean keystore |
| `project_seed` | Bootstrap a project's publisher keys (cold-start from `TN_API_KEY`) |
| `admin_log_snapshot` | Sync admin events between vaults |
| `offer` | Bilateral read agreement |
| `enrolment` | Recipient enrollment in a publisher's groups |
| `recipient_invite` | Pre-enrollment invitation |
| `kit_bundle` | Pre-minted reader kits for one or more groups |
| `full_keystore` | Backup / wallet restore |
| `contact_update` | Contact record sync |

A consumer MAY refuse unknown kinds (Python's absorb dispatch logs
+ rejects); MUST NOT silently accept.

## Signing

The manifest is signed AFTER all other fields are populated.

1. Build the manifest object with all fields including
   `state.body_encryption.recipient_wraps[]` if sealed, but WITHOUT
   `manifest_signature_b64`.
2. Compute the canonical bytes of that object — see
   [canonical-bytes.md](./canonical-bytes.md).
3. Sign with the publisher's Ed25519 seed:
   `sig = Ed25519.sign(seed, canonical_bytes(m_unsigned))`.
4. Encode `sig` as **standard base64 with padding** (different from
   envelope signatures — see [signing.md](./signing.md#base64-encoding---two-conventions)).
5. Insert as `manifest.manifest_signature_b64`.

Reference: `python/tn/tnpkg.py:165-181`,
`ts-sdk/src/core/tnpkg.ts::signManifest`.

## Verification

A consumer:

1. Reads `manifest.json` from the archive.
2. Pops `manifest_signature_b64` into a local variable.
3. Computes canonical bytes of the remaining manifest.
4. Verifies the signature against `publisher_identity`'s public key.
5. (For sealed bundles) walks `state.body_encryption.recipient_wraps[]`
   to find a wrap addressed to its DID — see
   [recipient-wraps.md](./recipient-wraps.md).
6. (For sealed bundles) recovers the BEK and decrypts
   `body/encrypted.bin` — see
   [body-encryption.md](./body-encryption.md).
7. Dispatches the kind-specific install path (`identity_seed` writes
   `local.private`/`local.public`/`tn.yaml`; `project_seed` writes the
   publisher's keys; etc.).

A signature failure is a hard reject. An unknown kind is a hard
reject. A wrap-not-addressed-to-us is NOT a tampering signal — the
bundle wasn't for us; surface a clear "not for me" reason.

## Source pointers

| Implementation | File:line |
|---|---|
| Python (reference) | `python/tn/tnpkg.py:88` |
| Rust core | `crypto/tn-core/src/tnpkg.rs:93` |
| TS SDK | `ts-sdk/src/core/tnpkg.ts:56` |
