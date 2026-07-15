# JWKS Trust in TN

JWKS is a standard JSON format for publishing public keys. In TN, it is useful
when one project, vault, account, or service needs to tell another party:

> These are the public keys I currently advertise.

JWKS by itself does not answer:

> Why should you trust these keys?

TN treats JWKS as public key discovery, not as a source of truth. Trust still
comes from a local decision: a pinned fingerprint, an admin-approved rotation,
or another authenticated channel. Once a JWKS is trusted, TN can use its public
encryption key with JWE and record which key was selected in the signed log.

## Where It Fits

TN already has ceremony YAML, local keystores, signed log entries, admin replay,
and cipher-specific key material. JWKS does not replace those pieces.

Instead, JWKS gives TN a standards-friendly way to publish public keys at the
edge of the system:

- A vault can publish public encryption keys so clients can send vault-bound
  packages.
- A project can export public keys so another service can encrypt a handoff
  package back to it.
- An account or device can publish public signing keys for verification flows.

Private keys stay in the local TN keystore or vault infrastructure. A JWKS
document should contain only public key material.

## Key Types

A TN JWKS can contain signing keys and encryption keys.

Signing keys are Ed25519 keys used for signatures and metadata verification:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "kid": "project-signing-2026-07",
  "use": "sig",
  "alg": "EdDSA",
  "x": "..."
}
```

Encryption keys are X25519 keys used as JWE recipients:

```json
{
  "kty": "OKP",
  "crv": "X25519",
  "kid": "default-jwe-current",
  "use": "enc",
  "alg": "ECDH-ES+A256KW",
  "x": "..."
}
```

The `kid` is important. When TN seals with JWE, the recipient header can include
the selected key ID, which lets the receiver identify the intended private key
without guessing indefinitely.

## TN JWKS Shape

TN uses normal JWKS key objects with a few TN-friendly metadata fields:

```json
{
  "issuer": "did:key:zVault...",
  "issued_at": "2026-07-14T00:00:00Z",
  "expires_at": "2026-08-14T00:00:00Z",
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "vault-signing-2026-07",
      "use": "sig",
      "alg": "EdDSA",
      "x": "...",
      "tn_status": "active"
    },
    {
      "kty": "OKP",
      "crv": "X25519",
      "kid": "vault-enc-2026-07",
      "use": "enc",
      "alg": "ECDH-ES+A256KW",
      "x": "...",
      "tn_status": "active",
      "tn_fingerprint": "sha256:..."
    }
  ]
}
```

Useful fields:

- `issuer`: stable identity for the vault, account, project, or device.
- `issued_at`: when the key set was issued.
- `expires_at`: when consumers should refresh or stop accepting the key set.
- `tn_status`: `active`, `retiring`, or `retired`.
- `tn_fingerprint`: a canonical fingerprint for one public key.

TN also computes a document fingerprint for the whole JWKS. That document
fingerprint is what gets pinned in local configuration.

## Trust Model

The safe default is explicit pinning.

1. Fetch or receive the JWKS.
2. Inspect its issuer and fingerprint without trusting it yet.
3. Compare those values with an authenticated source, such as a vault dashboard,
   a secure admin channel, or an out-of-band approval.
4. Pin the exact issuer and JWKS fingerprint.
5. Only then select an active encryption key and seal with JWE.

This keeps the important question visible:

> Is this the key set I meant to trust?

Encryption proves that only the holder of the matching private key can decrypt.
It does not prove that the public key belongs to the party you intended.

The TypeScript trust evaluator currently supports `tofu` and `pinned` policies.
The `hosted` and `did_bound` policy names are reserved for future vault/DID
trust roots and intentionally fail closed until those roots are implemented.

## Local Pin Cache

For vaults, the local pinned JWKS lives in `tn.yaml` under `vault.jwks`:

```yaml
vault:
  enabled: true
  url: https://vault.example
  jwks:
    issuer: did:key:zVault...
    url: https://vault.example/.well-known/tn/jwks.json
    fingerprint: sha256:...
    pinned_at: 2026-07-14T00:00:00Z
```

This YAML section is a fast local cache. It lets SDKs know where to fetch the
key set and what fingerprint to expect. It is intentionally paired with signed
admin events:

- `tn.jwks.pinned`
- `tn.jwks.rotated`

The stronger model is hybrid: YAML stores the operational cache, while admin
replay is used to detect if someone manually changed the YAML without a signed
trust event.

## Vault Flow

A typical vault-bound flow looks like this:

1. The client fetches the vault JWKS.
2. The client computes the issuer and JWKS fingerprint.
3. An operator verifies those values against the vault dashboard.
4. The project records `vault.jwks` and emits `tn.jwks.pinned`.
5. When sending a vault package, the SDK fetches the JWKS again and confirms
   that it still matches the pin.
6. The SDK selects the single active `use: "enc"` key.
7. The payload is sealed with JWE.
8. TN records `tn.jwks.key_selected` so later audits can explain which key
   protected the package.

When the JWKS key is being used to activate a JWE recipient, the trusted JWKS
selection should be converted into TN's normal verified JWE recipient binding.
That keeps package preparation, admin registration, and audit replay on the
same trust model used by DID-document, accepted-offer, and fingerprint-pin
flows.

Example CLI:

```powershell
tn-js vault jwks inspect --url https://vault.example/.well-known/tn/jwks.json
```

```powershell
tn-js vault jwks pin --yaml .tn/demo/tn.yaml `
  --issuer did:key:zVault... `
  --url https://vault.example/.well-known/tn/jwks.json `
  --fingerprint sha256:...
```

```powershell
tn-js vault jwks rotate --yaml .tn/demo/tn.yaml `
  --issuer did:key:zVault... `
  --url https://vault.example/.well-known/tn/jwks.json `
  --fingerprint sha256:new... `
  --previous sha256:old...
```

`inspect` is read-only. `pin` and `rotate` fetch the JWKS and verify it matches
the supplied issuer/fingerprint before writing YAML or admin events.

## Project-to-Project Sharing

JWKS is also useful without a vault.

For example, AuditCo can publish a public JWKS so a partner service can encrypt
a handoff package back to AuditCo:

1. AuditCo exports public key material from its TN project.
2. AuditCo shares the JWKS file or hosts it at a stable URL.
3. The partner verifies the issuer and fingerprint through an authenticated
   channel.
4. The partner seals the handoff package to AuditCo's active JWE encryption key.
5. AuditCo decrypts with its local private `<group>.jwe.mykey`.

Exporting public keys:

```powershell
tn-js jwks export --yaml .tn/auditco/tn.yaml `
  --include-encryption `
  --group default `
  --out auditco-public-jwks.json `
  --json
```

Without `--include-encryption`, the command exports only the local Ed25519
public signing key. With `--include-encryption`, it derives the public X25519
key from the local JWE private reader key and exports only the public half.

The private key never appears in the JWKS.

## What Gets Recorded

When a trusted JWKS key is used for encryption, TN should record enough public
metadata to explain the decision later.

Event type:

```text
tn.jwks.key_selected
```

Fields include:

- `issuer`
- `jwks_url`
- `jwks_fingerprint`
- `signing_kid`
- `signing_key_fingerprint`
- `encryption_kid`
- `encryption_key_fingerprint`
- `trust_policy`
- `trust_reason`
- `selected_at`

For first-use pinning, TN records:

```text
tn.jwks.pinned
```

For rotation, TN records:

```text
tn.jwks.rotated
```

This creates an audit trail that answers:

- Which key set did we trust?
- Who did it claim to belong to?
- Which encryption key did we select?
- Was this a first pin, a pin match, or a rotation?

## Rotation

JWKS rotation should not be treated as an unrelated new key set.

The expected rotation shape is:

1. The project already trusts an old JWKS fingerprint.
2. The new JWKS is fetched and inspected.
3. The operator or SDK verifies that the new set is an approved successor.
4. The new active encryption key is marked `tn_status: "active"`.
5. Older keys may remain as `retiring` during a transition window.
6. TN records `tn.jwks.rotated` with both the previous and new fingerprints.

If the old trust chain cannot approve the new key set, treat it as a fresh trust
decision and require explicit confirmation.

## TypeScript Surface

The current TypeScript implementation includes:

- `parseTnJwks(value)`: validate TN's JWKS shape.
- `localDeviceJwks(device, options)`: build a JWKS for the local public signing key.
- `localJweEncryptionJwksKey(group, privateKey)`: derive a public X25519 JWKS key from a local JWE reader key.
- `jwksKeyFingerprint(key)`: compute one key fingerprint.
- `jwksDocumentFingerprint(jwks)`: compute the whole document fingerprint.
- `selectActiveJwksEncryptionKey(jwks)`: select the single active encryption key.
- `trustedJwksEncryptionRecipient(value, input)`: parse, verify trust, select the key, and return a JWE recipient.
- `verifiedJweRecipientFromTrustedJwks(recipient, options)`: convert a trusted JWKS encryption key into a `VerifiedJweRecipient` fingerprint binding for `tn.admin.addRecipient` and `tn.pkg.prepareRecipient`.
- `jwksKeySelectedEvent(recipient, options)`: build `tn.jwks.key_selected` fields.
- `inspectVaultJwks({ url })`: fetch and report JWKS metadata without trusting it.
- `trustedVaultJwksRecipient({ jwks })`: fetch and verify a pinned vault JWKS.
- `sealForTrustedVaultJwks(payload, { jwks, recorder })`: verify, seal with JWE, and optionally record key-selection metadata.
- `tn.vault.pinJwks(jwks)`: write `vault.jwks` and emit `tn.jwks.pinned`.
- `tn.vault.rotateJwks(next, previousFingerprint)`: update `vault.jwks` and emit `tn.jwks.rotated`.

## Browser Demo

The demo at `ts-sdk/examples/jwks.html` shows both major workflows:

- vault-bound encryption with explicit JWKS pinning
- project-to-project sharing using `tn-js jwks export --include-encryption`

To run it locally:

```powershell
cd ts-sdk/examples
python -m http.server 8088
```

Then open:

```text
http://localhost:8088/jwks.html
```

The demo uses `sample-jwks.json` by default. If a remote fetch fails in the
browser, it is usually a CORS or mixed-origin issue rather than a TN crypto
issue.

## Important Boundaries

- JWKS is public. Never put private seeds or private X25519 keys in a JWKS.
- Pinning a fingerprint is a trust decision. It should not happen silently.
- JWE encryption uses the trusted key; it does not establish trust by itself.
- YAML is an operational cache. Signed admin replay is the tamper-evidence layer.
- JWE operations are backed by the shared Rust/WASM primitives in the TypeScript
  SDK. JWKS decides which public key may be used; it does not replace the JWE
  encryption/decryption layer.
