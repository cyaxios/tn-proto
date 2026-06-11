# Vault HTTP

The hosted TN vault speaks a versioned REST API at
`https://vault.tn-proto.org` (configurable via `TN_VAULT_URL`).
Authentication is **DID-challenge**: clients prove ownership of a
`did:key:` by signing a nonce, exchange that for a JWT, and Bearer-
auth subsequent requests with the JWT.

This spec catalogs the routes clients call. Server-side semantics
(persistence, rate limits, etc.) are out of scope.

## Base URL

```text
https://vault.tn-proto.org           (default)
```

Resolution order, with `resolveVaultUrl` (TS) / `resolve_vault_url`
(Python):

1. Explicit argument from the caller.
2. `TN_VAULT_URL` env var.
3. The hardcoded default.

For DID-resolved vault endpoints (when a yaml's `ceremony.linked_vault`
is a `did:web:` instead of a literal URL), see
`resolveDidEndpoint` and [signing.md#did-format](./signing.md#did-format).

## Auth handshake

### POST /api/v1/auth/challenge

Request: `{"did": "did:key:z..."}`.

Response: `{"nonce": "<random>"}`.

The nonce is a random string the client signs in the next step.

### POST /api/v1/auth/verify

Request:

```json
{
  "did": "did:key:z...",
  "nonce": "<from-challenge>",
  "signature": "<url-safe-b64-no-pad of Ed25519.sign(seed, nonce.encode('utf-8'))>"
}
```

Response: `{"token": "<JWT>"}`.

The client uses this JWT as `Authorization: Bearer <jwt>` for all
subsequent requests.

Reference: `python/tn/vault_client.py:271-296`,
`ts-sdk/src/runtime/bootstrap_api_key.ts::challengeVerify`.

## Account routes

### GET /api/v1/account/inbox

Bearer-auth. Returns the inbox listing: paths to incoming `.tnpkg`
files from other publishers, by `(from_did, ceremony_id, ts)`.

### GET /api/v1/account/inbox/{from_did}/{ceremony_id}/{ts}.tnpkg

Bearer-auth. Returns the raw `.tnpkg` bytes.

### POST /api/v1/account/connect-codes/redeem

**Unauthenticated**, but the request body is signed.

Request:

```json
{
  "code": "tn_connect_<random>",
  "did": "did:key:z...",
  "signature_b64": "<standard-b64 of Ed25519.sign(seed, SHA256(code.encode('utf-8')))>"
}
```

Response: `{account_id, did, project_id, project_name, recipient_dids, name, bound_at}`.

Used by the "redeem a connect code from the vault UI" flow. Server
binds the code to the redeeming DID.

Reference: `python/tn/vault_client.py:80-150`.

### GET /api/v1/account/projects

Bearer-auth. Lists projects bound to the authed DID.

### POST /api/v1/account/projects

Bearer-auth. Creates a new project.

### GET /api/v1/account/prefs / PUT

Bearer-auth. Account prefs blob.

### GET /api/v1/account/passkey-seed / PUT / DELETE

Bearer-auth. Encrypted passkey-derived seed for wallet recovery.

### GET /api/v1/account/received-kits

Bearer-auth. Lists received reader kits.

### POST /api/v1/account/reset

Bearer-auth. Dev/test reset.

## API-key cold-start

### GET /api/v1/api-keys/{key_id_b64}/sealed-bundle

Bearer-auth (with a JWT minted via the standard auth handshake using
the bearer's embedded seed). Returns:

```json
{
  "sealed_bundle_b64": "<base64 of recipient-wrapped tnpkg bytes>",
  "kind": "project_seed"
}
```

The bundle is a recipient-sealed `.tnpkg` whose wrap is addressed
to the bearer's DID. The client unseals via
[recipient-wraps.md](./recipient-wraps.md), decrypts the body via
[body-encryption.md](./body-encryption.md), and installs the
project_seed.

Response codes:

- `200` — bundle returned.
- `404` — single-pickup key already consumed, or never existed.
- `410` — key revoked.
- Other 4xx/5xx — caller MUST surface; never silently retry.

Reference: `python/tn/bootstrap.py:270-288`,
`ts-sdk/src/runtime/bootstrap_api_key.ts::bootstrapFromApiKey`.

## Project routes

### GET /api/v1/projects/{id}

Bearer-auth. Returns project metadata.

### DELETE /api/v1/projects/{id}

Bearer-auth.

### GET /api/v1/projects/{id}/files / POST / GET {name} / DELETE {name}

Bearer-auth. File upload/download for sealed blobs scoped to a
project.

### GET /api/v1/projects/{id}/restore

Bearer-auth. Restore manifest for project rehydration.

## Sync routes

### POST /api/v1/inbox/{from_did}/snapshots/{ceremony_id}/{ts}.tnpkg

Bearer-auth. Push a `.tnpkg` snapshot to a peer's inbox. Used by
the `vault.push` handler.

### GET /api/v1/inbox/{my_did}/incoming?since={cursor}

Bearer-auth. Pull incoming `.tnpkg`s since a cursor. Used by the
`vault.pull` handler.

## Pending-claim

### POST /api/v1/pending-claims

**Unauthenticated.** Used by the cold-start INIT-UPLOAD path when no
identity exists yet. The pending claim is bound to whoever first
authenticates with the matching DID.

## Contacts

### POST /api/v1/contacts/resolve

Bearer-auth. Resolves a contact identifier (email, handle) to a
DID + endpoint.

## Source pointers

| Side | File |
|---|---|
| Python client | `python/tn/vault_client.py` |
| Python bootstrap | `python/tn/bootstrap.py` |
| Python push handler | `python/tn/handlers/vault_push.py` |
| Python pull handler | `python/tn/handlers/vault_pull.py` |
| TS bootstrap | `ts-sdk/src/runtime/bootstrap_api_key.ts` |
| TS push handler | `ts-sdk/src/handlers/vault_push.ts` |
| TS pull handler | `ts-sdk/src/handlers/vault_pull.ts` |
