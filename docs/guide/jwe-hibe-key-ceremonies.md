# JWE and HIBE key ceremonies

This guide explains how to get the `jwe` and `hibe` ciphers running in a
TN ceremony, what each approach is for, and where the important keys enter
the ceremony.

It is intentionally higher level than the cipher references:

- [jwe-howto.md](jwe-howto.md) shows the JWE object and runtime examples.
- [hibe-howto.md](hibe-howto.md) shows HIBE key material with worked output.
- [protocol.md](protocol.md) defines the record wire format.

> **HIBE security status — not production-ready without review.** The
> `tn-bbg` scheme implementation and its `bls12_381_plus` pairing library are
> **unaudited**. External cryptographic review is required before production use.
> Treat `cipher: hibe` as experimental/evaluation-only until that review
> is complete; correctness, hardening, and interoperability tests are not a
> substitute for an independent cryptographic audit. See
> [The HIBE primitive library](hibe-library.md#security-status).

## Choose the cipher first

| Cipher | Use it when | What has to exist before sealing | How readers are admitted |
|---|---|---|---|
| `jwe` | You want standards-defined per-recipient encryption for a small, explicit audience, such as web/API request records, callbacks, partner handoffs, or support shares with no durable audience lifecycle. | Each reader has a 32-byte X25519 public key registered in the group's recipient list. | The publisher registers the reader's X25519 public key. The next seal includes a recipient block for that key. |
| `hibe` | For evaluation only, you want role separation: a writer can seal to a path using only the authority public key. | The writer has an authenticated, pinned authority master public key (`mpk`) and the group identity path. | The authority mints an exact-path key, or deliberately grants an ancestor key. An ancestor grantee becomes a delegated subauthority for descendants within the remaining `max_depth`. |

`btn` remains the default when TN controls both seal and open and wants
bounded-audience lifecycle semantics. JWE is included when standards-defined
per-recipient encryption is valuable. HIBE is included when writers and grant
authorities need to be separate. A BTN-in-JOSE encoding is possible, but it
would be a TN profile rather than ordinary JWE interoperability.

## Shared ceremony shape

A TN ceremony is a directory under `.tn/<name>/` with a `tn.yaml`, a `keys/`
directory, and one or more logs. Every cipher uses the same record envelope:

```json
{
  "device_identity": "did:key:z6Mk...",
  "event_type": "case.note",
  "row_hash": "sha256:...",
  "signature": "...",
  "default": {
    "ciphertext": "<base64 cipher-owned bytes>",
    "field_hashes": {
      "field": "hmac-sha256:v1:..."
    }
  }
}
```

The group cipher owns only the bytes inside `default.ciphertext`. Record
hashing, chaining, optional signing, field routing, and equality tokens are
cipher-agnostic. That is why JWE and HIBE can be selected per group without
changing the record shape.

### Keep the security boundaries separate

Neither cipher is a complete authorization system. Treat these as five
different controls:

| Boundary | What provides it | What it does not prove |
|---|---|---|
| Confidentiality | JWE or HIBE body encryption | Who authored the record |
| Reader admission | JWE recipient blocks, or possession/derivation of a HIBE path key | Whether a writer was allowed to write |
| Record signing | An optional Ed25519 TN signature, controlled by the profile/YAML | That the signer is on an authorized-writer list |
| Signature verification | A consumer recomputes record integrity and verifies a non-empty signature, for example with `tn.read(verify="raise")` | Authorization unless the verified DID is also checked against policy |
| Writer authorization | An ingestion ACL, trusted-DID allowlist, or application policy | This is not supplied by JWE or HIBE |

The default `transaction` profile signs and chains records, but `telemetry`,
`stdout`, or explicit YAML settings can disable those controls. `tn.read()` is
secure by default: omitting `verify` resolves to `verify="auto"`, which enforces
the applicable integrity, authentication, and trusted-writer checks before
returning plaintext. `verify="skip"` retains the same checks but drops rejected
records and reports their reasons instead of raising; it changes continuation,
not the security gates. Actual weakening remains explicit: `verify=False`,
`require_signature=False`, `allow_unauthenticated=True`, or
`allow_unknown_writers=True` relax specific gates. Foreign or detached unsigned
records require both `require_signature=False` and
`allow_unauthenticated=True`; they carry no authenticated-writer claim. These
parameters do not disable parsing or body AEAD/AAD validation. Successful
decryption therefore means only that the reader held suitable key material; it
is not proof of authorship or writer authorization.

Create a fresh ceremony with one cipher:

```python
import tn

tn.init("api-audit", cipher="jwe")
tn.info("request.completed", path="/v1/cases", status=200)
```

or:

```python
import tn

tn.init("case-review", cipher="hibe")
tn.info("case.note", case_id="case-17", decision="reviewed")
```

For mixed projects, configure ciphers per group in `tn.yaml`:

```yaml
groups:
  requests:
    cipher: jwe
    fields: [path, method, status, request_id]

  governed_cases:
    cipher: hibe
    fields: [case_id, decision, rationale]
```

## AAD markers in both ciphers

Both ciphers can bind a public marker to the encrypted body:

```python
tn.info(
    "case.note",
    case_id="case-17",
    decision="reviewed",
    aad={"policy": "fraud-review", "tenant": "acme"},
)
```

The effective marker is echoed into the public `tn_aad` field as canonical
JSON, and the same canonical bytes are authenticated by the group body
encryption. A reader reconstructs those bytes from `tn_aad` before opening the
group. Changing the echo while leaving the ciphertext unchanged always breaks
decryption.

When the profile computes a row hash (signing or chaining is enabled), changing
the echo also makes row-hash recomputation fail. The signature primitive covers
the stored row hash, not `tn_aad` directly, so that primitive check can still
pass while the composite record-integrity check fails. When a profile is both
unsigned and unchained, `row_hash` and `signature` are empty sentinels; in that
case the body AEAD/decryption check is what rejects the changed marker.

JWE stores the marker using the native RFC 7516 `aad` member inside the JWE
object. HIBE binds the marker as body AEAD AAD but does not store it inside the
ciphertext. In both cases, the application-facing rule is the same: the reader
must supply the byte-identical marker bytes, reconstructed from `tn_aad`, or the
group will not open.

## JWE ceremony

### What JWE gives you

`cipher: jwe` seals the group body as an RFC 7516 JWE General JSON
Serialization object:

- one fresh `A256GCM` content key seals the body;
- each reader gets one recipient block;
- each recipient block wraps that content key with `ECDH-ES+A256KW` over the
  reader's X25519 public key;
- JOSE generates a fresh ephemeral `epk` per recipient block, not one shared
  sender key per seal;
- the JWE object does not authenticate its sender.

The JWE JSON bytes become the group's opaque `ciphertext`. When row hashing is
enabled, `row_hash` covers the entire JOSE object, and a non-empty TN signature
covers that stored hash. Authenticity exists only if the reader enforces the
composite integrity checks and accepts the verified `device_identity` as an
authorized writer.

### JWE key material

| File or value | Secret? | Holder | Purpose |
|---|---:|---|---|
| `local.private` | yes | writer device | Ed25519 device signing key. Signs TN records. Not a JWE decrypt key. |
| `<group>.jwe.sender` | yes | publisher keystore | Stable group identity anchor for the TN ceremony surface. ECDH-ES does not use it to seal or open. |
| `<group>.jwe.recipients` | no, but audience-sensitive | publisher keystore | JSON recipient list: `recipient_identity` plus `pub_b64`, the reader's raw X25519 public key. |
| `<group>.jwe.mykey` | yes | reader keystore | The reader's raw X25519 private key for opening JWE recipient blocks. The publisher has one only when it is also a reader. |
| `<group>.jwe.mykey.revoked.<ts>` | yes | reader keystore | Archived prior reader keys kept so old records still open after JWE rotation. |

Do not confuse the DID with the JWE decrypt key. The DID is the device identity
used for signatures, addressing, and package sealing. The JWE recipient key is
an X25519 key used for ECDH-ES.

### JWE flow

```text
Reader/device                         Publisher ceremony
-------------                         ------------------
X25519 private key stays local
X25519 public key ------------------>  <group>.jwe.recipients

                                      seal:
                                      - canonicalize group body
                                      - make fresh CEK
                                      - wrap CEK once per recipient
                                      - write JWE JSON into ciphertext

<group>.jwe.mykey opens one
anonymous recipient block <----------  TN record (signature may be empty)
```

To create a JWE ceremony where the publisher is also the first reader:

```python
import tn

tn.init("api-audit", cipher="jwe")
tn.info("request.completed", path="/v1/cases", status=200)
```

### Provision and enroll a JWE reader

The reader generates its own X25519 keypair and keeps the private half local.
The following reader-side procedure installs the private key at the filename
the Python key-bag reader expects and produces only the public enrollment
value:

```python
import base64

import tn
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tn._keystore_backend import atomic_write_bytes

group = "default"
cfg = tn.current_config()  # run in the reader's ceremony
key_path = cfg.keystore / f"{group}.jwe.mykey"
if key_path.exists():
    raise FileExistsError(f"refusing to replace existing reader key: {key_path}")

reader_private = X25519PrivateKey.generate()
atomic_write_bytes(key_path, reader_private.private_bytes_raw())

reader_x25519_public_b64 = base64.b64encode(
    reader_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode("ascii")
reader_did = cfg.device.device_identity
enrollment = {
    "group": group,
    "reader_did": reader_did,
    "reader_x25519_public_b64": reader_x25519_public_b64,
}
```

The current Python keystore writer creates a same-directory temporary file as
owner-only `0600`, flushes it, and atomically replaces the destination, avoiding
a world-readable create-then-`chmod` window. On Windows, POSIX mode bits do not
apply: provision `cfg.keystore` under a directory ACL accessible only to the
reader account before generating the key. Treat a failure to establish that ACL
as a provisioning failure, not something to ignore. The public `tn.offer(...)`
flow now uses the same secret writer when it creates a missing JWE reader key.

Send `reader_did`, `group`, and `reader_x25519_public_b64` to the publisher
through an authenticated enrollment channel. The publisher must establish an
**authenticated binding** between the asserted DID and that X25519 public key,
for example by verifying a DID-key proof of possession over the enrollment
values or by using an already authenticated administrative channel. A
self-consistent length check, an email, or an unverified JSON field is not a
binding.

Likewise, parsing a `tn.offer(...)` package or verifying it against the signing
key embedded in that same package is transport integrity, not sufficient DID
binding by itself. The publisher must also establish that the signing key is the
asserted DID's trusted key and that its signature covers this X25519 enrollment,
or authenticate the binding through a separate administrative channel.

Only after that verification should the publisher register the public key:

```python
import base64

import tn

cfg = tn.current_config()
reader_x25519_public_key = base64.b64decode(
    authenticated_enrollment["reader_x25519_public_b64"],
    validate=True,
)
reader_did = authenticated_enrollment["reader_did"]
if len(reader_x25519_public_key) != 32:
    raise ValueError("JWE enrollment public key must be 32 raw X25519 bytes")

# The authenticated channel/proof above, not add_recipient(), establishes
# that reader_did controls this X25519 key.
tn.admin.add_recipient(
    "default",
    recipient_did=reader_did,
    public_key=reader_x25519_public_key,
    cfg=cfg,
)
```

That mutates the publisher's `<group>.jwe.recipients` list. The next seal
includes a recipient block for that public key. `add_recipient()` validates the
DID/key shapes but does not authenticate their relationship.

Python does not export a JWE reader private key through the ordinary reader-kit
path. `tn.pkg.bundle_for_recipient(...)` is BTN-only and fails on a JWE group
because its `out_path` flow mints BTN kits. Do not copy or export the
publisher's `<group>.jwe.mykey`: that is the publisher's self-recipient secret,
not the other reader's key. A JWE reader must generate and retain its own
private key as above; enrollment moves only public material.

In TypeScript, the ordinary synchronous logging and reading verbs support JWE
through the Rust/Wasm implementation:

```ts
tn.info("request.completed", { path: "/v1/cases", status: 200 });

for (const entry of tn.read()) {
  console.log(entry.event_type, entry.fields);
}
```

### JWE revocation and rotation

JWE revocation is a recipient-list edit:

```python
tn.admin.revoke_recipient("default", recipient_did=reader_did)
```

Future seals omit that reader's recipient block. Records already sealed to that
reader remain readable by that reader. Rotating a JWE group archives old JWE
reader material and recreates the active group with only the publisher's
self-recipient. Every other reader must be re-enrolled before it receives a
post-rotation recipient block. If the operation is intended to rotate reader
keys, obtain a fresh authenticated X25519 public key from each reader; reusing
an old public key also reuses the corresponding old private-key capability.
Existing history remains bounded by the keys that could open it at the time.

Use JWE when the audience is small, explicit, and known at seal time. Use BTN
when you need the bounded-audience lifecycle to be the central property.

## HIBE ceremony

### What HIBE gives you

`cipher: hibe` seals to an identity path under an authority public key. This is
the reason HIBE is different from JWE and BTN:

- a writer can seal with only the authority `mpk` and a path;
- the writer does not need reader public keys;
- a writer that holds neither `msk` nor a path key cannot mint reader grants;
- the authority can mint reader path keys later;
- a parent path key can derive child path keys locally, so its holder is a
  delegated subauthority for that subtree.

HIBE supplies confidentiality and hierarchical reader admission. It does not
authenticate or authorize a writer: `mpk` and an identity path are public
sealing inputs, so anyone who obtains them can create a decryptable ciphertext.
Use a verified TN record signature plus a trusted-writer policy when writer
identity matters.

This is the role split:

```text
Authority
  holds:  <group>.hibe.msk
  issues: <group>.hibe.sk grants
  publishes: <group>.hibe.mpk

Writer
  holds:  <group>.hibe.mpk + <group>.hibe.idpath
  can:    seal to the path
  cannot: mint reader grants

Reader
  holds:  <group>.hibe.mpk + <group>.hibe.idpath + <group>.hibe.sk
  can:    open ciphertexts at that path, or descendants covered by the key
```

### HIBE key material

| File or value | Secret? | Holder | Purpose |
|---|---:|---|---|
| `<group>.hibe.mpk` | no | writers and readers | Authority master public key. Lets anyone seal to a path and lets readers open with a path key. Its fingerprint identifies these bytes but does not authenticate the authority or writer. |
| `<group>.hibe.msk` | yes | authority only | Authority master secret. Can mint a reader key for any path under the authority. Never rides an ordinary kit. |
| `<group>.hibe.idpath` | no | group keystore and reader kits | The path future records seal to, such as `self`, `org/fraud`, or `org/fraud/case-17`. |
| `<group>.hibe.sk` | yes | one capability holder | Bearer capability for a path. It can derive exact descendant keys within the remaining depth; the key itself is not bound to a DID. |
| `<group>.hibe.sk.previous.<ts>` | yes | reader keystore | Superseded path keys retained so pre-rotation entries still open. |
| `<group>.hibe.idpath.history` | no | authority keystore | Prior paths retained so the authority can still open older records after path rotation. |
| `<group>.hibe.grants` | sensitive registry | authority keystore | Records which reader DID was granted which path, used to re-issue survivor kits during HIBE revocation. |

The master secret is the key to the authority. Anyone holding it can mint path
keys and read every group sealed under that authority. Treat it differently from
a reader kit.

The MPK fingerprint is a stable identifier, not proof of origin. Before a
writer seals, obtain the expected fingerprint through an authenticated channel
or verify a signed authority statement against an already trusted authority
identity. Then compare that pin to `mpk_fingerprint(mpk)`. Merely parsing an MPK
or receiving it beside an asserted authority name does not authenticate it.

### HIBE flow

```text
1. Authority setup

   <group>.hibe.mpk  public
   <group>.hibe.msk  authority-only secret

2. Writer seals

   writer has mpk + idpath
   writer seals group body to idpath
   ciphertext carries the wrapped CEK and AES-GCM body inside <group>.ciphertext

3. Authority grants

   authority uses msk to mint a path key:
   <group>.hibe.sk for org/fraud

4. Reader absorbs

   .tnpkg kit carries:
   - <group>.hibe.mpk
   - <group>.hibe.idpath
   - <group>.hibe.sk

   .tnpkg kit never carries:
   - <group>.hibe.msk
```

Create a HIBE ceremony where the local keystore is its own authority:

```python
import tn

tn.init("case-review", cipher="hibe")
tn.info("case.note", case_id="case-17", decision="reviewed")
```

That setup writes `default.hibe.mpk`, `default.hibe.msk`,
`default.hibe.idpath`, and a local `default.hibe.sk` so the authority can also
read its own records.

Grant a reader:

```python
from tn.recipient_seal import recipient_key_is_resolvable

# Complete Ed25519 did:key obtained from the reader through an authenticated
# channel. Do not abbreviate it with "...".
reader_did = authenticated_reader_identity
if not recipient_key_is_resolvable(reader_did):
    raise ValueError("reader DID cannot receive a recipient-sealed HIBE kit")

kit = tn.admin.grant_reader(
    "default",
    reader_did=reader_did,
    out_path="reader.tnpkg",
)
```

The kit contains the `mpk`, the group `idpath`, and one randomized delegated
reader key for that path. A `.hibe.sk` is a bearer capability, not a secret key
cryptographically bound to `reader_did`. `grant_reader` recipient-seals the
package only when `recipient_key_is_resolvable(reader_did)` recognizes a
complete Ed25519 `did:key`; otherwise it silently falls back to a plaintext
package. Placeholder, abbreviated, non-`did:key`, and non-Ed25519 identifiers
take that plaintext path. For a sensitive grant, fail as shown above rather
than relying on the fallback.

The reader installs the delivered kit:

```python
import tn

tn.init("reader")
tn.absorb("reader.tnpkg")
```

After absorb, the reader has enough key material to open records from the
authority's log for that group.

### External-authority writer

A writer can seal without being the authority. In that mode, the writer has the
authority `mpk` and the target `id_path`, but no `msk` and no reader `sk`.
It can write records that future grantees may open, but it cannot grant itself
or anyone else read access. It is not, however, authorized merely because it
can seal: MPK-plus-path encryption is public.

Depth is fixed when the authority creates the MPK. The normal
`tn.init(..., cipher="hibe")` authority uses `max_depth=2`, so it cannot seal to
the three-label path `org/fraud/case-17`. For that path, create the authority
with an explicit depth budget:

```python
from pathlib import Path

from tn import _hibe
from tn.cipher import HibeGroupCipher

target_path = "org/fraud/case-17"
authority_keystore = Path("authority/keys")
handoff_dir = Path("outbound")
handoff_dir.mkdir(parents=True, exist_ok=True)
authority = HibeGroupCipher.create(
    authority_keystore,
    "governed_cases",
    id_path=target_path,
    max_depth=3,
)
(handoff_dir / "authority.mpk").write_bytes(authority.mpk())
(handoff_dir / "authority.mpk.sha256").write_text(
    _hibe.mpk_fingerprint(authority.mpk()).hex(),
    encoding="ascii",
)
```

Deliver the MPK and its expected fingerprint to the writer through an
authenticated channel (or a signed authority statement whose signer is already
trusted). The writer verifies both the pin and encoded depth before configuring
the external-authority cipher:

```python
from hmac import compare_digest
from pathlib import Path

from tn import _hibe
from tn.cipher import HibeGroupCipher

target_path = "org/fraud/case-17"
writer_keystore = Path("writer/keys")
authenticated_dir = Path("authenticated")
authority_mpk_bytes = (authenticated_dir / "authority.mpk").read_bytes()
expected_mpk_fingerprint = (
    authenticated_dir / "authority.mpk.sha256"
).read_text(encoding="ascii").strip()

actual_mpk_fingerprint = _hibe.mpk_fingerprint(authority_mpk_bytes).hex()
if not compare_digest(actual_mpk_fingerprint, expected_mpk_fingerprint):
    raise ValueError("untrusted HIBE authority MPK")
if len(target_path.split("/")) > _hibe.mpk_max_depth(authority_mpk_bytes):
    raise ValueError("target path exceeds the authority MPK max_depth")

cipher = HibeGroupCipher.create(
    writer_keystore,
    "governed_cases",
    authority_mpk=authority_mpk_bytes,
    id_path=target_path,
)
```

The fingerprint identifies the exact MPK bytes; it does not authenticate them
by itself. The authenticated delivery/signature establishes the trust root, and
the comparison pins it. Application writers then seal with public material;
writer authorization remains a separate policy decision.

### HIBE revocation and rotation

A HIBE path key is permanent for its path. You cannot un-mint it. Removing a
reader means rotating future seals to a new path and issuing new kits to the
survivors:

```python
result = tn.admin.revoke_reader(
    "default",
    revoked_reader_did,
    out_dir="hibe-regrant",
)

print(result.new_path)
print(result.kit_paths)
```

The removed exact-path reader keeps records sealed before the path rotation.
`revoke_reader` changes the authority ceremony's local path and reissues
survivor kits; it does not update separate external writers. Each external
writer retains its own `.hibe.idpath` and will keep sealing to the old path until
it is updated. A revoked reader can still open those stale-writer ciphertexts.

Before the next external seal, deliver a signed/versioned path update to every
writer, require it to verify the pinned MPK is unchanged and the target is the
new sibling path, then reload/reconfigure that writer. Pause or fence writers
that have not acknowledged the update. Forward cutoff begins only after every
writer that can publish has adopted the authenticated sibling path.

An ancestor grant is stronger: its holder can derive the exact child key for
any new path inside that subtree, without the `msk`. Rotation below that
ancestor cannot revoke it. If such a capability has already been issued, move
to a fresh authority MPK outside that capability domain (and re-enroll everyone)
or use BTN. For rotatable HIBE admission, issue exact-path grants and rotate to
a sibling, never a descendant of the old path.

Use HIBE when the authority/writer split is the important property. Use BTN when
routine reader removal without re-issuing survivor keys is the important
property.

## Package and absorb rules

`.tnpkg` is used for public enrollment metadata and HIBE grants, but not every
cipher moves private reader keys this way:

| Cipher | Supported handoff | Must not contain |
|---|---|---|
| `jwe` | A reader offer can carry that reader's public X25519 enrollment value; a publisher enrollment can carry public sender metadata. Python ordinary reader-kit export does not collect `.jwe.mykey`. | Any party's `<group>.jwe.mykey`; especially never the publisher's self-recipient key. |
| `hibe` | `<group>.hibe.mpk`, `<group>.hibe.idpath`, and one `<group>.hibe.sk`. | `<group>.hibe.msk`. |

The absorb path refuses HIBE master secrets from ordinary packages. A package
containing `.hibe.msk` is treated like a full self-addressed backup, not like a
reader grant.

For HIBE, the `.hibe.sk` remains a bearer capability even when its surrounding
package names a reader. When recipient sealing is possible, use it. A plaintext
kit is a bearer token: whoever receives it can absorb and use it.

## Operator checklist

For JWE:

1. Decide the group name and set `cipher: jwe`.
2. Have every reader generate and retain its own raw 32-byte X25519 keypair.
3. Authenticate the binding between each reader DID and X25519 public key.
4. Register only the verified public key in the publisher ceremony.
5. Use the normal TypeScript or Python logging and reading verbs; JWE is a
   per-group cipher choice, not a separate application workflow.
6. Treat revocation as forward-only: it removes future recipient blocks.
7. After rotation, re-enroll every non-publisher reader.
8. If authorship matters, use a signing profile, enforce composite verification,
   and authorize the verified writer DID separately.

For HIBE:

1. Do not use HIBE in production before the required external review.
2. Decide who is the authority and authenticate/pin its MPK fingerprint.
3. Protect the authority's `<group>.hibe.msk`; it can mint every path key.
4. Budget `max_depth` and pick the group identity path deliberately.
5. Use exact-path grants unless you intend to delegate subauthority.
6. Require a complete resolvable Ed25519 DID before recipient-sealing a grant.
7. For removal, rotate to a sibling, reissue survivor kits, and update every
   external writer before it seals again.
8. Enforce signature verification and a writer-authorization policy separately.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| JWE group cannot seal. | `<group>.jwe.recipients` is missing or empty. | Create the group or register at least one recipient public key. |
| JWE reader gets no plaintext. | Reader did not generate/retain the matching `<group>.jwe.mykey`, was not enrolled for that seal, or was not re-enrolled after rotation. | Restore the reader's own key or re-enroll its authenticated public key. |
| HIBE writer cannot seal. | The writer lacks `<group>.hibe.mpk`/`<group>.hibe.idpath`, the MPK pin fails, or the path exceeds `max_depth`. | Authenticate and pin the authority MPK, then configure a path within its encoded depth. |
| HIBE reader cannot open. | The reader lacks `<group>.hibe.sk`, has a key for a sibling path, or the AAD marker changed. | Absorb the correct grant and verify the `tn_aad` echo was not changed. |
| HIBE grant package is plaintext. | The reader identifier was not a complete resolvable Ed25519 `did:key`. | Stop delivery, obtain the complete DID, require `recipient_key_is_resolvable(...)`, and mint a new grant. |
| HIBE removal did not block new records from one writer. | That external writer still pins the old path, or the reader held an ancestor key. | Authenticate and deploy the sibling path to every writer; an ancestor leak requires a fresh authority MPK or BTN. |
