# The JWE cipher (`cipher: jwe`)

`jwe` is one of TN's three per-group ciphers, peer to `btn` (the default) and
`hibe`. A group configured with `cipher: jwe` seals its body as a **standard
RFC 7516 JWE** — the same JSON Web Encryption every JOSE library speaks — so a
record sealed by one TN implementation opens in another by standards
conformance, not by any TN-specific format.

Under the hood: one fresh `A256GCM` content key encrypts the body; that key is
wrapped **per recipient** with `ECDH-ES+A256KW` over the recipient's X25519
key. The output is a JWE *General JSON Serialization* object (a `recipients`
array), which becomes the group's opaque `ciphertext`. When row hashing is
enabled it covers that complete object; a non-empty record signature covers the
stored hash. Unsigned and unchained profiles use empty hash/signature sentinels.

**When to reach for `jwe`:** the audience is small and enumerated at seal time;
you want an externally-inspectable, standards-compliant envelope; recipients
already hold X25519 keys. **When not to:** you need cheap forward revocation of
an already-admitted reader at scale (use `btn` — jwe revocation is forward-only,
below), or you seal to someone who holds no key yet (HIBE can model that, but
its TN scheme/pairing implementation is unaudited and evaluation-only pending
external cryptographic review; see
[the security warning](jwe-hibe-key-ceremonies.md#choose-the-cipher-first)).

The cipher is produced by **Authlib/joserfc** (BSD-3) in Python and the fixed
RustCrypto/Dalek profile in `tn-core`, exposed to TypeScript through `tn-wasm`.
Independent implementations are kept interoperable by RFC 7516 fixtures.

---

## The key model

- **Recipient key** — each reader holds a long-lived **X25519** keypair. The
  publisher needs only each recipient's **public** key to seal to them.
- **No sender secret in the seal path** — `ECDH-ES` generates an *ephemeral*
  sender key per recipient, carried in the recipient's JWE header (`epk`). There
  is no long-lived sender decryption key to leak. (A `<group>.jwe.sender` file
  is kept only as an inert group identity anchor for the ceremony; the crypto
  never uses it.) The cipher does not authenticate its sender. A separate
  authorship claim exists only when the TN signature is non-empty, composite
  record verification is enforced, and the verified DID is authorized.

Readers generate and retain their own `<group>.jwe.mykey`; publishers enroll
only an authenticated DID-to-X25519 public-key binding. Python's ordinary
reader-kit exporter does not transport JWE private keys. See
[JWE and HIBE key ceremonies](jwe-hibe-key-ceremonies.md#provision-and-enroll-a-jwe-reader).
- **Marker** — an optional string welded to the body via the native JWE `aad`
  member: authenticated, not encrypted. A reader must supply the identical bytes
  to open; a plain seal omits it entirely.

---

## Python

Configure a group with `cipher: jwe` (`tn.init(..., cipher="jwe")`, or per-group
in `tn.yaml`) and the normal `tn.info` / `tn.read` pipeline seals with JWE —
profile-controlled signature/chain/`row_hash` behavior stays separate from
decryption, as with every cipher. The cipher surface itself:

```python
from tn.cipher import JWEGroupCipher
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# A jwe group where the creator is publisher and sole reader.
pub = JWEGroupCipher.create(keystore, "orders", recipient_dids=["did:key:alice"])

blob = pub.encrypt(b'{"amount": 999, "currency": "USD"}')   # -> RFC 7516 JWE bytes
pub.decrypt(blob)                                           # -> the plaintext

# Bind a marker (authenticated, not encrypted, not required to read the group):
gov = pub.encrypt(b'{"amount": 999}', b"policy=finra-oba")
pub.decrypt(gov, b"policy=finra-oba")   # ok
pub.decrypt(gov, b"policy=other")       # raises NotARecipientError

# Add / revoke a recipient (O(1) recipient-list edits).
pub.add_recipient("did:key:bob", bob_x25519_pub_bytes)
pub.revoke_recipient("did:key:bob")
```

```
==================================================================
create a jwe group (publisher is also the sole reader)
==================================================================
keystore files: ['orders.jwe.mykey', 'orders.jwe.recipients', 'orders.jwe.sender']

==================================================================
seal / open a body
==================================================================
sealed blob     : 365 bytes of RFC 7516 JWE JSON
open (publisher): {"amount": 999, "currency": "USD"}

==================================================================
bind a marker (the JWE aad member: authenticated, not encrypted)
==================================================================
aad member set  : True
open, right aad : {"amount": 999}
open, wrong aad : rejected (NotARecipientError)
plain seal aad? : False

==================================================================
add a second recipient — both can open, next seal wraps to both
==================================================================
recipient blocks: 2
alice opens     : {"amount": 250}
bob opens       : {"amount": 250}

==================================================================
revoke bob — forward only (pre-revocation seals he holds stay open)
==================================================================
recipient blocks: 1
alice opens new : {"amount": 50}
bob opens new   : rejected (revoked before this seal)
bob opens old   : {"amount": 250} (pre-revocation, still his)
```

---

## The on-wire object

A jwe group's `ciphertext` decodes to UTF-8 JSON of a JWE General JSON
Serialization object — captured from the demo:

```
members         : ['ciphertext', 'iv', 'protected', 'recipients', 'tag']
protected       : eyJlbmMiOiJBMjU2R0NNIn0   (b64url {"enc":"A256GCM"})
recipients      : 1
recipient[0].alg: ECDH-ES+A256KW
recipient[0].epk: {"crv": "X25519", "kty": "OKP", "x": "Oh6l4aGvkZdjTpOeoEdnAV3zOtSj3UTaap7LQmqe8xc"}
```

```json
{
  "protected": "<b64url {\"enc\":\"A256GCM\"}>",
  "recipients": [
    { "header": { "alg": "ECDH-ES+A256KW",
                  "epk": { "kty": "OKP", "crv": "X25519", "x": "<b64url>" } },
      "encrypted_key": "<b64url A256KW-wrapped CEK>" }
  ],
  "aad": "<b64url marker — present only when a marker is bound>",
  "iv": "<b64url>", "ciphertext": "<b64url A256GCM body>", "tag": "<b64url>"
}
```

One `recipients[]` entry per reader, each with its own ephemeral `epk`. Blocks
are **anonymous** — no `kid` identifies who a block is for — so an observer
can't enumerate the audience. A reader trial-opens the blocks; the AEAD tag
rejects the wrong key with no false-plaintext risk.

---

## TypeScript / JavaScript

The TS SDK exposes the same fixed RFC 7516 profile through the Rust/Wasm `jwe`
namespace:

```ts
import { jwe } from "@cyaxios/tn-proto";

// recipientPubs: raw 32-byte X25519 public keys
const blob = jwe.encryptSync(
  plaintextBytes,
  [alicePub],
  enc("policy=finra-oba"),
);

// The reader retains its raw 32-byte X25519 private key locally.
const pt = jwe.subscribe([alicePrivate]).decryptSync(
  blob,
  enc("policy=finra-oba"),
);
// A wrong/absent marker or non-recipient key throws; plaintext is never returned.
```

`jwe.encryptSync` and `Subscriber.decryptSync` execute immediately. The
`encrypt` and `decrypt` methods are backward-compatible async delegates. Both
forms interoperate with the Python cipher: bytes sealed by one open with the
other.

To write and read JWE groups through the TS runtime, use the ordinary verbs:

```ts
tn.info("order.created", { amount: 999, currency: "USD" });

for (const entry of tn.read()) {
  console.log(entry.event_type, entry.fields);
}
```

---

## Cross-implementation interop

Because both sides emit standard RFC 7516, a record sealed by one opens in the
other with no shared golden vectors — the standard is the contract. A record
sealed by the Python cipher opens under the TS cipher and vice versa, marker
included.

---

## Notes and limits

- **Revocation is forward-only.** `revoke_recipient` drops a reader from the
  list so the *next* seal omits their block — but a record they already hold
  stays open to them (shown above: bob opens the pre-revocation seal, not the
  post-revocation one). For retroactive lockout of an admitted reader, use
  `btn`.
- **Group rotation resets the audience.** Rotation archives the active JWE
  files and recreates the group with only the publisher's self-recipient.
  Every external reader must re-enroll an authenticated X25519 public key
  before receiving a post-rotation recipient block.
- **Fail-closed.** A wrong marker, a non-recipient key, or a tampered/garbage
  blob never yields plaintext. The public `jwe` subscriber throws a stable
  `PrimitiveError` subtype, the JWK compatibility helper offers a detailed
  outcome or legacy `null`, and ordinary readers leave a group hidden when the
  caller holds no fitting key.
- **Marker is public-inspectable.** The marker is authenticated but not
  encrypted; a proxy can read and check it (via the record's `tn_aad` echo)
  without decrypting the body.
- **Recipient-key rotation is the forward-secrecy lever.** ECDH-ES gives forward
  secrecy against the sender (ephemeral epk), but a recipient's static X25519
  key opens all of their past blocks — rotate recipient keys to bound that.
- **Implementations.** Keep `joserfc`, RustCrypto, and Dalek dependencies
  current, retain envelope size limits, and run the cross-language fixtures at
  release time.
