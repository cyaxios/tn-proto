# The JWE cipher (`cipher: jwe`)

`jwe` is one of TN's three per-group ciphers, peer to `btn` (the default) and
`hibe`. A group configured with `cipher: jwe` seals its body as a **standard
RFC 7516 JWE** — the same JSON Web Encryption every JOSE library speaks — so a
record sealed by one TN implementation opens in another by standards
conformance, not by any TN-specific format.

Under the hood: one fresh `A256GCM` content key encrypts the body; that key is
wrapped **per recipient** with `ECDH-ES+A256KW` over the recipient's X25519
key. The output is a JWE *General JSON Serialization* object (a `recipients`
array), which becomes the group's opaque `ciphertext` — so `row_hash`, the
chain, and the record signature cover it with no envelope change.

**When to reach for `jwe`:** the audience is small and enumerated at seal time;
you want an externally-inspectable, standards-compliant envelope; recipients
already hold X25519 keys. **When not to:** you need cheap forward revocation of
an already-admitted reader at scale (use `btn` — jwe revocation is forward-only,
below), or you seal to someone who holds no key yet (use `hibe`).

The cipher is produced by production JOSE libraries — **Authlib/joserfc**
(BSD-3) in Python, **panva/jose** (MIT) in TypeScript/JS. TN does not hand-roll
the crypto.

---

## The key model

- **Recipient key** — each reader holds a long-lived **X25519** keypair. The
  publisher needs only each recipient's **public** key to seal to them.
- **No sender secret in the seal path** — `ECDH-ES` generates an *ephemeral*
  sender key per recipient, carried in the recipient's JWE header (`epk`). There
  is no long-lived sender decryption key to leak. (A `<group>.jwe.sender` file
  is kept only as an inert group identity anchor for the ceremony; the crypto
  never uses it. Sender *authenticity* comes from the record's Ed25519
  signature, not the cipher.)
- **Marker** — an optional string welded to the body via the native JWE `aad`
  member: authenticated, not encrypted. A reader must supply the identical bytes
  to open; a plain seal omits it entirely.

---

## Python

Configure a group with `cipher: jwe` (`tn.init(..., cipher="jwe")`, or per-group
in `tn.yaml`) and the normal `tn.info` / `tn.read` pipeline seals with JWE —
signature, chain, `row_hash`, and decrypt all work identically to any other
cipher. The cipher surface itself:

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

The TS SDK ships the same cipher on panva/jose, pure JS — it runs in Node,
browsers, and edge runtimes with no wasm:

```ts
import { jweSeal, jweDecrypt, okpPrivateJwk } from "@cyaxios/tn-proto/core";

// recipientPubs: raw 32-byte X25519 public keys
const blob = await jweSeal([alicePub], plaintextBytes, enc("policy=finra-oba"));

// readerJwk: the reader's X25519 key as an OKP JWK ({kty,crv,x,d})
const pt = await jweDecrypt(readerJwk, blob, enc("policy=finra-oba"));
// wrong / absent marker, or a non-recipient key -> null (never plaintext)
```

`jweSeal` and `jweDecrypt` are `async` (they use WebCrypto), and interoperate
with the Python cipher — bytes sealed by one open with the other.

To write and read jwe groups through the TS runtime, use the async verbs —
`emitAsync` / `infoAsync` to seal, `readAsync` to open (the synchronous
`emit` / `info` / `read` handle btn and hibe):

```ts
await tn.infoAsync("order.created", { amount: 999, currency: "USD" });

for await (const entry of tn.readAsync()) {
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
- **Fail-closed.** A wrong marker, a non-recipient key, or a tampered/garbage
  blob yields an error (Python) or `null` (TS) — never wrong plaintext, and the
  SDK never throws into host space.
- **Marker is public-inspectable.** The marker is authenticated but not
  encrypted; a proxy can read and check it (via the record's `tn_aad` echo)
  without decrypting the body.
- **Recipient-key rotation is the forward-secrecy lever.** ECDH-ES gives forward
  secrecy against the sender (ephemeral epk), but a recipient's static X25519
  key opens all of their past blocks — rotate recipient keys to bound that.
- **Libraries.** joserfc (BSD-3) and panva/jose (MIT) are permissive and
  maintained; keep them current for JOSE DoS advisories. Neither is vendored —
  the wheel and npm package stay Apache-2.0.
