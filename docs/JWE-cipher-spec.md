# JWE for tn-proto — cipher spec

`cipher: jwe` emits interoperable RFC 7516 JWE. A JWE group's `ciphertext` blob is
a valid JWE **General JSON Serialization** object that any conformant JOSE
implementation can parse, produced by each language's production JOSE library
(Python: Authlib/joserfc, BSD-3; JS/TS: panva/jose, MIT). A record sealed by one
SDK opens in the other by standard conformance, not by shared golden vectors.

## Non-negotiable constraints

**1. No hand-rolled JOSE layer — use a production JOSE library.**
JWE is a standard (RFC 7516) with mature, maintained libraries; use them. The one
sanctioned exception is a thin, spec-conformant RFC 7516 serializer over
`pyca/cryptography` as a Python fallback, and only if the permissive primary
library fails its verification spike. Assembling AES-GCM + AES-KW + a custom
container by hand is out of bounds.

**2. The output MUST be interoperable RFC 7516 JWE — the standard is the wire format.**
A JWE group's `ciphertext` blob is a valid JWE General JSON Serialization object
any conformant JOSE implementation can parse. A record sealed by the Python SDK
opens in the TS SDK and vice versa **by standard conformance**, not by shared
bespoke golden vectors. A design choice that would make the output non-standard
(e.g. TN-only external AAD a compliant decryptor can't supply) is disallowed.

**3. btn is the STANDARD / DEFAULT cipher. JWE is one OPTION, never a replacement.**
Groups that don't opt into another cipher stay pure btn. JWE and HIBE are peer
options selected per group via `cipher:`.

**4. JWE stays on the PURE engine — not in the Rust native runtime or the wasm bundle.**
Unlike btn and hibe — native in `tn-core` because their crypto is heavy (NNL
subset-cover, BBG pairings) — JWE's crypto is commodity (X25519 ECDH +
AES-256-GCM), hardware-accelerated in every language's backend, so a Rust port
buys **no** measurable speed. There is also no pure-Rust, `wasm32`-compatible
JOSE library that encrypts. `should_use_rust` stays btn-or-hibe (it excludes
jwe); the `JwePlaceholder` is a clean `NotImplemented` sentinel, served by the
pure engine by design.

## Design decisions — the contract

**D1. Library per language — permissive JOSE libraries.**
- **Python → Authlib / `joserfc` (BSD-3-Clause).** Permissive, actively
  maintained; does multi-recipient General-JSON JWE (`encrypt_json` /
  `decrypt_json`) and RFC 8037 X25519 (OKP). Profile: `alg: ECDH-ES+A256KW`,
  `enc: A256GCM`, recipient key `{kty:OKP, crv:X25519}`, top-level `aad` member.
  **`jwcrypto` (LGPL-3.0) is REJECTED** — it meets every requirement but its
  copyleft posture is incompatible with the permissive-only wheel; permissive is
  a hard requirement.
- **JS/TS → panva `jose` (MIT, zero-dependency).** `GeneralEncrypt` +
  `.addRecipient()` + `.setAdditionalAuthenticatedData()`; `generalDecrypt`;
  native X25519 ECDH-ES.
- **Rust → non-native (no dependency added).** JWE is not built into `tn-core` /
  the wasm bundle (Constraint 4). If a **server-only** Rust JWE is ever needed,
  josekit (MIT/Apache-2.0, OpenSSL) is the fallback — never in the wasm bundle.

**D2. Wire format — RFC 7516 JWE General JSON Serialization, stored INSIDE `ciphertext`.**
A JWE group's cipher output is the UTF-8 bytes of the compact JSON of a General
JSON Serialization object (`{protected, recipients[], aad?, iv, ciphertext,
tag}`). Those bytes ARE the group's `ciphertext` field, exactly as btn serializes
its cover inside `ciphertext`. So `row_hash`, the chain, and the Ed25519
signature cover the entire JWE with **zero** envelope-schema change (row_hash
covers `ciphertext` + `field_hashes` only). **No sibling group-dict keys, ever** —
a wrapped key, iv, or tag hoisted to a sibling of `ciphertext` sits outside
`row_hash`/signature, a strip/swap vector. This matches protocol.md §3's opacity
rule.

**D3. Crypto profile — ECDH-ES+A256KW / A256GCM / X25519, ephemeral sender.**
Per recipient: `alg: ECDH-ES+A256KW` (ephemeral-static ECDH-ES derives a KEK,
AES-256 key-wrap of the shared CEK); body `enc: A256GCM` under one fresh CEK;
recipient keys are static X25519 OKP (RFC 8037). The sender epk is ephemeral per
seal, so there is **no long-lived sender secret** — the ephemeral key adds
forward secrecy w.r.t. the sender, and the epk travels in each recipient's JWE
header, so recipients don't need the sender's public key out-of-band. Sender
authenticity comes from the TN envelope's Ed25519 signature (protocol.md §2), not
from the cipher; ECDH-ES's lack of KEM-level sender authentication is therefore
not a gap. (If cipher-level sender auth were ever required, the JOSE mechanism is
ECDH-1PU — out of scope; the envelope signature already provides it.)

**D4. Recipient privacy — anonymous recipient blocks by default.**
Per-recipient headers carry **no identifying `kid`** by default, so an observer
cannot enumerate the audience from the envelope. Readers **trial-decrypt** the
small recipient list (bounded N; the AEAD tag rejects wrong CEKs with no
false-plaintext risk). A group MAY opt into `kid = recipient DID` for direct
block selection — a privacy tradeoff (it leaks the audience), off by default.

**D5. AAD marker — bind via JWE's native `aad` member.**
The TN marker (the AAD "governed flag": authenticated, not encrypted) binds
through JWE's standard top-level `aad` member (RFC 7516). This is the **one**
place JWE differs from the btn/hibe convention (where the marker is not stored in
the ciphertext and is reconstructed from the public `tn_aad` echo at read): in
JWE the marker rides inside the JWE JSON (inside `ciphertext`, so covered by
`row_hash`). This keeps JWE library-native and spec-pure. The public `tn_aad`
echo is unchanged (cross-cipher uniform, publicly inspectable by a proxy without
decrypting); at read the reader reconstructs the marker from `tn_aad` and the
JOSE library verifies it against the embedded `aad` member (mismatch fails the
tag). Empty marker ⇒ omit the `aad` member (byte-clean no-marker path).

## Framing — JWE is a general-purpose cipher, and it is a *standard*

JWE is a first-class `GroupCipher` peer to `btn` (the default) and `hibe`,
selected per group with `cipher: jwe`. Nothing else about the flow changes — a
caller writes to and reads from a `jwe` group through the identical verb surface
(seal/encrypt, open/decrypt, add-recipient, revoke, rotate, absorb) as btn/hibe.
Interchangeability is the deliverable: a caller should not have to know whether a
group is jwe, btn, or hibe.

btn and hibe are TN-original schemes — TN owns both ends, so cross-impl parity
needs bespoke golden vectors of a format TN defines. JWE is the opposite: an
**IETF standard** with independent, audited, production implementations in every
language. So this cipher leans on them and lets the standard carry interop —
per-language production libraries rather than one shared Rust impl, off the
native/wasm runtime (Constraint 4), and cross-impl correctness gated by a
**Python↔TS round-trip conformance test**, not golden vectors.

**When to choose jwe:** the audience is small and enumerated at seal time; you
want a standards-compliant, externally-inspectable envelope; recipients already
hold X25519 keys. **When not to:** you need btn-grade cheap forward revocation at
scale (use btn — jwe revocation is an O(1) recipient-list edit that only affects
future seals), or you seal to someone holding no key yet (use hibe).

## Library survey

| Lang | Library | License | Multi-recipient General JSON | ECDH-ES+A256KW · X25519(OKP) · A256GCM · `aad` | wasm | Verdict |
|---|---|---|---|---|---|---|
| Python | **Authlib / joserfc** | **BSD-3** | Yes (`encrypt_json`/`decrypt_json`) | X25519/RFC 8037 ✓ | n/a | **CHOSEN** (D1) |
| Python | jwcrypto | **LGPL-3.0** | Yes | All ✓ | n/a | **REJECTED** — copyleft |
| Python | python-jose | MIT | No | — | n/a | Rejected — unmaintained |
| Python | pyca/cryptography + thin serializer | Apache/BSD | (in-house) | in-house | n/a | Fallback only (D1) |
| JS/TS | **panva `jose`** | **MIT** | Yes (`GeneralEncrypt`/`generalDecrypt`) | All ✓ (native X25519) | Node/browser/Workers/Deno/Bun | **CHOSEN** (D1) |
| Rust | josekit | MIT/Apache-2.0 | Yes | All ✓ | **No (OpenSSL C dep)** | server-only fallback; never wasm |
| Rust | RustCrypto `jose` | Apache/MIT | (structural) | Encryption not implemented | pure-Rust | Not usable |

Keep the JOSE library pins current: joserfc and panva/jose have both had DoS
advisories (oversized-segment / compressed-JWE); TN envelopes are size-bounded
upstream, but track the pins. panva/jose is the most scrutinized (reference impl
for many OIDC libraries).

## The wire object

A `jwe` group's `ciphertext` (base64 of the cipher-output bytes, per the envelope
schema) decodes to UTF-8 JSON of an RFC 7516 General JSON Serialization object:

```json
{
  "protected": "<b64url({\"enc\":\"A256GCM\"})>",
  "recipients": [
    { "header": { "alg": "ECDH-ES+A256KW",
                  "epk": { "kty": "OKP", "crv": "X25519", "x": "<b64url>" } },
      "encrypted_key": "<b64url A256KW-wrapped CEK>" }
  ],
  "aad": "<b64url marker bytes — present only when a marker is bound>",
  "iv":  "<b64url 96-bit>",
  "ciphertext": "<b64url A256GCM body>",
  "tag": "<b64url>"
}
```

- One `recipients[]` entry per reader; each carries its **own** ephemeral `epk`
  (ECDH-ES+A256KW is per-recipient). Anonymous by default (no `kid`) per D4.
- `aad` present iff a marker is bound (D5); the AEAD binds `protected` (and `aad`
  when present) per RFC 7516 §5.1 — the library computes this.
- The entire object is `g["ciphertext"]`; **no sibling group-dict keys**.

## Keystore

A JWE group's on-disk material:

- `<group>.jwe.recipients` — the recipient list; each entry is a DID plus that
  recipient's raw 32-byte X25519 public key.
- `<group>.jwe.mykey` — this party's static X25519 private (secret; 0600). Its
  presence is what marks a keystore as a reader of the group.
- `<group>.jwe.sender` — a stable per-group X25519 identity anchor (secret;
  0600). ECDH-ES uses a fresh ephemeral key per seal, so this key never seals or
  opens; it is kept only so the ceremony / compile / absorb surface has a stable
  group anchor to read.

## Design tradeoffs

- **Recipient enumeration vs. direct selection (D4).** Default anonymity means
  readers trial-decrypt. At small N this is microseconds; a group opting into
  `kid` trades audience privacy for O(1) block selection.
- **Marker location differs from btn/hibe (D5).** JWE stores the marker in the
  `aad` member (inside `ciphertext`), whereas btn/hibe reconstruct it from
  `tn_aad` and never store it. Both are covered by `row_hash`; the reader
  cross-checks the reconstructed `tn_aad` marker against the embedded `aad`, so a
  tampered `tn_aad` echo fails the AEAD.
- **No forward secrecy across a recipient's static key.** ECDH-ES gives forward
  secrecy w.r.t. the *sender* (ephemeral epk), but a recipient's static X25519
  private still opens all of their past blocks — same as any ECDH-ES deployment.
  Recipient-key rotation is the mitigation.
- **Forward-only revocation.** `revoke` is an O(1) recipient-list edit; the next
  seal omits that block. Pre-revocation records the reader already holds stay
  open. For retroactive lockout, use btn.

## Test plan

- **Standard conformance (the gate):** Python-seal→TS-open and TS-seal→Python-open,
  multi-recipient, with and without an `aad` marker. An independent JOSE tool (or
  the other library) parses the object — proving it is real RFC 7516, not a
  bespoke blob.
- **Cipher interchangeability:** the same caller code writes/reads a group under
  `cipher: btn`, `jwe`, and `hibe` with no branching on cipher kind; all
  round-trip.
- **Envelope coverage:** the JWE JSON lives inside `g["ciphertext"]`; assert
  (a) flipping any byte, (b) swapping a recipient block, (c) stripping the `aad`
  member each break `row_hash`/signature verification; assert Python and TS
  compute an identical `row_hash` for the same jwe envelope; assert no sibling
  group-dict keys.
- **Multi-recipient + revocation:** seal to 3 readers; each opens; `revoke` one;
  the next seal omits their block and they can no longer open new records;
  pre-revocation records they already hold stay open.
- **AAD marker:** open succeeds only with the byte-identical reconstructed
  marker; a wrong/absent marker fails the AEAD; empty marker omits the `aad`
  member and is a clean no-marker seal.
- **Negative:** a non-recipient X25519 key opens nothing; a truncated/garbage JWE
  object errors cleanly (never false plaintext, never crashes host space).
- **Dispatch/validation:** `ceremony.cipher='jwe'` and `groups.<name>.cipher='jwe'`
  are accepted; mint/load build a `JWEGroupCipher`; an unknown cipher raises.
