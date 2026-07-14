# JWE for tn-proto — cipher spec

`cipher: jwe` emits interoperable RFC 7516 JWE. A JWE group's `ciphertext` blob is
a valid JWE **General JSON Serialization** object that any conformant JOSE
implementation can parse, produced by Python's JOSE implementation or the
fixed Rust profile exposed natively and through WebAssembly. A record sealed
by one SDK opens in another by
standard conformance, not by a TN-only frame.

## Non-negotiable constraints

**1. Standard JOSE wire only; no TN-specific crypto container.**
Python uses its maintained JOSE library. Rust implements this fixed profile over
RustCrypto AES-KW/AES-GCM, SHA-256, and Dalek X25519, and TypeScript consumes it
through WebAssembly; it is deliberately not a general JOSE layer. Its release
gate includes bidirectional Rust/Wasm↔Python seal/open and independent managed
C# opening of the same wire bytes. New algorithms or header modes require a
maintained implementation and a spec revision.

**2. The output MUST be interoperable RFC 7516 JWE — the standard is the wire format.**
A JWE group's `ciphertext` blob is a valid JWE General JSON Serialization object
any conformant JOSE implementation can parse. A record sealed by the Python SDK
opens in the TS SDK and vice versa **by standard conformance**, not by shared
bespoke golden vectors. A design choice that would make the output non-standard
(e.g. TN-only external AAD a compliant decryptor can't supply) is disallowed.

**3. btn is the STANDARD / DEFAULT cipher. JWE is one OPTION, never a replacement.**
Groups that don't opt into another cipher stay pure btn. JWE and HIBE are peer
options selected per group via `cipher:`.

**4. JWE is native in Rust and WebAssembly.**
`tn-core` seals and opens this fixed profile using raw X25519 enrollment
material. `tn-wasm` exposes the same implementation as standalone primitives
and through the configured runtime, and TypeScript uses those Rust/Wasm
surfaces for its public JWE primitive API.

## Design decisions — the contract

**D1. Implementation per surface — permissive dependencies.**
- **Python → Authlib / `joserfc` (BSD-3-Clause).** Permissive, actively
  maintained; does multi-recipient General-JSON JWE (`encrypt_json` /
  `decrypt_json`) and RFC 8037 X25519 (OKP). Profile: `alg: ECDH-ES+A256KW`,
  `enc: A256GCM`, recipient key `{kty:OKP, crv:X25519}`, top-level `aad` member.
  **`jwcrypto` (LGPL-3.0) is REJECTED** — it meets every requirement but its
  copyleft posture is incompatible with the permissive-only wheel; permissive is
  a hard requirement.
- **JS/TS → Rust/Wasm fixed profile.** The public `jwe` namespace delegates
  key generation, multi-recipient encryption, and decryption to `tn-wasm` and
  presents synchronous methods plus backward-compatible async delegates.
- **Rust → fixed native profile over audited primitives.** `curve25519-dalek`
  supplies X25519, RustCrypto supplies SHA-256, AES-256-KW, and A256GCM, and
  `serde_json` supplies the strict General JSON shape. No OpenSSL toolchain or
  TN-specific framing is involved. The same implementation builds for wasm.

**D2. Wire format — RFC 7516 JWE General JSON Serialization, stored INSIDE `ciphertext`.**
A JWE group's cipher output is the UTF-8 bytes of the compact JSON of a General
JSON Serialization object (`{protected, recipients[], aad?, iv, ciphertext,
tag}`). Those bytes ARE the group's `ciphertext` field, exactly as btn serializes
its cover inside `ciphertext`. When row hashing is enabled, `row_hash` covers the
entire JWE with **zero** envelope-schema change; a non-empty Ed25519 signature
then covers that stored hash. In an unsigned and unchained profile both fields
are empty sentinels. **No sibling group-dict keys, ever** — a wrapped key, iv, or
tag hoisted beside `ciphertext` would fall outside the group ciphertext input, a
strip/swap vector whenever envelope integrity is enabled. This matches
protocol.md §3's opacity rule.

**D3. Crypto profile — ECDH-ES+A256KW / A256GCM / X25519, ephemeral sender.**
Per recipient: `alg: ECDH-ES+A256KW` (ephemeral-static ECDH-ES derives a KEK,
AES-256 key-wrap of the shared CEK); body `enc: A256GCM` under one fresh CEK;
recipient keys are static X25519 OKP (RFC 8037). JOSE creates a fresh ephemeral
`epk` per recipient block, and that `epk` travels in the block's JWE header, so
recipients need no sender public key out-of-band. There is no long-lived sender
secret in the seal path.

ECDH-ES does not authenticate the sender. TN can supply a separate authorship
claim only when the envelope has a non-empty Ed25519 signature, the consumer
recomputes record integrity and verifies that signature, and the verified DID is
authorized by application policy. Successful JWE decryption alone proves none
of those things. ECDH-1PU would be the JOSE cipher-level sender-auth mechanism;
it is out of scope.

**D4. Recipient privacy — recipient blocks are anonymous.**
Per-recipient headers carry **no identifying `kid`**, so an observer cannot
enumerate the audience from the envelope. Readers **trial-decrypt** the bounded
recipient list; AES-KW integrity and the AEAD tag reject wrong keys with no
false-plaintext risk. Adding a `kid` mode would require a profile and spec
revision because the fixed TN header allowlist is `alg`, `enc`, and `epk`.

**D5. AAD marker — bind via JWE's native `aad` member.**
The TN marker (the AAD "governed flag": authenticated, not encrypted) binds
through JWE's standard top-level `aad` member (RFC 7516). This is the **one**
place JWE differs from the btn/hibe convention (where the marker is not stored in
the ciphertext and is reconstructed from the public `tn_aad` echo at read): in
JWE the marker rides inside the JWE JSON (inside `ciphertext`, so covered by
`row_hash`). This keeps JWE library-native and spec-pure. The public `tn_aad`
echo is unchanged (cross-cipher uniform, publicly inspectable by a proxy without
decrypting); at read the reader reconstructs the marker from `tn_aad` and the
JWE implementation verifies it against the embedded `aad` member (mismatch
fails the tag). Empty marker ⇒ omit the `aad` member (byte-clean no-marker path).

## Framing — JWE is a general-purpose cipher, and it is a *standard*

JWE is a first-class `GroupCipher` peer to `btn` (the default) and `hibe`,
selected per group with `cipher: jwe`. Ordinary emit/read and seal/unseal use the
same application surface for every cipher. Reader enrollment, revocation, and
rotation retain their cipher-specific semantics because JWE enrolls public
X25519 keys rather than minting BTN kits or HIBE path capabilities.

btn and hibe are TN-original schemes, while JWE is an **IETF standard**. TN's
fixed JWE profile is implemented in Rust and exposed through WebAssembly to
TypeScript. Python independently seals and opens the profile. C# ordinary verbs
use the Rust runtime, while its managed second-pass cipher independently opens
recipient blocks. Cross-language fixtures prove every supported direction uses
the same RFC 7516 General JSON wire format.

**When to choose jwe:** the audience is small and enumerated at seal time; you
want a standards-compliant, externally-inspectable envelope; recipients already
hold X25519 keys. **When not to:** you need btn-grade cheap forward revocation at
scale (use btn — jwe revocation is an O(1) recipient-list edit that only affects
future seals), or you seal to someone holding no key yet (HIBE can model that,
but TN's HIBE scheme/pairing implementation is unaudited and evaluation-only
pending external cryptographic review).

## Implementation inventory

| Surface | Implementation | Multi-recipient General JSON | Fixed profile | Runtime |
|---|---|---|---|---|
| Rust | `tn-core` over RustCrypto + Dalek | Yes | `ECDH-ES+A256KW`, X25519, `A256GCM`, optional `aad` | Native |
| WebAssembly / TypeScript | `tn-wasm` exports backed by `tn-core` | Yes | Same Rust profile | Node and browser hosts |
| Python | Authlib / `joserfc` (BSD-3) | Yes | Same interoperable profile | Python |
| C# | Managed platform cryptography | Opens General JSON recipient blocks | Same interoperable profile | .NET |

Keep cryptographic dependencies current and retain strict envelope size limits.
Cross-implementation fixtures are the release gate for profile compatibility.

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
  0600). ECDH-ES uses a fresh ephemeral key for every recipient block, so this
  key never seals or opens; it is kept only so the ceremony / compile / absorb
  surface has a stable group anchor to read.

## Design tradeoffs

- **Recipient anonymity (D4).** Readers trial-decrypt the bounded recipient
  list. The fixed profile intentionally omits `kid`; direct block selection
  would require a new profile because it exposes audience identity.
- **Marker location differs from btn/hibe (D5).** JWE stores the marker in the
  `aad` member (inside `ciphertext`), whereas btn/hibe reconstruct it from
  `tn_aad` and never store it. The reader cross-checks the reconstructed
  `tn_aad` marker against the embedded `aad`, so a tampered echo always fails
  decryption. When a row hash exists, recomputation also fails. In an unsigned
  and unchained profile, `row_hash` and `signature` are empty and AEAD is the
  applicable tamper check. A signature primitive covers the stored row hash, so
  it may still verify while a separate row-hash recomputation detects an edited
  public echo.
- **No forward secrecy across a recipient's static key.** ECDH-ES gives forward
  secrecy w.r.t. the *sender* (ephemeral epk), but a recipient's static X25519
  private still opens all of their past blocks — same as any ECDH-ES deployment.
  Recipient-key rotation is the mitigation.
- **Forward-only revocation.** `revoke` is an O(1) recipient-list edit; the next
  seal omits that block. Pre-revocation records the reader already holds stay
  open. For retroactive lockout, use btn.
- **Rotation requires re-enrollment.** Rotation archives the active JWE files
  and recreates the group with only the publisher self-recipient. Every other
  reader must be re-enrolled before it appears in post-rotation seals.

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
  member each cause composite record rejection when envelope integrity is
  enabled; assert Python and TS compute an identical `row_hash` for the same JWE
  envelope; assert no sibling group-dict keys. In unsigned and unchained mode,
  assert wrong AAD still breaks decryption while the empty hash/signature
  sentinels remain empty.
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
