# The HIBE primitive library

This is the developer reference for the **low-level HIBE crypto primitives** —
the bytes-in/bytes-out functions underneath the `cipher: hibe` group option.
This page is for building directly on the scheme, below the product workflow
(`tn.info`, `grant_reader`, `tn.absorb`).

The scheme is BBG (Boneh-Boyen-Goh, constant-size ciphertext) on BLS12-381,
implemented in the `tn-bbg` crate and re-exported by `tn-hibe`. The same
surface is exposed in three places, **byte-identical across all of them**:

| Surface | Import |
|---|---|
| Rust | `tn_hibe::*` (re-exports `tn_bbg`) |
| Python | `from tn import _hibe` |
| JS / TS | the `hibe*` exports from `tn-wasm` (re-exported by the TS SDK's `raw`) |

Every value that crosses a function boundary is raw bytes (keys, blobs,
wrapped CEKs) except identity paths, which are strings. That is deliberate:
you can store and ship these bytes with anything, and no language owns the
wire format.

> Every code block and output block below is real. Byte-value previews are
> random per run; the sizes are fixed for a given `(max_depth, path depth)`.

---

## The operations

| Operation | Rust (`tn_hibe`) | Python (`tn._hibe`) | JS (`tn-wasm`) |
|---|---|---|---|
| Set up a system | `setup(max_depth, rng)` | `setup(max_depth)` | `hibeSetup(maxDepth)` |
| Mint a reader key | `keygen(&pp, &msk, &id, rng)` | `keygen(mpk, msk, id_path)` | `hibeKeygen(mpk, msk, idPath)` |
| Delegate a child key | `delegate(&pp, &parent, label, rng)` | `delegate(mpk, parent_sk, label)` | `hibeDelegate(mpk, parentSk, label)` |
| A key's identity path | `sk.identity()` | `key_id_path(sk)` | `hibeKeyIdPath(sk)` |
| Seal a body | `seal` / `seal_with_aad` | `seal(mpk, id_path, pt[, aad])` | `hibeSeal(mpk, idPath, pt, aad?)` |
| Open a body | `open` / `open_with_aad` | `open(mpk, sk, blob[, aad])` | `hibeOpen(mpk, sk, blob, aad?)` |
| Wrap a 32-byte CEK | `kem_wrap` | `kem_wrap(mpk, id_path, cek)` | `hibeKemWrap(mpk, idPath, cek)` |
| Unwrap a CEK | `kem_unwrap` | `kem_unwrap(mpk, sk, wrapped)` | `hibeKemUnwrap(mpk, sk, wrapped)` |
| Fingerprint an mpk | `mpk_fingerprint(&pp)` | `mpk_fingerprint(mpk)` | `hibeMpkFingerprint(mpk)` |
| An mpk's max depth | `pp.max_depth()` | `mpk_max_depth(mpk)` | `hibeMpkMaxDepth(mpk)` |

The four key artifacts are the same everywhere: **mpk** (master public key —
shareable), **msk** (master secret — authority only), a **reader key** (`sk`,
opens one identity path), and the **identity path** string.

---

## Python (`tn._hibe`)

```python
from tn import _hibe

# One authority's system keypair (max_depth = deepest identity path allowed).
mpk, msk = _hibe.setup(2)
_hibe.mpk_fingerprint(mpk)          # 32 bytes — what a manifest pins
_hibe.mpk_max_depth(mpk)            # 2  (also validates the mpk bytes)

# Mint a reader key for an identity path from the master secret.
sk = _hibe.keygen(mpk, msk, "alice/reports")
_hibe.key_id_path(sk)               # 'alice/reports'

# Seal a body to a path (writer needs only mpk + path); open with the key.
blob = _hibe.seal(mpk, "alice/reports", b"quarterly numbers")
_hibe.open(mpk, sk, blob)           # b'quarterly numbers'

# Bind a marker: authenticated into the tag, not encrypted, not stored.
gov = _hibe.seal(mpk, "alice/reports", b"governed body", b"policy=finra-oba")
_hibe.open(mpk, sk, gov, b"policy=finra-oba")   # b'governed body'
_hibe.open(mpk, sk, gov, b"policy=other")       # raises HibeCryptoError

# Wrap/unwrap a 32-byte content key directly (the KEM half).
wrapped = _hibe.kem_wrap(mpk, "alice/reports", cek)
_hibe.kem_unwrap(mpk, sk, wrapped)  # == cek

# A parent key delegates a child key with no master secret.
parent = _hibe.keygen(mpk, msk, "alice")
child  = _hibe.delegate(mpk, parent, "reports")   # opens 'alice/reports'
```

```
==================================================================
setup(max_depth) -> (mpk, msk)
==================================================================
mpk (public, shareable) : 010297f1d3a73197... (482 bytes)
msk (secret, authority) : 0180a1f41bf89e79... (97 bytes)
mpk_fingerprint(mpk)    : 36fdadd9c571cd0ac939082c5b8b53554972554091975ef4f9bc21ffd1751444
mpk_max_depth(mpk)      : 2

==================================================================
keygen(mpk, msk, id_path) -> sk
==================================================================
sk for 'alice/reports'  : 01020005616c6963... (163 bytes)
key_id_path(sk)         : 'alice/reports'

==================================================================
seal(mpk, id_path, plaintext[, aad]) / open(mpk, sk, blob[, aad])
==================================================================
sealed blob             : 0101a830daa0257e... (251 bytes)
open with alice's sk    : b'quarterly numbers'
open with correct aad   : b'governed body'
open with wrong aad     : HibeCryptoError (marker mismatch)

==================================================================
kem_wrap(mpk, id_path, cek32) / kem_unwrap(mpk, sk, wrapped)
==================================================================
wrapped CEK             : 01b6a81c8399ebeb... (205 bytes)
unwrap == original CEK  : True

==================================================================
delegate(mpk, parent_sk, child_label) -> child_sk
==================================================================
delegated child path    : 'alice/reports'
child opens alice/reports blob: b'quarterly numbers'
```

Failures are **fail-closed**: a key on the wrong path, a wrong AAD marker, or
any flipped byte raises `HibeCryptoError` (or `ValueError` for malformed
bytes) — you never get back wrong plaintext.

---

## Rust (`tn_hibe`)

The Rust surface takes an explicit `rng: impl RngCore` (use `rand_core::OsRng`)
and returns typed `Result`s. Keys and blobs are the byte encodings via
`to_bytes()` / `from_bytes()`.

```rust
use rand_core::OsRng;
use tn_hibe::{setup, keygen, delegate, seal, seal_with_aad, open, open_with_aad,
              kem_wrap, kem_unwrap, mpk_fingerprint, Identity, PublicParams, PrivateKey};

let (pp, msk) = setup(2, OsRng)?;                 // PublicParams + MasterKey
let mpk = pp.to_bytes();                          // ship this
let _fp = mpk_fingerprint(&pp);                   // [u8; 32]

let id = Identity::from_str_path("alice/reports");
let sk = keygen(&pp, &msk, &id, OsRng)?;

let blob = seal(&pp, &id, b"quarterly numbers", OsRng)?;
assert_eq!(open(&pp, &sk, &blob)?, b"quarterly numbers");

let gov = seal_with_aad(&pp, &id, b"governed body", b"policy=finra-oba", OsRng)?;
assert_eq!(open_with_aad(&pp, &sk, &gov, b"policy=finra-oba")?, b"governed body");
assert!(open_with_aad(&pp, &sk, &gov, b"policy=other").is_err());

let wrapped = kem_wrap(&pp, &id, &[7u8; 32], OsRng)?;
assert_eq!(kem_unwrap(&pp, &sk, &wrapped)?, [7u8; 32]);

let parent = keygen(&pp, &msk, &Identity::from_str_path("alice"), OsRng)?;
let child  = delegate(&pp, &parent, b"reports", OsRng)?;   // opens alice/reports

// Serialize anything; from_bytes round-trips.
assert_eq!(PublicParams::from_bytes(&mpk)?, pp);
assert_eq!(PrivateKey::from_bytes(&sk.to_bytes())?, sk);
```

```
setup           mpk: 010297f1d3a73197... (482 bytes)
mpk_fingerprint    : 5dc0a4f9dbf261d79bd7ac63a816a6e1d0eb9c952e3feba541c6e15f9c5b343d
max_depth          : 2
keygen           sk: 01020005616c6963... (163 bytes)
seal/open (+aad)   : ok (wrong aad rejected)
kem_wrap/unwrap    : 01acef6b6260c7cd... (205 bytes) round-trip ok
delegate           : alice -> alice/reports opens the blob
encodings          : round-trip ok
```

Rust additionally exposes the raw scheme — `encrypt`/`decrypt` over a GT
element, plus `gt_to_bytes`/`gt_from_bytes`. These exist for the golden-vector
fixtures only; **do not use them on the wire** (see the KEM rule below).
Python and JS deliberately omit them.

---

## JS / TypeScript (`tn-wasm`)

`hibeSetup` returns base64 strings (`{ mpk_b64, msk_b64 }`); everything else is
`Uint8Array` in and out. The AAD argument is optional (`undefined` = none).

```js
const w = await import("tn-wasm");                // or the TS SDK's `raw`

const { mpk_b64, msk_b64 } = w.hibeSetup(2);
const mpk = b64(mpk_b64), msk = b64(msk_b64);
w.hibeMpkFingerprint(mpk);                        // Uint8Array(32)
w.hibeMpkMaxDepth(mpk);                           // 2

const sk = w.hibeKeygen(mpk, msk, "alice/reports");
w.hibeKeyIdPath(sk);                              // "alice/reports"

const blob = w.hibeSeal(mpk, "alice/reports", enc("quarterly numbers"), undefined);
dec(w.hibeOpen(mpk, sk, blob, undefined));        // "quarterly numbers"

const gov = w.hibeSeal(mpk, "alice/reports", enc("governed body"), enc("policy=finra-oba"));
dec(w.hibeOpen(mpk, sk, gov, enc("policy=finra-oba")));   // "governed body"
// w.hibeOpen(mpk, sk, gov, enc("policy=other"))  throws

const wrapped = w.hibeKemWrap(mpk, "alice/reports", cek);
w.hibeKemUnwrap(mpk, sk, wrapped);                // == cek

const parent = w.hibeKeygen(mpk, msk, "alice");
const child  = w.hibeDelegate(mpk, parent, "reports");    // opens alice/reports
```

```
hibeSetup            mpk: 010297f1d3a73197... (482 bytes)  msk: 0193157614d6ac53... (97 bytes)
hibeMpkFingerprint      : 54a1253347510cc48bf50271fb64c610ec4a10d65e2c95afd734da03ea1e8205
hibeMpkMaxDepth         : 2
hibeKeygen           sk : 01020005616c6963... (163 bytes)  path: alice/reports
hibeSeal/hibeOpen (+aad): ok (wrong aad rejected)
hibeKemWrap/Unwrap      : 0196120ed12d7c12... (205 bytes)  round-trip ok
hibeDelegate            : alice -> alice/reports opens the blob
```

Notice the sizes match Python and Rust exactly (`mpk=482`, `msk=97`,
`sk=163`, `wrapped_cek=205`). That is the cross-impl guarantee: a key or blob
made on any surface is opened by any other.

---

## Wire format and rules

**Sizes** (max_depth 2, path depth 2), from the runs above — all three impls
agree byte-for-byte:

```
mpk=482   msk=97   sk=163   wrapped_cek=205   fingerprint=32
```

`sk` size varies with `max_depth − path_depth` (it carries one group element
per remaining delegatable level); `mpk` grows with `max_depth`. `open` on a
sealed blob returns the exact plaintext bytes.

**KEM-not-direct — the one rule you must not break.** A raw GT element is
never placed on the wire. `kem_wrap` derives an AES-256-GCM key from the shared
GT element with HKDF-SHA256 and ships only the AEAD output plus two compressed
group points; `seal` does the same for a whole body. This is what makes the
bytes canonical across implementations — there is no GT serialization to
disagree on. Never serialize a GT element into anything you store or send.

**AAD markers** bind a string into the body's authentication tag: authenticated,
not encrypted, and **not stored** in the blob. A reader must supply the
identical bytes to open. Empty AAD is byte-identical to a plain seal, so it
costs nothing when unused.

**Fail-closed.** Wrong path, wrong AAD, or a tampered byte always errors — the
primitives never return incorrect plaintext.

**Trust model.** `setup` is per-authority: whoever holds the `msk` can mint a
key for any path and read everything under that mpk. Keep it off the wire —
only mpk, identity paths, and per-reader keys are meant to travel.

---

## Security status

The scheme (`tn-bbg`) and the underlying `bls12_381_plus` pairing library are
**unaudited**. An external cryptographic review is required before production
use. Delegated keys are permanent — there is no forward revocation of an
admitted reader at the primitive level (rotate the identity path instead).
