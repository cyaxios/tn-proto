# Using the HIBE cipher

HIBE (Hierarchical Identity-Based Encryption) is a third group cipher in
tn-proto, alongside `btn` (the default) and `jwe`. This guide explains its
key material — which is the part that trips people up — and shows how to
pass keys around, all with real code and real output.

Every code block below is real code, and every output block is its actual
stdout. The byte values (hex previews) are random per run; the sizes and
structure are stable.

> HIBE seals to a named identity path using an authority's public key. The
> authority can issue reader keys before or after records are sealed. BTN
> manages reader admission and revocation through a broadcast tree.

---

## 1. The key material

A HIBE system has **one keypair for the whole group**, plus **per-reader
keys minted from it**. Four things exist; keep them straight:

| Name | File | Secret? | Who holds it | What it does |
|------|------|---------|--------------|--------------|
| **mpk** (master public key) | `<group>.hibe.mpk` | no — shareable | everyone | seal to any identity path; compute a byte identifier that must be authenticated before it is trusted |
| **msk** (master secret) | `<group>.hibe.msk` | **yes — never leaves the authority** | the authority only | mint reader keys for any path |
| **sk** (reader key) | `<group>.hibe.sk` | yes | one reader | open blobs sealed to that reader's path |
| **idpath** (identity path) | `<group>.hibe.idpath` | no | the group | the string a group seals to, e.g. `alice` or `engineering/alice` |

The unfamiliar idea: **you seal to a *path string*, not to a recipient's
public key.** There is no per-recipient key exchange at write time. The
writer needs only the mpk and a path.

```python
from tn import _hibe

# An authority runs Setup once. It produces a keypair for the WHOLE
# system: one public master key (mpk) and one master secret (msk).
mpk, msk = _hibe.setup(2)  # max_depth=2: paths up to 2 labels deep
print(f"mpk (master public key, SHAREABLE) : {h(mpk)}")
print(f"msk (master secret, AUTHORITY ONLY): {h(msk)}")
print(f"mpk fingerprint (byte identifier only): {_hibe.mpk_fingerprint(mpk).hex()}")

# From the msk the authority mints a reader key (sk) for an IDENTITY
# PATH. The path is just a string; there is no per-reader key exchange.
alice_sk = _hibe.keygen(mpk, msk, "alice")
print(f"\nalice's reader key for path 'alice': {h(alice_sk)}")
print(f"  the key knows its own path: {_hibe.key_id_path(alice_sk)!r}")

# Anyone with the mpk can seal to a path WITHOUT holding a key for it.
blob = _hibe.seal(mpk, "alice", b"hello alice")

# Only a key on that path opens it.
opened = _hibe.open(mpk, alice_sk, blob)

# A key for a DIFFERENT path cannot.
bob_sk = _hibe.keygen(mpk, msk, "bob")
_hibe.open(mpk, bob_sk, blob)  # raises HibeCryptoError
```

```
======================================================================
PART 1 - the key material
======================================================================
mpk (master public key, SHAREABLE) : 010297f1d3a73197... (482 bytes)
msk (master secret, AUTHORITY ONLY): 018a21f09d7dad21... (97 bytes)
mpk fingerprint (byte identifier only): 5526e45f38deb3f9c6eae0d413844672f6b8d238044b00443afa1b414f7ad12e

alice's reader key for path 'alice': 01010005616c6963... (250 bytes)
  the key knows its own path: 'alice'

sealed to 'alice' with only the mpk: 0101a54bc7c13904... (245 bytes)
alice opens it: b'hello alice'
bob's key refuses alice's blob (HibeCryptoError)
```

Takeaways:

- The **mpk is safe to publish.** Handing it out lets people seal *to* your
  identity paths; it never lets them read.
- The **fingerprint identifies MPK bytes; it does not authenticate them.**
  Obtain the expected fingerprint through an authenticated channel or a signed
  statement from an already trusted authority, then compare it before sealing.
- The **msk is the crown jewel.** Whoever holds it can mint a key for any
  path and therefore read everything. It stays with the authority.
- A **reader key carries its own path** (`key_id_path` reads it back). It opens
  that path and can derive exact descendant keys within the remaining
  `max_depth`, so an ancestor-key holder is a delegated subtree authority.

---

## 2. The hierarchy: reader keys make more reader keys

The "H" in HIBE. A reader key for a parent path can **derive child keys by
itself**, without the master secret. This is how you delegate authority
downward without funnelling every request back to the msk holder.

```python
mpk, msk = _hibe.setup(3)
# The authority hands a DEPARTMENT key one level down.
dept_sk = _hibe.keygen(mpk, msk, "engineering")

# The department, holding only that key and the mpk (NO msk), derives a
# key for a child path locally.
alice_sk = _hibe.delegate(mpk, dept_sk, "alice")
print(f"department delegated -> {_hibe.key_id_path(alice_sk)!r}")

blob = _hibe.seal(mpk, "engineering/alice", b"design review notes")
assert _hibe.open(mpk, alice_sk, blob) == b"design review notes"

# The parent (department) key also opens the child's path, by deriving down.
alice_again = _hibe.delegate(mpk, dept_sk, "alice")
assert _hibe.open(mpk, alice_again, blob) == b"design review notes"
```

```
======================================================================
PART 2 - the hierarchy (delegation without the master secret)
======================================================================
authority minted 'engineering' key: 0101000b656e6769... (352 bytes)
department delegated -> 'engineering/alice': 'engineering/alice'
  (no master secret was used or needed)
alice's delegated key opens a blob sealed to her full path: ok
the department key spans everything beneath it: ok
```

So a key for `engineering` can read `engineering`, `engineering/alice`,
`engineering/bob`, and so on — it derives down as needed. A key for
`engineering/alice` can read only at or below its own path. This is exactly
what makes the ancestor-vs-exact-path distinction matter for rotation
(see §4).

`max_depth` (the argument to `setup`) is the deepest path the system
allows: `setup(3)` supports up to three labels like
`engineering/alice/2026`.

---

## 3. The everyday workflow

You rarely touch `_hibe` directly. The product surface is `tn.init`,
`tn.info`, `tn.admin.grant_reader`, and `tn.absorb` — identical to how you
use btn or jwe, just with `cipher="hibe"`.

The keys move like this:

```
AUTHORITY keystore                          READER keystore
------------------                          ---------------
default.hibe.msk   (stays here, always)
default.hibe.mpk  ─┐
default.hibe.idpath├─ grant_reader ──┐
(fresh reader sk) ─┘   packs a       │
                       .tnpkg kit ────┼─ tn.absorb ─→ default.hibe.mpk
                                      │                default.hibe.idpath
                                      │                default.hibe.sk
```

The reader kit contains a delegated `.hibe.sk` bearer capability and public
authority material. `grant_reader` requires a complete Ed25519 `did:key` and a
valid scoped proof of reader key possession, then recipient-seals the kit.
Plaintext delivery requires the explicit `unsafe_plaintext=True` option.

The following local walkthrough retains separate reader and authority
configurations. In separate processes, exchange the challenge and proof as
shown in the [HIBE enrollment workflow](jwe-hibe-key-ceremonies.md#hibe-reader-enrollment).

```python
from tn.recipient_seal import recipient_key_is_resolvable

# Alice creates her own ceremony and retains its signing identity.
tn.init(reader_yaml, log_path=ws / "alice" / "log.ndjson")
reader_cfg = tn.current_config()
alice_did = reader_cfg.device.device_identity
tn.flush_and_close()

# 1. The authority starts a hibe ceremony. It becomes its OWN authority:
#    Setup runs, the msk stays in this keystore.
tn.init(authority_yaml, log_path=authority_log, cipher="hibe")
authority_cfg = tn.current_config()

# 2. Log some governed entries.
tn.info("decision.recorded", subject="loan-4821", outcome="approved")
tn.info("decision.recorded", subject="loan-4822", outcome="declined")

# 3. The authority challenges Alice; Alice signs using her own ceremony.
if not recipient_key_is_resolvable(alice_did):
    raise ValueError("Alice DID cannot receive a recipient-sealed HIBE kit")
challenge = tn.admin.issue_hibe_reader_challenge("default", alice_did)
alice_proof = tn.admin.create_hibe_reader_proof(
    challenge,
    expected_authority_did=authority_cfg.device.device_identity,
    cfg=reader_cfg,
)
kit = ws / "alice.tnpkg"
tn.admin.grant_reader(
    "default", reader_did=alice_did, proof=alice_proof, out_path=kit
)
tn.flush_and_close()

# 4. The reader is a separate person with their own ceremony. They
#    absorb the kit, and can now read the authority's log.
tn.init(reader_yaml, log_path=ws / "alice" / "log.ndjson")
reader_cfg = tn.current_config()
tn.absorb(kit)

entries = list(
    tn.reader.read_as_recipient(authority_log, reader_cfg.keystore, group="default")
)
for e in entries:
    body = e["plaintext"]["default"]
    print(f"  read: {body['subject']} -> {body['outcome']}")
```

```
======================================================================
PART 3 - the product workflow (tn.init / grant_reader / absorb)
======================================================================
authority ceremony cipher: hibe
key files written: ['default.hibe.idpath', 'default.hibe.mpk', 'default.hibe.msk', 'default.hibe.sk']
logged 2 entries under the 'default' hibe group
granted reader; kit written to: alice.tnpkg
kit body is recipient-sealed: ['encrypted.bin']
  (note: NO .hibe.msk — the master secret never leaves the authority)

reader absorbed the kit: accepted=3
  read: loan-4821 -> approved
  read: loan-4822 -> declined
```

A fresh `cipher="hibe"` ceremony becomes **its own authority** — it runs
Setup and keeps the msk locally. That is the recommended trust model: no
tn-hosted service ever holds a decryption root, and a compromise is bounded
to that one ceremony. (To seal to an *external* authority's path instead,
pass `authority_mpk=` and `id_path=` to the group's `create` — the keystore
can then write but cannot read until a granted key arrives.)

Note the kit carries three files and no msk. `accepted=3` in the absorb
receipt is exactly those three files landing in the reader's keystore. The
recipient-sealed package protects the bearer key in transit; possession after
absorb remains the capability.

---

## 4. Adding and removing readers

**Adding** is just another `grant_reader` — call it once per reader. Each
grant mints independent key material for the same path, and each grantee
decrypts the same entries.

`revoke_reader` rotates the sealing path and issues replacement kits to the
surviving readers. Each writer must adopt the new path before its next seal:

```python
# alice_did and bob_did are complete Ed25519 did:key values.
# alice_proof and bob_proof are their fresh scoped challenge responses,
# obtained through the enrollment exchange above for this authority and path.
for reader_did in (alice_did, bob_did):
    if not recipient_key_is_resolvable(reader_did):
        raise ValueError("reader DID cannot receive a sealed HIBE grant")

tn.init(a_yaml, log_path=a_log, cipher="hibe")
tn.info("memo", text="visible to both readers")
tn.admin.grant_reader(
    "default", reader_did=alice_did, proof=alice_proof, out_path=alice_kit
)
tn.admin.grant_reader(
    "default", reader_did=bob_did, proof=bob_proof, out_path=bob_kit
)

# Remove bob. The path rotates and every SURVIVOR gets a re-issued kit.
res = tn.admin.revoke_reader("default", bob_did, out_dir=ws / "regrant")
print(f"revoked bob; new sealing path = {res.new_path!r}")
print(f"survivors re-kitted: {len(res.remaining)}")
tn.info("memo", text="sealed AFTER bob was removed")
```

```
======================================================================
PART 4 - removing a reader (revoke = rotate + re-issue)
======================================================================
granted alice and bob
revoked bob; new sealing path = 'self~r1'
survivors re-kitted: 1

bob's view after removal:
  seq 1: visible to both readers
  seq 2: {'$no_read_key': True}
  (bob keeps the pre-removal memo, is locked out of the new one)
```

What happened:

- `revoke_reader` bumped this authority ceremony's sealing path from `self` to
  `self~r1`, dropped bob from the grant registry, and wrote a fresh kit for
  alice into `out_dir`. Distribute those kits; each survivor runs `tn.absorb`
  on theirs and keeps reading seamlessly (their superseded key stays in the
  keystore for the old entries).
- Bob still opens `seq 1` (sealed before the rotation) and gets
  `{'$no_read_key': True}` for `seq 2` (sealed to the new path he was never
  given) in this local-authority example.
- Separate external writers retain their own `.hibe.idpath`. Deliver the
  authenticated sibling path to each writer and reload its configuration.
- A parent-path key can derive descendants within its depth budget. Use
  exact-path grants for the readers in this rotation flow.

---

## Binding a policy marker to a governed body (AAD)

Sometimes you want to weld a marker — a governance policy id, a tenant, an
epoch — to an encrypted body so it **cannot be stripped or swapped without
breaking decryption**. Pass an `aad` dict to the emit call:

```python
tn.init(a_yaml, log_path=a_log, cipher="hibe")
tn.info("oba.filed", note="quarterly OBA", aad={"policy": "finra-oba", "v": "1"})
tn.flush_and_close()

# The marker rides in the record's public section as a canonical string.
line = [ln for ln in a_log.read_text(encoding="utf-8").splitlines() if ln][0]
env = json.loads(line)
print(f"public tn_aad echo: {env['tn_aad']!r}")

# A legitimate read reconstructs the marker and opens the body.
rec = next(e for e in tn.reader.read(a_log, cfg))
print(f"row_hash valid: {rec['valid']['row_hash']}, decrypts: {rec['plaintext']['default']}")

# This example uses a signed, chained profile. Tampering the marker makes
# decryption and row-hash recomputation fail.
tampered = env.copy()
tampered["tn_aad"] = env["tn_aad"].replace("finra-oba", "swapped-policy")
# ... write it back, reopen ...
```

```
======================================================================
PART 5 - welding a policy marker (the AAD dict)
======================================================================
public tn_aad echo (a canonical JSON string): '{"default":{"policy":"finra-oba","v":"1"}}'
row_hash valid: True, decrypts: {'note': 'quarterly OBA', 'run_id': '4d757b0cf3ec4784a3820bfe27857ba5'}
after swapping the marker -> row_hash valid: False, body: {'$no_read_key': True}
```

How it works:

- The `aad` dict is authenticated into the body's encryption tag — **not
  encrypted, not secret.** A reader must reconstruct the identical bytes to
  open the body.
- So the effective dict (a group's config `aad:` default merged with the
  per-emit `aad=`, per-emit winning per key) is **echoed into the public
  `tn_aad` field** as a canonical JSON string keyed by group. The reader
  reconstructs the marker from it, so changing the echo always prevents
  decryption. When row hashing is enabled, recomputation also fails. A raw
  signature check over the unchanged stored row hash may still pass while the
  composite integrity check fails. In an unsigned and unchained profile,
  `row_hash` and `signature` stay empty and the body AEAD is the applicable
  tamper check. A record that binds no marker carries no `tn_aad` field and is
  byte-identical to before.
- Set a default for a whole group in the yaml:

  ```yaml
  groups:
    governed:
      cipher: hibe
      aad: { policy: "finra-oba" }
  ```

The Python emit pipeline accepts `aad=` on BTN, JWE, and HIBE groups. The
native BTN runtime and the Python cipher implementations bind the supplied
marker bytes and check them when opening the body.

---

## Quick reference: who gets which key

| Actor | Holds | Never holds | Can |
|-------|-------|-------------|-----|
| Authority | msk, mpk, own sk, idpath | — | mint any reader key, seal, read everything, rotate its local path and reissue exact-path grants |
| Granted reader | mpk, idpath, one bearer sk | msk | read its path and deliberately derive descendants, making an ancestor holder a subtree subauthority |
| A writer-only party | authenticated/pinned mpk, idpath | msk, any sk | seal to the path; **not** read, authenticate, or authorize itself |
| The wire (a recipient-sealed `.tnpkg` kit) | mpk, idpath, one bearer sk | **msk** | protect delivery only when addressed to a resolvable Ed25519 `did:key` |

Rules that hold everywhere:

- **The msk never rides a kit** and is refused by `absorb` from any package
  that is not a self-addressed backup. It only appears in the authority's
  own keystore (or a full-keystore restore of that same identity).
- **Sealing needs only the mpk + a path.** Reading needs a key on that path
  (or an ancestor of it). That public sealing operation provides no writer
  authentication or authorization.
- **The blob rides inside the group's `ciphertext`** exactly like btn/jwe,
  with no envelope change. Row hashing, chaining, signing, verification, and
  trusted-writer authorization are separate profile/consumer controls; a
  successful HIBE open proves only possession of a suitable reader capability.
