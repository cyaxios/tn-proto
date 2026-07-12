# Groups, readers, bundles, and rotation

This is the full sharing workflow: organize events into encrypted **groups**, grant **readers** access to a group, hand them a **bundle**, and **rotate** keys when access changes.

---

## Groups

A group is a cipher domain. Every event you write lands in one or more groups based on field routing in the yaml. Each group has its own publisher state and its own reader list. Readers of group `payments` can decrypt `payments` events, and only those.

Fresh ceremonies start with two groups:

- `default` — everything you emit without explicit routing.
- `tn.agents` — reserved, used by the protocol for agent-policy events.

Add more in `tn.yaml`:

```yaml
groups:
  default:
    cipher: btn
  payments:
    cipher: btn
    fields: [order_id, amount, card_last4]
  audits:
    cipher: btn
    fields: [reviewer_did, decision]
```

A single `tn.info(...)` call can fan one event into N groups, each encrypted under that group's readers only. `btn` is the broadcast cipher: sub-millisecond encrypt, up to 256 readers per group, selective revocation.

---

## Readers

A reader of a group can decrypt that group's entries. As the publisher you grant read access by minting a **kit** for the reader's DID. The reader installs the kit (or a `.tnpkg` bundle that contains it) and from then on `tn.read` returns decoded entries on their machine.

Two terms that are easy to conflate: a **kit** (`<group>.btn.mykit`) is one reader's raw decryption material; a **bundle** (`.tnpkg`) is a signed zip that wraps a kit plus a manifest, and it is what `tn.absorb` consumes.

Python:

```python
import tn
tn.init()

# Complete reader DID authenticated out of band; do not use a placeholder.
reader_did = authenticated_reader_did
result = tn.admin.add_recipient(
    group="default",
    recipient_did=reader_did,
    out_path="./alice.btn.mykit",
)
print(result.leaf_index, result.kit_path)
# 1 alice.btn.mykit
```

`recipient_did` must be a real `did:key:z6Mk...` device DID (the reader's actual public key). The call writes a `.btn.mykit` file and records a `tn.recipient.added` admin event.

CLI, one-shot mint plus a `.tnpkg` bundle ready to hand off:

```bash
$ tn add_recipient default alice
[tn add_recipient] wrote /your/cwd/alice.tnpkg
[tn add_recipient]   group:     default
[tn add_recipient]   recipient: did:key:zLabel-alice
```

The CLI form synthesises a `did:key:zLabel-<name>` placeholder for friendly labels, mints the kit, and wraps it as a `.tnpkg` in one step. That `zLabel-` form is a CLI-only convenience for local demos, not a valid key: it cannot recipient-seal the package, so the resulting kit body is plaintext bearer material. Do not deliver it as a sensitive grant. A real handoff uses the reader's authenticated, complete Ed25519 `did:key` and fails if it is not resolvable.

Revoke a reader when you need to:

```python
tn.admin.revoke_recipient(group="default", leaf_index=1)
```

For `btn` groups the broadcast tree handles up to 256 readers (height-8 tree; minting past that returns `TreeExhausted`) with sub-millisecond encrypt. Revocation is selective: the revoked kit stops decrypting, and every other reader keeps working without rekeying.

---

## Bundles

A `.tnpkg` is a signed zip containing a manifest and body files. It is the unit of exchange for everything the dashboard does locally.

Producer:

```python
from tn.recipient_seal import recipient_key_is_resolvable

reader_did = authenticated_reader_did
if not recipient_key_is_resolvable(reader_did):
    raise ValueError("reader DID cannot receive a recipient-sealed kit")

tn.export(
    "alice.tnpkg",
    kind="kit_bundle",
    to_did=reader_did,
    seal_for_recipient=True,
)
```

`seal_for_recipient=True` wraps the body under a per-export key that only the named DID can unwrap, so a vault or CDN can host the bundle without being able to read its contents.

Reader:

```python
import tn

# tn.absorb installs INTO an existing ceremony. Run tn.init() first;
# absorb merges the kit material into your current ceremony.
tn.init()
receipt = tn.absorb("./alice.tnpkg")
print(receipt.kind, receipt.accepted_count, receipt.deduped_count)
# kit_bundle 1 0
```

---

## BTN rotation

For a BTN group, revoke and rotate are different operations with different causality. Revoking a leaf stops that reader from decrypting anything written *after* the revoke; it takes effect on the next write and needs no rotation. Rotation additionally retires the whole key generation (a fresh master seed and a new epoch), so reach for it when the key material itself may be compromised, not merely to drop one reader. In both cases a revoked or pre-rotation reader keeps their old entries: neither operation reaches back and rewrites history.

`tn rotate` writes a new generation of group keys and produces one per-recipient `.tnpkg` artifact for each surviving reader. The CLI runs unattended:

```bash
$ tn rotate
[tn rotate] rotated 1 group(s); emitted 1 .tnpkg artifact(s) into
            /your/cwd/rotated_20260513T224809Z
             default: epoch=1
             -> did_key_zLabel-alice.tnpkg
```

Distribute the per-recipient files however you like (vault push, CI artifact, email). Each reader runs `tn absorb` on theirs. The revoked reader is not in the new generation, so they keep their old entries but cannot read anything written after the rotation.

Everything the dashboard at `vault.tn-proto.org` does (invite a reader by email, watch absorb status, trigger rotations) is backed by this same `.tnpkg` format that `tn.export` and `tn.absorb` produce locally.

---

## JWE rotation

JWE does not emit those BTN survivor kits. Rotating a JWE group archives its
active sender, self-reader, and recipient-list files, then recreates the group
with only the publisher's self-recipient. Every external reader must generate
or retain its own `.jwe.mykey` and re-enroll its authenticated X25519 public key
before it appears in post-rotation seals. Never distribute the publisher's
self-recipient private key as a substitute.

---

## HIBE groups

> **Security status:** `tn-bbg` and the underlying `bls12_381_plus` pairing
> library are unaudited. External cryptographic review is required before
> production use. Treat HIBE as evaluation-only until that review is complete.

`hibe` is a third cipher option, peer to `btn` (the default) and `jwe`, selected per group the same way:

```yaml
groups:
  governed:
    cipher: hibe
    fields: [decision, rationale]
```

For a focused walkthrough of JWE and HIBE key material, package handoff, and
the grant ceremony, see [JWE and HIBE key ceremonies](jwe-hibe-key-ceremonies.md).

A hibe group encrypts to an **identity path** (like `reader-did/policy-hash`) under an authority's authenticated, pinned master public key. That gives it two properties the other ciphers don't have:

- **No key exchange at write time.** Anyone holding the authority's public key can seal to a path — including a reader who doesn't hold any key yet.
- **Hierarchical delegation.** A key for a parent path can derive keys for paths below it, locally, with no re-keying and no authority involvement.

The ceremony that mints a hibe group becomes its own authority (it runs setup and keeps its own master secret). Nothing tn-hosted ever holds a decryption root.

### Granting readers

`grant_reader` is hibe's `add_recipient` — the generic `add_recipient` verb also routes here for hibe groups:

```python
from tn.recipient_seal import recipient_key_is_resolvable

reader_did = authenticated_reader_identity  # complete Ed25519 did:key
if not recipient_key_is_resolvable(reader_did):
    raise ValueError("reader DID cannot receive a recipient-sealed HIBE kit")

result = tn.admin.grant_reader(
    "governed",
    reader_did=reader_did,
    out_path="./alice.tnpkg",
)
```

The bundle carries the authority's public key, the group's identity path, and a freshly minted identity key. Each grant gets independently randomized key material for the same path, and every grantee decrypts the same entries. The `.hibe.sk` is a bearer capability, not a key bound to `reader_did`; when the DID is not a complete resolvable Ed25519 `did:key`, `grant_reader` silently falls back to a plaintext package. The reader absorbs the securely delivered kit with `tn.absorb`. The authority's master secret never rides a reader bundle; it only appears in a self-addressed full-keystore backup.

### Revocation: the honest tradeoff

Choose the cipher by its revocation story. **btn revokes forward**: drop a reader and the next write already excludes them. **hibe cannot do that**: a delegated key is a permanent trapdoor for its path — once admitted, a reader opens everything ever sealed to that path, past and future. What hibe offers instead is **path rotation**:

```python
tn.admin.rotate_reader_path("governed", "policy-b")
```

Future seals from the updated authority target the new path, so holders of exact old-path keys stop reading those new entries; everything sealed before the rotation stays open to them forever. External writers keep their own local path and must receive, authenticate, and pin the new sibling path before sealing again, or the old exact-path reader still opens their output. A grantee holding an *ancestor* key is a delegated subauthority for that subtree and cannot be cut off by rotation beneath it. Grant exact paths when rotation must cut access; if an ancestor capability has already escaped, move to a fresh authority MPK or use BTN. If a group genuinely needs routine per-reader forward revocation, use BTN for that group. That's what the default is for.

### If the authority's master secret leaks

The master secret can mint a key for any path under its public key, which means whoever holds it can read every entry ever sealed by that group. There is no partial fix:

1. Stop sealing under the compromised authority immediately.
2. Run a fresh setup (a new authority) and point the group at it — this is a new cipher domain, equivalent to minting the group fresh.
3. Re-grant every legitimate reader under the new authority.
4. Treat everything sealed under the old authority as readable by the attacker. Rotation cannot claw it back; that history's confidentiality is bounded by whatever the attacker captured.

Because each ceremony is its own authority, the blast radius of a leak is that one ceremony's hibe groups — never anyone else's.
