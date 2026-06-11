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
    cipher: jwe
    fields: [reviewer_did, decision]
```

A single `tn.info(...)` call can fan one event into N groups, each encrypted under that group's readers only. `btn` is the default broadcast cipher (sub-millisecond encrypt, thousands of readers, selective revocation); `jwe` is the pure-Python fallback.

---

## Readers

A reader of a group can decrypt that group's entries. As the publisher you grant read access by minting a **kit** for the reader's DID. The reader installs the kit (or a `.tnpkg` bundle that contains it) and from then on `tn.read` returns decoded entries on their machine.

Python:

```python
import tn
tn.init()

result = tn.admin.add_recipient(
    group="default",
    recipient_did="did:key:z6MkAliceExamplePublicKey",
    out_path="./alice.btn.mykit",
)
print(result.leaf_index, result.kit_path)
# 1 alice.btn.mykit
```

The call writes a `.btn.mykit` file and emits a `tn.recipient.added` admin event.

CLI, one-shot mint plus a `.tnpkg` bundle ready to hand off:

```bash
$ tn add_recipient default alice
[tn add_recipient] wrote /your/cwd/alice.tnpkg
[tn add_recipient]   group:     default
[tn add_recipient]   recipient: did:key:zLabel-alice
```

The CLI form synthesises a `did:key:zLabel-<name>` for friendly labels, mints the kit, and wraps it as a `.tnpkg` in one step.

Revoke a reader when you need to:

```python
tn.admin.revoke_recipient(group="default", leaf_index=1)
```

For `btn` groups the broadcast tree handles thousands of readers with sub-millisecond encrypt. Revocation is selective: the revoked kit stops decrypting, and every other reader keeps working without rekeying.

---

## Bundles

A `.tnpkg` is a signed zip containing a manifest and body files. It is the unit of exchange for everything the dashboard does locally.

Producer:

```python
tn.export(
    "alice.tnpkg",
    kind="kit_bundle",
    to_did="did:key:z6MkAlice...",
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

## Rotation

`tn rotate` writes a new generation of group keys and emits one per-recipient `.tnpkg` artifact for the surviving readers. The CLI runs unattended:

```bash
$ tn rotate
[tn rotate] rotated 1 group(s); emitted 1 .tnpkg artifact(s) into
            /your/cwd/rotated_20260513T224809Z
             default: epoch=1
             -> did_key_zLabel-alice.tnpkg
```

Distribute the per-recipient files however you like (vault push, CI artifact, email). Each reader runs `tn absorb` on theirs. The revoked reader is not in the new generation, so they keep their old entries but cannot read anything written after the rotation.

Everything the dashboard at `vault.tn-proto.org` does (invite a reader by email, watch absorb status, trigger rotations) is backed by this same `.tnpkg` format that `tn.export` and `tn.absorb` produce locally.
