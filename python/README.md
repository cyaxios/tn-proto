# tn-protocol

TestigoNodo (TN) Python SDK — attested logging with broadcast encryption
(`btn`) and JWE ciphers.

```bash
pip install tn-protocol
```

## Library

```python
import tn

tn.init("./tn.yaml")            # discovery: $TN_YAML, ./tn.yaml, .tn/default/, ~/.tn/
tn.info("order.created", order_id="A100", amount=4999)

for entry in tn.read():         # yields typed Entry instances
    print(entry.event_type, entry.fields.get("order_id"))

tn.flush_and_close()
```

Dirt-easy bootstrap from a dashboard-minted bundle:

```python
import tn
tn.absorb("Agentic20.project.tnpkg")   # implicit init binds the runtime
tn.info("hello.world", who="alice")    # works immediately, no tn.init() needed
```

## CLI

`tn` (or `python -m tn.cli`) ships CI-shaped verbs that run unattended —
no interactive prompts unless a TTY is detected:

```bash
tn init ./project --no-link            # provision identity + ceremony
                                       # (non-TTY: mnemonic persisted into
                                       #  identity.json, treat as a secret)

tn add_recipient default alice         # mint+bundle a kit for "alice"

tn rotate                              # deploy primitive: rotate every
                                       # non-internal group + emit one
                                       # .tnpkg artifact per surviving
                                       # recipient under ./rotated_<UTC_TS>/

tn rotate default --out ./out/         # rotate one group, custom output
tn rotate --groups a,b --out file.tnpkg  # subset, single-recipient only

tn absorb ./alice.tnpkg                # install someone's kit_bundle
tn read                                # print decoded entries
```

Vault-linked ceremonies push the new state via `_maybe_autosync` as a
side effect of `tn rotate`; the vault then drives recipient notification.
Vault-less projects use the per-recipient `.tnpkg` files as the
distribution channel — typically uploaded as a CI build artifact.

Source, docs, and issue tracker: https://github.com/cyaxios/tn-proto

License: Apache-2.0
