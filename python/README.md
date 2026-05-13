# tn-protocol

TestigoNodo (TN) Python SDK — attested logging with broadcast encryption
(`btn`) and JWE ciphers.

```bash
pip install tn-protocol
```

## Library — Hello, TN

The smallest useful program (no yaml file required — first run auto-creates `./.tn/default/tn.yaml`):

```python
import tn

tn.init()                                                    # auto-creates a ceremony on first run
tn.info("order.created", order_id="A100", amount=4999)
tn.info("order.shipped", order_id="A100", carrier="ups")

for entry in tn.read():                                      # yields typed Entry instances
    print(entry.event_type, entry.fields.get("order_id"))
```

You can also pass an explicit yaml path or pick a different ceremony:

```python
tn.init("./tn.yaml")            # use this specific file (legacy path form)
tn.init(name="payments")        # named ceremony at ./.tn/payments/
tn.init(stream="pod-1")         # mint+open a stream of the default ceremony
```

Discovery chain when no args are passed: `$TN_YAML` → `./tn.yaml` → `./.tn/default/tn.yaml` → `$TN_HOME/tn.yaml`, then mints if nothing's there.

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
