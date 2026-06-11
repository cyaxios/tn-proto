# tn-proto

Signed, encrypted, append-only logging — one entry per event, with the same wire format in Python, TypeScript, and the browser.

## Install (from TestPyPI)

The packages publish to TestPyPI. Install them from TestPyPI while letting pip pull their ordinary dependencies from regular PyPI:

```bash
pip install --pre -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ tn-proto==0.6.0a1
```

- `-i https://test.pypi.org/simple/` — get the TN packages from TestPyPI.
- `--extra-index-url https://pypi.org/simple/` — get everything else (PyYAML, cryptography, httpx, …) from PyPI.

`tn-proto` is the SDK; `tn-core` and `tn-btn` are the Rust-backed wheels that provide native acceleration and the default `btn` cipher. Pure-Python install (`tn-proto` alone) works too, on the `jwe` cipher.

The current alpha is `v0.6.0a1`. See the [changelog](CHANGELOG.md) for what changed, or the [releases page](https://github.com/cyaxios/tn-proto/releases) for the wheels and sdists.

## Getting started

The first run mints a ceremony at `./.tn/default/` — nothing to configure.

```python
import tn

tn.init()
tn.info("order.created", order_id="A100", amount=4999)
tn.warning("order.flagged", order_id="A100", reason="hold")

for entry in tn.read():
    print(entry.level, entry.event_type, entry.fields)
```

```
info order.created {'amount': 4999, 'order_id': 'A100'}
warning order.flagged {'order_id': 'A100', 'reason': 'hold'}
```

A `tn` CLI ships with the package. Set `TN_NO_STDOUT=1` to silence the stdout echo. There's no explicit flush — the SDK drains on interpreter exit.

### The verbs

| verb | what it does |
|---|---|
| `tn.init(...)` | resolve or create a ceremony, bind the runtime |
| `tn.info / .warning / .error / .debug` | one signed, encrypted entry per call at that level |
| `tn.log(event_type, *, level="", **fields)` | severity-less entry; pass `level=` for a custom level |
| `tn.read(...)` | iterate decoded entries |
| `tn.watch(...)` | tail the log live (async iterator) |
| `tn.absorb / tn.export` | install or produce a `.tnpkg` bundle |
