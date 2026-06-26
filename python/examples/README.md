# Examples

Progressive scenarios that teach the `tn.*` SDK from "hello world" to
rotation, fan-out, and revocation. Each `ex0*.py` file is self-contained:
it creates its own ceremony in a temporary directory and tears it down at
the end, so there are no prerequisites. You do not need to run `tn init`
first, and nothing is written outside the temp dir.

Run any one of them directly:

```
python examples/ex01_hello.py
```

The `ex0*` files are also executed by
[`tests/test_examples.py`](../tests/test_examples.py) on every commit, so
the numbers and output strings the primer cites stay current. For the
narrative version, see [`docs/primer.md`](../docs/primer.md).

## Walkthrough examples

| File | Demonstrates | Run |
|---|---|---|
| `ex01_hello.py` | First `tn.init()`, three `tn.info()` entries, `tn.read()` them back as flat dicts. | `python examples/ex01_hello.py` |
| `ex02_reading.py` | Envelope shape, `tn.read(raw=True)`, signature and chain verification, tamper detection. | `python examples/ex02_reading.py` |
| `ex03_groups.py` | Routing fields into groups so PII and finance stay encrypted; reading as publisher vs as a partner holding only the `default` kit. | `python examples/ex03_groups.py` |
| `ex05_rotate.py` | Mint a recipient kit, then revoke it: old ciphertexts stay decryptable, new ones do not. | `python examples/ex05_rotate.py` |
| `ex06_multi_handler.py` | The `handlers:` fan-out in `tn.yaml`: rotating file, HTTP webhook (in-process stub), and object storage, each with its own filter and outbox. | `python examples/ex06_multi_handler.py` |
| `ex07_context.py` | `tn.set_context(**kwargs)` under concurrent asyncio load: per-task isolation, fields picked up automatically downstream. | `python examples/ex07_context.py` |
| `ex08_stdout.py` | The default stdout handler: every emit prints the canonical envelope JSON, plus the `TN_NO_STDOUT=1` and `stdout=False` opt-outs. | `python examples/ex08_stdout.py` |

## Standalone demo

| File | Demonstrates | Run |
|---|---|---|
| `demo_revocation.py` | btn add/revoke through the Python skin on the Rust runtime, with a verbose printout. Pass `--legacy` for the pre-Rust comparison path. | `python examples/demo_revocation.py` |

## Benchmarks

The `bench_*.py` files are perf harnesses, not teaching examples: 1 KB
emit breakdown, info/read timing, signing cost, and file-isolate
microbench. Each writes a sibling `*.results.md`. They are dev tooling,
not part of the `tn` package, and are not exercised by the example test
suite.
