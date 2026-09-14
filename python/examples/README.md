# Examples

## Governed application workflows

Python calls the canonical Rust object implementation through PyO3.

| File | Demonstrates |
| --- | --- |
| [governed_workflow.py](governed_workflow.py) | Create, release, accept for an application and operation, calculate, and release. The [Rust example](../../crypto/tn-core/examples/governed_workflow.rs) performs the same calculation. |
| [governed_data.py](governed_data.py) | Mutable working data with additive policy, inclusion, and retained signed snapshots. |
| [governed_sessions.py](governed_sessions.py) | Independent session identities and assigned group material. |
| [governed_outbox.py](governed_outbox.py) | Retain exact signed replies with business and inbox/outbox transactions. |

Run `python python/examples/governed_workflow.py` from the repository root after
installing the governed wheel. See the [workflow guide](../GOVERNED_WORKFLOW.md)
for accepted dataset editions and native ancestry verification.

## Event stream examples

These examples cover writing and reading events, sharing encrypted groups,
managing recipient keys, and configuring output handlers. Install `tn-proto`
first. Each `ex0*.py` file creates a ceremony in a temporary directory and
cleans it up on exit.

Run any one of them directly from the `python/` directory:

```
python examples/ex01_hello.py
```

The `ex0*` files are also executed by
[`tests/test_examples.py`](../tests/test_examples.py). For
installation, configuration, and CLI examples, see the
[getting started guide](../../docs/guide/getting-started.md).

## Walkthrough examples

| File | Demonstrates | Run |
|---|---|---|
| `ex01_hello.py` | Initialize a ceremony, write three events, and read them as `Entry` objects with decrypted fields. | `python examples/ex01_hello.py` |
| `ex02_reading.py` | Inspect envelopes with `tn.read(raw=True)`, verify the log's signatures and chains, and verify a signature using its public key. | `python examples/ex02_reading.py` |
| `ex03_groups.py` | Keep customer details and internal diagnostics encrypted while a partner reads with only the `default` kit. | `python examples/ex03_groups.py` |
| `ex05_rotate.py` | Mint a recipient kit, then revoke it: old ciphertexts stay decryptable, new ones do not. | `python examples/ex05_rotate.py` |
| `ex06_multi_handler.py` | The `handlers:` fan-out in `tn.yaml`: size-rotated and daily files, with separate filters for auth and page events. | `python examples/ex06_multi_handler.py` |
| `ex07_context.py` | `tn.set_context(**kwargs)` under concurrent asyncio load: per-task isolation, fields picked up automatically downstream. | `python examples/ex07_context.py` |
| `ex08_stdout.py` | Readable stdout output, `TN_STDOUT_FORMAT=json` for envelope JSON, and `stdout=False` for file-only output. | `python examples/ex08_stdout.py` |

## Benchmarks

The `bench_*.py` scripts measure emit/read timing, signing cost, and file
writes. They print results; the emit/read and signing scripts also save a
sibling `*.results.md` file.
