# Examples

Six progressive scenarios that teach `tn.log` from "hello world" to
rotation and fan-out. Each file is runnable standalone:

```
python examples/ex01_hello.py
```

Each is also executed by [`tests/test_examples.py`](../tests/test_examples.py)
on every commit, so the numbers and output strings the primer cites are
always current.

| File | Scenario |
|---|---|
| `ex01_hello.py` | First init, three log entries, read back. |
| `ex02_reading.py` | Envelope shape, signature verification, chain integrity. |
| `ex03_groups.py` | Routing fields into BGW groups (PII and finance separation). |
| `ex05_rotate.py` | Revoke a recipient by rotating the group. |
| `ex06_multi_handler.py` | Multiple file handlers with filter-based fan-out. |
| `ex07_context.py` | Request-scoped context under concurrent asyncio load. |

For the narrative version, see [`docs/primer.md`](../docs/primer.md).
