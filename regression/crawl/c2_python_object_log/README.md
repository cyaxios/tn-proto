# C2 — Python object-level logging

**Status: scaffolded, no tests yet. Implemented in the C2+C4 PR.**

## What this silo proves

The TN handle (object-level) round-trip on the Python side:

```python
import tn

t = tn.use("payments")  # returns a TN object handle
t.info("app.hello", a=1)
entries = list(t.read())
t.flush_and_close()
```

Same observable outcome as C1, but exercises a different dispatch path:
**per-instance runtime** (the TN handle holds its own runtime
reference), not the module singleton. This catches bugs that only show
up when a process holds multiple TN handles or when the singleton and
handle paths diverge.

## Why it's load-bearing

Multi-ceremony users (anyone running more than one TN context in a
process — vault server, CLI tools that switch ceremonies, tests) all
go through the object-level path. If this drifts from the module-level
path, those users get inconsistent behavior depending on which API
they reach for.

## Code paths exercised

- `python/tn/_handle.py` — the `TN` class (handle returned by `tn.use`)
- `python/tn/_multi.py:tn_use_impl` — named ceremony resolution
- `python/tn/_registry.py` — per-ceremony runtime registry
- `python/tn/__init__.py` — re-export wiring for handle methods

## Tests to add (in the C2+C4 PR)

- `test_handle_round_trip.py` — `t = tn.use(...); t.info(...); t.read()` returns the just-written entry
- `test_handle_close_releases_runtime.py` — `t.flush_and_close()` drops the per-instance runtime
- `test_singleton_vs_handle_parity.py` — module verb and handle verb produce identical envelopes for identical inputs

## How to run only this silo

```bash
make -C regression c2
# or
pytest regression/crawl/c2_python_object_log -v
```

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| `tn.use("name")` raises | `_multi.py:tn_use_impl` ceremony discovery + `_layout.py` name validation |
| Handle's `t.info` writes to the wrong ceremony | `_handle.py:_get_runtime` — per-instance vs singleton dispatch |
| Handle methods missing | `_handle.py` `TN` class definition; method names must match module verbs (no "emit") |
| `t.flush_and_close()` leaves resources open | `_handle.py:close` + `_registry.py` per-instance cleanup |
