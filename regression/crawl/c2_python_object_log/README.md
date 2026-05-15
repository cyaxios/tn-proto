# C2 — Python object-level logging

## What this silo proves

The TN handle (object-level) round-trip on the Python side:

```python
import tn

t = tn.use("payments")    # returns a TN object handle
t.info("payments.charge", amount=1000)
entries = list(t.read())  # only sees payments' entries
```

Same observable outcome as C1 (module-level), but exercises a
**per-instance runtime** path: every `TN` handle holds its own runtime
reference, so `payments.info(...)` and `billing.info(...)` never cross.

The default-named ceremony (`tn.use("default")`) is special — its
runtime IS the module-level singleton, so `tn.info(...)` and
`tn.use("default").info(...)` share state. This silo gates that
contract.

## Why it's load-bearing

Multi-ceremony users (vault servers, CLI tools that switch ceremonies,
tests) all go through the object-level path. If this drifts from the
module-level path, those users get inconsistent behavior depending on
which API they reach for. Bug #1 in the multi-ceremony rework was
exactly this: every `t.info()` call rebinding the singleton, so
`payments` and `billing` raced and the last-bound one won. The
per-instance runtime is the fix; this silo regresses against re-drift.

## Code paths exercised

- `python/tn/_handle.py` — the `TN` class (handle returned by `tn.use`)
- `python/tn/_multi.py:use` — named ceremony resolution + registry
- `python/tn/_handle.py:_get_runtime` + `_activate` — per-instance
  runtime vs singleton bridge
- `python/tn/_handle.py:read` — replay-surface gating

## Tests in this silo

- `test_handle_round_trip.py` — `tn.use(name).info(...)` writes; the
  same handle's `read()` returns the entry.
- `test_multi_ceremony_isolation.py` — `payments` and `billing` handles
  write to separate log files; each handle's `read()` returns only its
  own entries.
- `test_handle_severity_verbs.py` — handle's info/warning/error/debug/
  log methods stamp the correct level in the envelope (parity with C1).
- `test_default_handle_shares_module_state.py` — `tn.info(...)` and
  `tn.use("default").info(...)` both write to the same default
  ceremony's log; both observable in `tn.read()`.

## How to run only this silo

```
make c2
# or
pytest regression/crawl/c2_python_object_log -v
```

No vault contact — `TN_NO_LINK=1` is set by the hermetic fixture.

## Failure investigation guide

| symptom | first place to look |
|---|---|
| `tn.use("name")` raises `TNInvalidName` | `_multi.py:use` name regex check |
| `tn.use("name")` raises `TNCreateFailed` | filesystem permissions on the cwd; check `.tn/<name>/` creation |
| Handle's `t.info` writes to wrong ceremony | `_handle.py:_get_runtime` per-instance dispatch (this was Bug #1) |
| `tn.use("default").info(...)` doesn't show in `tn.read()` | default-bridge: `_handle.py:_activate` not wiring the singleton |
| `read()` returns empty iterator unexpectedly | `_handle.py:_has_replay_surface` — profile says no replay |
