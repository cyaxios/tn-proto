# C1 — Python module-level logging

**Status: scaffolded, no tests yet. Implemented in the C1+C3 PR.**

## What this silo proves

The simplest possible TN-protocol round-trip on the Python side:

```python
import tn

tn.init(yaml_path)
tn.info("app.hello", a=1)
entries = list(tn.read())
```

After this returns, the attested log on disk contains an envelope with
`event_type=app.hello`, `level=info`, fields `{a: 1}`, and the
`tn.read()` call yields it back. The default handler stack (file
rotating + stdout) both produce output.

## Why it's load-bearing

This is the **smallest user-facing surface**. If C1 is failing, every
single Python consumer of the SDK is broken — pipelines, scripts, the
vault server, every downstream test.

## Code paths exercised

- `python/tn/__init__.py` — `tn.init`, `tn.info`, `tn.read` public verbs
- `python/tn/_autoinit.py` — first-init discovery + ceremony mint
- `python/tn/_multi.py:_init_named_ceremony` — yaml + keystore creation
- `python/tn/_dispatch.py` — Rust-vs-Python runtime selection
- `python/tn/handlers/file.py` — default file rotating handler
- `python/tn/handlers/stdout.py` — default stdout handler

## Tests to add (in the C1+C3 PR)

- `test_default_handlers.py` — round-trip + both default handlers produce output
- `test_file_handler_only.py` — `stdout=False` keeps file output going
- `test_stdout_handler_only.py` — file disabled, stdout still produces lines

## How to run only this silo

```bash
make -C regression c1
# or
pytest regression/crawl/c1_python_module_log -v
```

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| `tn.info()` raises before writing anything | `_dispatch.py` runtime selection + `_autoinit.py` discovery |
| Log file never created | `handlers/file.py` rotating-handler bootstrap; ceremony yaml `logs.path` |
| Log written but `tn.read()` returns empty | `_read_impl.py` filter chain; check `$TN_RUN_ID` env scope |
| stdout silent on console | `handlers/stdout.py` — check `TN_NO_STDOUT` env, IPython detection |
