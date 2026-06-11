# Advanced usage

Reading modes, scoped lifecycles, templated log paths, and the cross-language guarantee. For the basic verbs (`tn.init`, `tn.log`, `tn.info`, `tn.read`) see the [cookbook](cookbook-python.md); for the evidence trade-offs see [profiles](profiles.md).

---

## Reading: all runs, this run, admin

`tn.read()` defaults to every entry on disk (`all_runs=True`). A fresh `python hello.py` reading an existing `.tn/` log will surface yesterday's events. To restrict to entries written by this process's runtime, pass `all_runs=False`:

```python
import tn
tn.init()

# All entries on the main log (default).
for e in tn.read():
    print(e.level, e.event_type, e.fields)

# Restrict to entries emitted by this process run.
for e in tn.read(all_runs=False):
    print(e.level, e.event_type, e.fields)

# Admin log (ceremony lifecycle), addressed explicitly by name.
for e in tn.read(log="admin"):
    print(e.level, e.event_type)
# info tn.ceremony.init
# info tn.group.added
```

The `all_runs=True` default was chosen so that `tn read` (CLI) and `tn.read()` (Python) match the operator expectation of "show me what is in this log file." Set `all_runs=False` to scope a read to the current run.

The default surface (`tn.read()` / `tn.watch()` with no `log=`) is the **main user log only**. Admin envelopes (`tn.*`) live in a separate log; address them by name. `log=` also accepts a path template (see [Templated paths](#templated-paths)).

---

## Scoped lifecycle

For test code, or anything that wants a TN context bounded by a code block instead of the global `init`:

```python
with tn.session() as s:
    s.log("order.created", order_id="A100")
    s.log("order.shipped", order_id="A100")
# block exit: the session's ephemeral ceremony is torn down,
# the global runtime (if any) is restored.
```

`tn.session()` creates an isolated tmpdir ceremony for the duration of the block. The handle's verbs (`s.info`, `s.read`, ...) match the module-level ones, and `s.log` returns the written envelope just like `tn.log`. Use it for tests and short-lived processes that should not leave a `./.tn/` on disk.

For the long-running-process case, just call `tn.init()` once at startup; the global runtime stays for the life of the interpreter and drains on exit (there is no explicit flush).

---

## Templated paths

Both the admin log address (`admin_log_location` in the yaml) and the main log address (`logs.path` plus the matching `handlers[].path` entry) accept seven tokens:

`{event_type}`, `{event_class}`, `{event_id}`, `{date}`, `{yaml_dir}`, `{ceremony_id}`, `{did}`.

```yaml
logs:
  path: "./logs/{event_class}/{date}.ndjson"
handlers:
  - kind: file.rotating
    name: main
    path: "./logs/{event_class}/{date}.ndjson"   # same template
```

Each emit lands in its rendered file:

```bash
$ ls .tn/default/logs/
audit/    order/    payment/
$ ls .tn/default/logs/order/
2026-05-13.ndjson
```

Read it back as a single stream by passing the same template to `log=`:

```python
for entry in tn.read(log="./logs/{event_class}/{date}.ndjson", all_runs=True):
    print(entry.event_type)
```

Unknown tokens fail at `tn.init()` time, not at first emit.

---

## Cross-language

Every binding reads byte-identical envelopes. A row written by Python can be decoded in the browser, and vice versa. Cross-language parity tests run on every PR.

| Binding | Where | Use case |
|---|---|---|
| Python | `pip install tn-proto` | reference SDK, CLI, services |
| TypeScript / Node | `ts-sdk/` in the repo | Node services, build tools |
| Browser (WASM) | `crypto/tn-wasm` build | in-browser verify and decrypt |

The Python wheel and the WASM build share one Rust engine, so the wire format agrees down to the byte across all three.
