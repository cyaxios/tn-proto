# Profiles

A profile is a named preset that decides how much ceremony each log entry
carries: whether it is signed, whether it is hash-chained to the entry
before it, and where it is written. You pick a profile when you create a
ceremony. Fields routed to private groups are encrypted under every profile;
fields explicitly routed as public remain visible.

## The Python profiles

| Profile | Encrypts private groups | Signs | Chains | Sink | Use for |
|---|---|---|---|---|---|
| `transaction` (default) | yes | yes | yes | rotating file | Grants, payments, agent actions, and security events requiring signed history. |
| `audit` | yes | yes | yes | rotating file | Business events requiring signed history; the current write path matches `transaction`. |
| `secure_log` | yes | yes | no | rotating file | Sensitive application logs where signing matters but chain order does not. |
| `telemetry` | yes | no | no | rotating file + stdout | Traces, metrics, and debug output with signing and chaining disabled. |
| `stdout` | yes | no | no | stdout | Local development and notebooks with console output. |

The TypeScript catalog has `transaction`, `audit`, `secure_log`, and
`telemetry`. Its `telemetry` preset selects stdout and has no default replay
surface. Use a file-backed profile when the application needs `read()` history.

## What the columns mean

- **Encrypts private groups**: per-group field encryption, retained by every profile. Public field routing is a separate configuration choice.
- **Signs**: each entry carries an Ed25519 signature over its row hash, so a reader can prove who wrote it. An unsigned entry carries an empty `signature`, and a reader skips the Ed25519 check on it; the trade-off is the loss of authorship proof.
- **Chains**: each entry's `prev_hash` links it to the previous entry of the same event type, making gaps and reordering detectable. Without chaining, entries are independent and sequence is informational only.
- **Sink**: `rotating file` writes to the configured log path and rolls it over by size. Python stdout defaults to a readable summary; set `TN_STDOUT_FORMAT=json` for the full encrypted NDJSON envelope. Without a file sink, ordinary `tn.read()` has no backlog. Python's `telemetry` preset writes both file and console output.

The native file writer appends before returning and calls `Write::flush`.
Durability and remote delivery depend on the selected storage and handlers.
Call `tn.flush_and_close()` in Python, or `await tn.close()`
in TypeScript, to drain handlers at shutdown.

## Choosing a profile

Pick by the question you need the log to answer later:

- Need signed, chained history: `transaction` or `audit`.
- Need to prove authorship but not order: `secure_log`.
- Want encrypted traces and metrics: `telemetry`.
- Want console output during development: Python's `stdout`.

## Setting a profile in code

Pass `profile` when you create the ceremony. This is the only place it
takes effect; it is read at init time, not on every write.

Python:

```python
import tn

# tn.init makes the ceremony the process default logger
tn.init("payments", profile="transaction")

# tn.use returns a handle without changing the process default
log = tn.use("traces", profile="telemetry")
```

TypeScript:

```typescript
import * as tn from "@cyaxios/tn-proto";

await tn.use("payments", { profile: "transaction" });
await tn.use("traces", { profile: "telemetry" });
```

If you do not pass a profile, the ceremony uses `transaction`.

## Setting a profile in the yaml

A profile is a generator of `tn.yaml` settings. When you create a ceremony
with a profile, the chosen preset is written into the yaml as concrete
fields, and the profile name is recorded as a label.

`transaction` (the default) produces:

```yaml
ceremony:
  sign: true
  chain: true
  profile: transaction
handlers:
  - kind: file.rotating
    name: main
    path: ./logs/tn.ndjson
```

`telemetry` produces:

```yaml
ceremony:
  sign: false
  chain: false
  profile: telemetry
handlers:
  - kind: file.rotating
    name: main
    path: ./logs/tn.ndjson
  - kind: stdout
```

The behavior comes from the concrete fields, `ceremony.sign`,
`ceremony.chain`, and the `handlers` list, not from the `profile:` label.
The label records which preset created the file. To depart from a preset,
edit those fields directly: for example, take a `transaction` ceremony and
set `ceremony.chain: false` to keep signing but drop the chain. Every field
is listed in [yaml-reference.md](yaml-reference.md).

## Inspecting the catalog

`show profiles` prints the full matrix, including each profile's intended
use:

```bash
tn show profiles
tn show profiles --format json
```

## How a profile changes a written entry

The same `info("order.created", ...)` call produces different records under
different profiles:

- Under `transaction`, the record has a populated `signature` and a
  `prev_hash` that links it into its event-type chain.
- Under `telemetry`, the same record has an empty `signature` and an empty
  `prev_hash`, and the entry is printed to stdout. Python also writes its file
  sink before returning.

The same fields route to the same groups under either profile. Encryption uses
fresh randomness, so separate writes produce different ciphertext. The
on-the-wire record format is documented in [protocol.md](protocol.md).
