# Profiles

A profile is a named preset that decides how much ceremony each log entry
carries: whether it is signed, whether it is hash-chained to the entry
before it, how aggressively it is flushed to disk, and where it is written.
You pick a profile when you create a ceremony. Encryption is always on; a
profile dials everything else between "maximum evidence" and "fast logger".

## The five profiles

| Profile | Encrypts | Signs | Chains | Flush | Sink | Use for |
|---|---|---|---|---|---|---|
| `transaction` (default) | yes | yes | yes | fsync | rotating file | Grants, revokes, payments, agent actions, security events. Maximum evidence: signed, chained, durable. |
| `audit` | yes | yes | yes | buffered | rotating file | Business events where reconstruction matters but a small flush window is acceptable. Same evidence as `transaction`, weaker durability. |
| `secure_log` | yes | yes | no | buffered | rotating file | Sensitive application logs where signing matters but sequence does not. Each entry stands alone; cheaper to scale. |
| `telemetry` | yes | no | no | async | rotating file + stdout | High-volume traces, metrics, and debug output. Signing and chaining are dropped for near-zero overhead. |
| `stdout` | yes | no | no | async | stdout | Local dev and notebooks. Writes the same encrypted NDJSON envelope to the console instead of a file. |

## What the columns mean

- **Encrypts**: per-group field encryption. On for every profile. This is the protocol floor and cannot be turned off.
- **Signs**: each entry carries an Ed25519 signature over its row hash, so a reader can prove who wrote it. An unsigned entry carries an empty `signature`, and a reader skips the Ed25519 check on it; the trade-off is the loss of authorship proof.
- **Chains**: each entry's `prev_hash` links it to the previous entry of the same event type, making gaps and reordering detectable. Without chaining, entries are independent and sequence is informational only.
- **Flush**: the durability of a write is a property of the handler, not a top-level profile field; there is no `flush:` yaml key. `fsync` syncs every write to disk before returning (survives a crash). `buffered` leaves the write in the OS buffer. `async` hands the write to a background path for the lowest latency.
- **Sink**: `rotating file` writes to `logs/tn.ndjson` and rolls it over by size. `stdout` writes the encrypted envelope to the console instead of a file; you still use `tn.read()` to see decoded fields. `telemetry` does both, so `tn.read()` still works while you also see console output.

## Choosing a profile

Pick by the question you need the log to answer later:

- Need to prove what happened and in what order, and survive a crash: `transaction`.
- Same proof, can tolerate a small loss window on crash: `audit`.
- Need to prove authorship but not order: `secure_log`.
- Just want fast, encrypted, high-volume logging: `telemetry`.
- Just want the encrypted envelope written to the console during development: `stdout`.

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
  `prev_hash` that links it into its event-type chain, and the write is
  fsynced before the call returns.
- Under `telemetry`, the same record has an empty `signature` and an empty
  `prev_hash`, the write returns without waiting on disk, and the entry is
  also printed to stdout.

The fields you logged and the per-group ciphertext are identical either way.
Only the evidence and delivery around them change. The on-the-wire record
format is documented in [protocol.md](protocol.md).
