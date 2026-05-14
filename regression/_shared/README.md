# `_shared/` — utilities every silo can use

These are the only pieces a silo author should reach for outside their
own directory. **If you find yourself wanting to import from another
silo's directory, stop — what you want belongs here.**

## Files

| file | purpose |
|---|---|
| `assertions.py` / `assertions.ts` | Named-assertion helpers. **Every** check goes through `assert_named()` — never a bare `assert x == y`. Failure output names the predicate, expected, observed, and pointer-to-source. |
| `log_query.py` / `log_query.ts` | Query the attested TN log for envelopes matching a predicate. The "watch for X in the log" sidecar. Mandatory whenever the workflow under test is TN's own protocol. |
| `personas/*.yaml` | Persona registry — Alice, Frank, Bob, Carol, … Each has a deterministic DID seed, default passphrase, and a one-line role description. Personas thread through silos; their identities are stable. |
| `fixtures/` | Canned ceremonies, kits, sample logs that more than one silo wants. **Per-silo fixtures stay in the silo's own directory.** |
| `../conftest.py` | pytest plugin (lives at `regression/conftest.py`, NOT in `_shared/`, so pytest auto-loads it for every silo). Implements `--silo-report=<path>` and per-test `silo` inference from the test's nodeid. |
| `finalize_ts_report.py` | Translates `node --test` TAP output into the same JSON report shape pytest produces. So TS silo reports look identical to Python silo reports. |

## Named-assertion contract

There are two assertion styles, both produce **identical failure output
shape** so a maintainer reading a report doesn't need to know if the
silo is Python, TS, or Playwright.

### Style 1 — TN-native (against the attested log)

Use this whenever the workflow you're testing is TN's own protocol —
i.e. when the success criterion is "the publisher produced an attested
envelope with these fields."

```python
from regression._shared.log_query import LogQuery

log = LogQuery(ceremony_path=ctx.yaml_path)

log.assert_contains(
    name="recipient-added",
    where={
        "event_type": "tn.recipient.added",
        "recipient_did": frank.did,
        "group": "default",
    },
)
```

On miss, the failure prints:

```
ASSERTION FAILED: recipient-added
  silo: c5_groups_recipients_inproc
  predicate: event_type=tn.recipient.added AND recipient_did=did:key:z6Mk… AND group=default
  observed in log: 4 envelopes, event_types=[tn.ceremony.init, app.hello, app.hello, tn.group.added]
  closest match: <none — no envelope had event_type=tn.recipient.added>
  look at: regression/crawl/c5_*/README.md#failure-investigation-guide
```

### Style 2 — Non-TN state (HTTP, Mongo, DOM, filesystem)

Use this for anything that isn't a TN envelope — vault HTTP responses,
Mongo rows, DOM state in Playwright, file existence on disk.

```python
from regression._shared.assertions import assert_named

assert_named(
    name="vault-pending-claim-row-exists",
    expected="present",
    observed=mongo.pending_claims.find_one({"vault_id": vid}),
    on_miss=(
        f"Expected row in pending_claims for vault_id={vid}, got None. "
        f"Check routes_pending_claims.py:50 (insert path) and Mongo "
        f"TTL index — row may have expired."
    ),
)
```

Same failure shape. The `on_miss` string is **mandatory** and **must
point at code** (file:line or function name) — that's the "where to
look" the maintainer needs.

## Persona registry

Personas are characters who thread through silos. Each one's identity
(DID seed, passphrase) is stable across all silos so the same Alice in
C5 can be referenced in C7 without re-minting.

The yaml shape:

```yaml
# personas/alice.yaml
name: alice
role: publisher
device_seed_hex: "01..."              # 64 hex chars = 32 bytes; used to derive Ed25519 device key
passphrase: "alice-test-passphrase"   # default vault passphrase; per-silo can override
notes: |
  Alice is the canonical publisher. She mints projects, invites
  recipients, rotates groups. Used as the "owner" in every silo
  that needs a publisher persona.
```

Load via:

```python
from regression._shared.personas import load_persona
alice = load_persona("alice")   # → Persona(name="alice", did="did:key:z6Mk…", …)
```

## Anti-patterns

Don't.

- **Bare `assert x == y`.** Every check goes through `assert_named` or
  `LogQuery.assert_contains`. No exceptions.
- **Importing from another silo's directory.** If two silos want the
  same helper, it goes in `_shared/`.
- **Re-minting personas inside a test.** Use the registry. Tests
  should not generate keys randomly — flakes are intolerable in
  regression.
- **Silent skips.** A skipped test is invisible noise. Either delete
  it or fix what's making it skip.
- **The word "emit"** anywhere — names, comments, docstrings. Public
  verbs only: `tn.log`, `tn.info`, `tn.warning`, `tn.error`,
  `tn.debug`.
