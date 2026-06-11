# Profile Immutability

A profile (`transaction`, `audit`, `secure_log`, `telemetry`) is a
**creation-time** choice. Once a ceremony's YAML exists, the on-disk
`ceremony.profile` is authoritative.

## Rule

When code supplies a `profile` while opening a ceremony:

- **Unknown profile name** → fail fast. It is misconfig at the call
  site, not a conflict. Python raises `TNConfigConflict`; TS throws
  `TNCreateFailed`. The message names the catalog.
- **No on-disk YAML yet** → the supplied profile is honored at creation.
- **On-disk YAML exists and its `ceremony.profile` matches** → silent.
- **On-disk YAML exists and disagrees** → the on-disk value wins
  (operator authority) and a warning is logged. Logging never fails on a
  profile mismatch — the product principle is "log no matter what."

## Warning Text

Both SDKs emit the same operator-authority message on a known mismatch:

```text
profile conflict for <yaml>: code requested "<code_profile>", on-disk
yaml specifies "<on_disk_profile>". Operator authority — yaml wins. To
use the code-requested profile, edit the yaml or pick a different
ceremony name.
```

Python logs it on the `tn` logger at WARNING; TS calls `console.warn`.

## Implementations

- Python: `python/tn/_multi.py::_check_no_conflict`
- TS: `ts-sdk/src/multi.ts::checkProfileConflict`

This surface is a behavioral contract (warn vs raise + a message
template), not a byte-vector, so it is pinned by matching tests in both
languages rather than a shared JSON fixture.

## Current Contract Tests

- Python: `python/tests/test_multi_ceremony.py::TestConflictPolicy`
  (known mismatch warns + returns a handle; unknown profile raises)
- TS: `ts-sdk/test/profile_conflict.test.ts`
  (known mismatch warns once with the operator-authority phrasing and
  does not throw; matching profile is silent; unknown profile throws;
  missing yaml is a no-op)
