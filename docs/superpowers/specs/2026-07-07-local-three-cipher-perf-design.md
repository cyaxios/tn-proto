# Local three-cipher performance suite design

## Goal

Build a Windows-local performance smoke suite for TN-Proto that runs from the
repo venv in `C:\codex\tn\tn_proto`, measures BTN, JWE, and HIBE on the same
machine with the same payloads and metrics, and produces raw artifacts that can
graduate to the AWS paper run without changing the metric contract.

The suite is not allowed to produce paper numbers. It is a local rehearsal for
the paper artifact: it proves the runner, instrumentation, raw schema, and
statistics are sufficient before we pay for AWS time or fill paper
`[MEASURE:*]` slots.

## Non-goals

- Do not fill `tn-paper` measurement slots from local Windows output.
- Do not compare BTN totals from Rust against JWE/HIBE totals from an
  uninstrumented Python path.
- Do not report any number that cannot be recomputed from raw artifacts.
- Do not use per-cipher bespoke runners that produce different schemas.
- Do not rely on a remote branch; the local checkout is the source of truth.

## Local execution target

Run from:

```powershell
cd C:\codex\tn\tn_proto
.\.venv\Scripts\python.exe -m tn_bench.local_perf --profile local-smoke
```

Verified local environment on 2026-07-07:

- `.venv` exists at `C:\codex\tn\tn_proto\.venv`.
- Python is `3.12.4`.
- `pip` is available.
- `tn` imports from `C:\codex\tn\tn_proto\python\tn\__init__.py`.
- `pytest` is available in the venv.

The runner records the venv path, Python version, platform, CPU count, memory,
Git revision, dirty status, command line, relevant env vars, and
`environment_class: "local_windows_smoke"` in `raw/env.json`.

## Matrix

Local smoke payload sizes:

| Name | Canonical payload target |
|---|---:|
| `p64b` | 64 bytes |
| `p256b` | 256 bytes |
| `p1k` | 1024 bytes |

Cipher axis:

- `btn`
- `jwe`
- `hibe`

Recipient axis:

- Local default: `R = 1, 4, 8`
- AWS/paper profile later: `R = 1, 4, 8, 32`

BTN revocation axis:

- Local default: `none`
- Local optional stress: `dispersed64`
- AWS/paper profile later: `none`, `dispersed64`, `clustered64`

JWE/HIBE revocation field:

- Always `none` in the cell id, because those ciphers do not have BTN-style
  cover revocation.

Local default cells:

- BTN: `3 payloads x 3 recipient counts x 1 revocation = 9 cells`
- JWE: `3 payloads x 3 recipient counts = 9 cells`
- HIBE: `3 payloads x 3 recipient counts = 9 cells`
- Total default local smoke: 27 cells

Optional local stress adds 9 BTN cells for `dispersed64`.

## Passes

Each cell has two separate passes over the same generated records.

### Emit pass

The emit pass creates the log records. It measures:

- wall-clock emit latency
- payload byte count
- serialized envelope byte count
- stage counters for classification, canonicalization, encryption, signing,
  row hash, envelope construction, chain work, and file write/save
- success or failure

### Read/decrypt pass

The read pass reads and decrypts the records produced by the emit pass. Local
smoke uses verified read by default because the paper runbook requires fully
verified read. It measures:

- wall-clock read latency
- verified-read latency where enabled
- line parse
- row-hash verification
- signature verification
- chain verification
- ciphertext decode
- cipher decrypt/open
- plaintext JSON parse
- success or failure
- payload equality against the deterministic expected payload

Read timings are recorded as batch measurements and per-event derived rows.
Because the public Python/Rust read APIs read a log, the raw artifact must retain
both:

- `read_batch` row: one row for the measured read invocation, with
  `batch_events` and `batch_lat_ns`.
- `read` rows: one derived per-event row with `lat_ns = batch_lat_ns /
  batch_events`, carrying `derived_from_batch: true`.

The paper summary must describe this as per-event batch read latency, not as
independent single-record random access latency.

## Iteration counts

Local default:

- warmup trials: `1`
- measured trials: `3`
- operations per trial: `50`

CLI overrides:

```text
--warmup-trials N
--trials N
--ops N
--payloads 64,256,1024
--recipients 1,4,8
--btn-revocations none,dispersed64
```

The runner keeps warmup raw rows but excludes them from reported stats. Runtime
and cipher initialization happen before warmup. First-open file costs are
absorbed by warmup, not measured steady-state.

## Stage vocabulary

Every cipher must produce the same stage names for the same logical work. If a
stage is not emitted for one cipher, the runner marks that cell
`instrumentation_failed` and the run is not paper-sufficient.

### Emit stages

Required emit stages:

| Stage | Meaning |
|---|---|
| `emit:_TOTAL` | End-to-end emit path |
| `emit:field_classify` | Route public vs encrypted group fields |
| `emit:group_encrypt` | Whole per-group encrypt pipeline |
| `emit:group_encrypt.sort` | Stable field ordering before canonical bytes |
| `emit:group_encrypt.index_token` | HMAC/index token generation |
| `emit:group_encrypt.canonical_bytes` | Canonical plaintext group bytes |
| `emit:group_encrypt.cipher` | Actual cipher seal/encrypt/open-library call |
| `emit:row_hash` | Envelope row hash |
| `emit:sign` | Ed25519 signing |
| `emit:envelope_build` | Serialize canonical envelope |
| `emit:file_write` | Append/save durable row |

Optional emit stages may include `emit:header`, `emit:path_setup`,
`emit:tip_refresh`, `emit:lock_acquire`, `emit:chain_advance`,
`emit:chain_commit`, and `emit:fan_out`.

### Read stages

Required read stages:

| Stage | Meaning |
|---|---|
| `read:_TOTAL` | End-to-end read/decrypt invocation |
| `read:line_parse` | NDJSON parse |
| `read:row_hash_verify` | Recompute and compare row hash |
| `read:signature_verify` | Verify Ed25519 signature |
| `read:chain_verify` | Check `prev_hash` linkage |
| `read:group_decode` | Decode envelope ciphertext bytes |
| `read:group_decrypt` | Whole group decrypt pipeline |
| `read:group_decrypt.cipher` | Actual cipher open/decrypt/library call |
| `read:group_plaintext_parse` | Parse decrypted canonical JSON |

Optional read stages may include flattening/projection and source filtering.

## Instrumentation architecture

Existing Rust instrumentation:

- `tn_core::perf` exposes gated counters when `TN_PERF_TRACE` is set before
  runtime init.
- BTN native runtime already records many emit stages including
  `emit:_TOTAL`, `emit:group_encrypt.cipher`, and `emit:file_write`.
- Python extension exposes `perf_snapshot()` and `perf_reset()` for Rust
  counters.

Required new Python instrumentation:

- Add a small Python perf module, for example `python/tn/_perf.py`.
- Gate it on `TN_PERF_TRACE` using the same truthiness as Rust.
- Provide `record_ns(stage, ns)`, `time_stage(stage)`, `snapshot()`,
  and `reset()`.
- Use `time.perf_counter_ns()` for all Python-side timings.
- Keep counters process-global and single-threaded for the benchmark runner.

Required JWE instrumentation:

- Wrap `JWEGroupCipher.encrypt()` around recipient-list load and `_jwe_seal()`.
- The actual `_jwe_seal()` call records `emit:group_encrypt.cipher`.
- Wrap `JWEGroupCipher.decrypt()` / `_jwe_open()` so the anonymous-recipient
  trial-decrypt loop records `read:group_decrypt.cipher`.

Required HIBE instrumentation:

- Wrap `HibeGroupCipher.encrypt()` so `_native_hibe().seal(...)` records
  `emit:group_encrypt.cipher`.
- Wrap `HibeGroupCipher.decrypt()` so candidate-key setup is outside
  `read:group_decrypt.cipher` and the actual `_native_hibe().open(...)`
  attempts are inside it.
- Record candidate count for HIBE read as metadata because trying multiple
  candidate keys changes decrypt cost.

Required read-path instrumentation:

- Add Python read path counters around line parse, row hash verification,
  signature verification, chain verification, group decode, group decrypt,
  and plaintext parse.
- Add Rust read path counters with the same stage names for BTN/Rust-backed
  reads.

Counter merger:

- The runner collects both Python counters and Rust counters.
- If the same stage appears in both sources for one cell, the artifact records
  both source-specific values and a merged value only when the stages are known
  not to overlap.
- The default rule is no blind summing. Stage rows carry `source:
  "python" | "rust" | "merged"`.

Measurement-window rule:

- Do not reset/snapshot counters inside every operation for the main latency
  measurement.
- For each trial, reset counters after warmup, run `ops` operations, then
  snapshot once.
- Operation rows carry wall-clock latency. Stage rows carry per-trial totals
  and per-operation averages derived from `stage_total_ns / stage_count`.
- Optional diagnostic mode may reset/snapshot per operation, but those numbers
  are labeled `diagnostic_counter_overhead` and cannot feed paper stats.

This prevents instrumentation collection overhead from polluting the primary
latency measurements while still exposing step timings.

## Raw artifact schema

Artifacts are written to:

```text
artifacts/bench-artifact-local-<rev>-<timestamp>/
  raw/
    env.json
    cells.json
    covers.json
    <cell>.ndjson
  stats/
    summary.json
    summary.md
    stage-summary.json
  REPRODUCE.md
```

One operation row:

```json
{
  "schema": "tn-bench-operation/v1",
  "cell": "jwe.r4.p256b.none",
  "cipher": "jwe",
  "op": "emit",
  "trial": 2,
  "i": 37,
  "payload_bytes": 256,
  "payload_sha256": "hex",
  "wire_bytes": 1034,
  "lat_ns": 83125,
  "ok": true
}
```

One read batch row:

```json
{
  "schema": "tn-bench-read-batch/v1",
  "cell": "hibe.r8.p1k.none",
  "cipher": "hibe",
  "op": "read_batch",
  "trial": 2,
  "batch_events": 50,
  "batch_lat_ns": 5750000,
  "payload_bytes": 1024,
  "ok": true
}
```

One stage row:

```json
{
  "schema": "tn-bench-stage/v1",
  "cell": "btn.r4.p64b.none",
  "cipher": "btn",
  "op": "emit",
  "trial": 2,
  "stage": "emit:group_encrypt.cipher",
  "source": "rust",
  "count": 50,
  "total_ns": 1410000,
  "avg_ns": 28200
}
```

One cell metadata row:

```json
{
  "schema": "tn-bench-cell/v1",
  "cell": "btn.r4.p64b.none",
  "cipher": "btn",
  "recipients": 4,
  "payload_bytes": 64,
  "revocation": "none",
  "runtime_path": "python",
  "seed": "tn-local-smoke-v1/btn/r4/p64b/none",
  "status": "ok"
}
```

BTN cover metadata:

```json
{
  "cell": "btn.r8.p256b.dispersed64",
  "revoked": 64,
  "layout": "dispersed64",
  "cover_entries": 17,
  "c_d": 9,
  "c_f": 8
}
```

## Deterministic payloads

The runner creates canonical JSON group bodies with deterministic payload
strings sized so `len(canonical_bytes(group_map))` equals the target payload
size. It records both:

- `payload_target_bytes`
- `payload_bytes`

The run fails if `payload_bytes` differs from the target. This matters
especially for `64 B`, where JSON key overhead can otherwise dominate without
being explicit.

## Recipient setup

Each cell gets a fresh temporary ceremony/workspace so log history, chain state,
and key material do not leak between ciphers or payload sizes.

Every cell records `runtime_path`, one of:

- `rust-dispatch`
- `python-runtime`
- `python-wrapper-native-cipher`

The runner uses the production path by default for each cipher and tests assert
which path was used. A cell without `runtime_path` fails sufficiency.

BTN:

- Mint `R` measured readers.
- For `none`, revoke zero leaves.
- For `dispersed64`, revoke 64 non-measured leaves spaced across the h=8 tree.
- Log realized cover metadata.

JWE:

- Generate `R` X25519 recipients.
- Include all `R` recipient public keys in the group recipient list.
- Read/decrypt with one representative recipient key.
- Record `recipient_count = R`.

HIBE:

- Set up one authority mpk/msk.
- Seal to one current identity path.
- Grant `R` reader paths/keys for metadata parity, but seal cost is expected to
  be independent of `R`.
- Read/decrypt with one representative key.
- Record `recipient_count = R`, `hibe_path`, `candidate_key_count`, and whether
  the key is exact-path or derived.

## Statistics

`summary.json` derives from raw rows only.

Per cell and op:

- count
- failures
- min/p50/p95/p99/max latency
- total payload bytes
- total wire bytes
- min/p50/p95/p99/max wire bytes for emit
- events/s from p50

Per cell and stage:

- count
- total_ns
- avg_ns
- pct_of_emit_total or pct_of_read_total when a matching total exists

Cross-cipher tables:

- by payload at fixed `R`
- by recipient count at fixed payload
- BTN revocation delta where stress is enabled

The summary marks local output as `paper_eligible: false`.

## Sufficiency gates

The local run fails the sufficiency check if any of these are true:

- Any cipher cell is missing.
- Payload bytes do not match target.
- Emit and read passes do not both run for every cell.
- Read pass is not verified read.
- Read payload equality fails.
- `runtime_path` is missing for any cell.
- Required stage names are missing for any cipher.
- Required stage names exist for BTN but not for JWE/HIBE.
- JWE/HIBE stage source is ambiguous or unmerged without explanation.
- Wire bytes are missing on emit rows.
- Warmup rows are included in reported stats.
- Git revision or dirty status is missing from `env.json`.
- `environment_class` is missing from `env.json`.
- `TN_PERF_TRACE` was not enabled before runtime/cipher initialization.
- `raw` rows fail schema validation.
- Summary contains values that cannot be recomputed from `raw`.

## Test plan

Instrumentation tests:

- Enable `TN_PERF_TRACE`.
- Run one emit and one read for BTN, JWE, and HIBE.
- Assert required emit/read stages exist for each cipher.
- Assert `emit:group_encrypt.cipher` and `read:group_decrypt.cipher` counts are
  non-zero for each cipher.

Artifact tests:

- Generate a tiny one-cell artifact.
- Validate every NDJSON row parses.
- Validate stats recompute from raw.
- Validate warmup exclusion.
- Validate missing required stage fails sufficiency.

Payload tests:

- Generate `64 B`, `256 B`, and `1024 B` canonical payload bodies.
- Assert exact canonical byte length and stable SHA-256.

Runner smoke:

```powershell
.\.venv\Scripts\python.exe -m pytest python\tests\test_perf_instrumentation.py
.\.venv\Scripts\python.exe -m pytest python\tests\test_bench_artifact.py
.\.venv\Scripts\python.exe -m tn_bench.local_perf --profile local-smoke --trials 1 --ops 5
```

## Implementation placement

Recommended files:

```text
python/tn/_perf.py
python/tests/test_perf_instrumentation.py
python/tests/test_bench_artifact.py
tools/bench_artifact_py/tn_bench/__init__.py
tools/bench_artifact_py/tn_bench/local_perf.py
tools/bench_artifact_py/tn_bench/artifact.py
tools/bench_artifact_py/tn_bench/cells.py
tools/bench_artifact_py/tn_bench/stats.py
tools/bench_artifact_py/tn_bench/sufficiency.py
```

The tool package can be imported by adding `tools/bench_artifact_py` to
`PYTHONPATH` from the runner command, or by making it an editable dev dependency
inside the repo venv. The first implementation should prefer a direct
`PYTHONPATH` wrapper to avoid mutating the user venv more than necessary.

## Open implementation question

Whether `dispersed64` should be part of default local smoke. It improves BTN
evidence but adds time; default can stay `none` with a `--btn-stress` flag.
