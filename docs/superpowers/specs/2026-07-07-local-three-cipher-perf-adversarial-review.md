# Adversarial review: local three-cipher performance design

Review target:

`docs/superpowers/specs/2026-07-07-local-three-cipher-perf-design.md`

Review question:

Would the proposed local artifact be sufficient to avoid discovering, during
paper/AWS execution or peer review, that the measurements are not comparable,
not reproducible, or missing data and therefore must be rerun?

## Findings

### 1. Stage parity can be fake if Python and Rust counters are blindly merged

Risk:

BTN can use Rust counters while JWE/HIBE use Python counters. If the runner
sums counters with the same stage names without proving they represent
non-overlapping work, the stage breakdown can double-count or omit work. A paper
reviewer could reject the stage table as inconsistent across runtimes.

Required design control:

- Stage rows must carry a `source` field.
- The default rule must be no blind summing.
- Merged rows are allowed only for explicitly non-overlapping stages.
- The summary must surface source coverage per cipher.

Status:

Addressed in the design under "Counter merger".

### 2. Per-operation read rows can misrepresent batch reads

Risk:

The public read surface reads a log, not one random-access message. If the
artifact emits one `read` row per event as if each event were independently
timed, the paper could be accused of overstating precision. Worse, rerunning
with a different batching method would produce different numbers.

Required design control:

- Keep raw `read_batch` rows with total batch time and event count.
- Derived per-event read rows must be labeled `derived_from_batch: true`.
- The paper must call these "per-event batch read latency".

Status:

Addressed in the design under "Read/decrypt pass".

### 3. The smallest payload can accidentally measure JSON scaffolding instead of payload

Risk:

For `64 B`, a naive field value length of 64 bytes does not produce a 64-byte
canonical group body. JSON key and quote overhead would make the cell larger
than claimed. This would force a rerun if the paper later says "64-byte payload"
and the raw artifacts show a different plaintext size.

Required design control:

- Define payload size as canonical group-map bytes.
- Generate strings that make canonical bytes exactly the target.
- Fail if `payload_bytes != payload_target_bytes`.

Status:

Addressed in the design under "Deterministic payloads".

### 4. HIBE recipient count is not semantically identical to JWE recipient count

Risk:

JWE `R` means `R` recipient headers in the ciphertext. HIBE `R` means `R`
granted keys, while sealing uses one identity path and does not scale with `R`.
If the artifact only records `recipients: R`, a reviewer may think the HIBE
writer encrypted to R concrete recipients.

Required design control:

- HIBE rows must record that `R` is granted-reader count, not per-record
  recipient header count.
- HIBE rows must record the seal path and candidate key count used for read.
- Summary text must state HIBE's constant-in-R expectation.

Status:

Addressed in the design under "Recipient setup".

### 5. Instrumentation overhead could distort the latency being reported

Risk:

Resetting and snapshotting counters for every operation could dominate the
64-byte case and make local numbers useless. It could also bias one cipher more
than another if one path crosses Python/Rust boundaries more often.

Required design control:

- Primary latencies use per-operation wall clock only.
- Stage counters are collected once per trial.
- Per-operation counter mode is diagnostic only and excluded from paper stats.

Status:

Addressed in the design under "Measurement-window rule".

### 6. Missing verified-read instrumentation would cause a paper rerun

Risk:

The paper runbook calls for fully verified read. If local smoke only measures
decrypt-only read, the first AWS run may discover missing signature, row-hash,
or chain verification timing fields.

Required design control:

- Required read stages include row hash, signature, and chain verification.
- Local smoke should default to verified read once instrumentation is present.
- Sufficiency gates fail if verified-read stages are missing.

Status:

Resolved after review. The design now makes verified read mandatory for local
smoke and adds a sufficiency failure if the read pass is not verified.

### 7. BTN production path versus Python wrapper path could change results

Risk:

BTN may use the Rust dispatch runtime while JWE/HIBE use Python fallback. If the
local runner accidentally uses a different BTN path from production, the
comparison may be invalid or at least need rerunning.

Required design control:

- Every cell records `runtime_path`.
- The suite chooses the production path by default.
- Tests assert which path was used for BTN/JWE/HIBE.

Status:

Resolved after review. The design now makes `runtime_path` mandatory metadata
for every cell and a sufficiency failure if it is missing.

### 8. Warmup and initialization can leak into measured operations

Risk:

JWE/HIBE import/setup costs, native HIBE initialization, and first file-open
costs can pollute the first measured trial if warmup is not strict. A paper
reviewer may reject results if setup and steady-state are mixed.

Required design control:

- Warmup trial is always present by default.
- Runtime/cipher init happens before warmup.
- Warmup rows are kept but excluded.
- The summary records whether first-open file cost is included in measured
  steady-state. Prefer including first write in warmup only.

Status:

Resolved after review. The design now states that runtime/cipher initialization
happens before warmup and first-open file costs belong to warmup, not measured
steady-state.

### 9. Local Windows output cannot be used as paper evidence

Risk:

If local smoke artifacts look complete, someone may be tempted to fill paper
slots from them. That would contradict the paper runbook's fixed-performance AWS
instance requirement and could force correction.

Required design control:

- `summary.json` marks `paper_eligible: false`.
- `env.json` records `environment_class: local_windows_smoke`.
- REPRODUCE and summary say local output is for harness validation only.

Status:

Resolved after review. The design now requires
`environment_class: "local_windows_smoke"` in `raw/env.json`.

### 10. The raw schema must preserve enough to recompute stage percentages

Risk:

If stage rows are separate from operation rows but do not include op, trial,
count, source, and total, later stats cannot reconstruct stage percentages per
cell/op. That would force a rerun to recover missing raw data.

Required design control:

- Stage rows include cell, cipher, op, trial, stage, source, count, total_ns,
  and avg_ns.
- Summary derives percentages only where matching `_TOTAL` exists for same
  cell/op/trial/source.

Status:

Addressed in the stage row schema and stats section.

## Review-driven changes applied to the design

1. Verified read is mandatory for local smoke, not an open question.
2. `runtime_path` is mandatory metadata for every cell.
3. `environment_class: local_windows_smoke` is recorded in `raw/env.json`.
4. Runtime/cipher initialization happens before warmup.
5. First-open file costs are absorbed by warmup, not measured steady-state.

After those changes, the design is sufficient for a local harness validation
run. It still will not make local output paper-eligible, which is intentional.
