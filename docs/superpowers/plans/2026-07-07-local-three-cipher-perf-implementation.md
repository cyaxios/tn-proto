# Local Three-Cipher Perf Instrumentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add committed, test-backed local instrumentation and smoke coverage for BTN, JWE, and HIBE before building the local performance runner.

**Architecture:** Preserve the current local working state in an isolated worktree, then add Python venv-first tests and instrumentation incrementally. Python gets a small `_perf` counter module for JWE/HIBE and Python read paths; Rust `tn_core::perf` remains the BTN/native counter source and gets read-path stages where missing. The benchmark runner consumes raw operation rows and stage snapshots but is added only after functional smoke and instrumentation tests are green.

**Tech Stack:** Python 3.12 venv at `C:\codex\tn\tn_proto\.venv`, pytest, TN Python package, PyO3 `_native` extension, Rust `tn-core` perf counters.

## Global Constraints

- Work in `C:\codex\tn-worktrees\tn-proto-perf-instrumentation` on branch `perf-instrumentation`.
- Run Python commands with `PYTHONPATH=C:\codex\tn-worktrees\tn-proto-perf-instrumentation\python`.
- Keep active checkout `C:\codex\tn\tn_proto` untouched.
- Tests precede production code for new instrumentation.
- Commit each durable slice so local work is not lost.
- Local Windows output remains `paper_eligible: false`.

---

### Task 1: Functional Smoke Tests

**Files:**
- Create: `python/tests/perf_smoke/functional/test_three_cipher_functional.py`

**Interfaces:**
- Consumes: public `tn.init`, `tn.info`, `tn.warning`, `tn.flush_and_close`, `tn.current_config`, and `tn.reader.read`.
- Produces: one pytest module proving BTN, JWE, and HIBE can sign, verify, chain-check, decrypt, and keep each cipher's files in separate directories.

- [ ] **Step 1: Write functional smoke test**

Create a parametrized pytest over `["btn", "jwe", "hibe"]`. For each cipher, create `tmp_path / cipher / "publisher"` and use separate `tn.yaml`, `log.ndjson`, and keystore/log directories. Emit two records, close, reopen, read through `tn.reader.read`, and assert signature, row hash, chain, and plaintext.

- [ ] **Step 2: Run functional smoke**

Run:

```powershell
$env:PYTHONPATH='C:\codex\tn-worktrees\tn-proto-perf-instrumentation\python'
C:\codex\tn\tn_proto\.venv\Scripts\python.exe -m pytest python\tests\perf_smoke\functional\test_three_cipher_functional.py -q
```

Expected: pass, or fail with a real existing cipher regression to fix before instrumentation.

- [ ] **Step 3: Commit functional smoke**

```powershell
git add python/tests/perf_smoke/functional/test_three_cipher_functional.py
git commit -m "test: add three-cipher functional smoke"
```

### Task 2: Python Perf Counter Module and Cipher Stages

**Files:**
- Create: `python/tn/_perf.py`
- Create: `python/tests/perf_smoke/instrumentation/test_python_perf_counters.py`
- Modify: `python/tn/cipher.py`

**Interfaces:**
- Produces: `tn._perf.enabled() -> bool`, `record_ns(stage: str, ns: int) -> None`, `time_stage(stage: str)`, `reset() -> None`, `snapshot() -> list[tuple[str, int, int]]`.
- Produces cipher stages `emit:group_encrypt.cipher` and `read:group_decrypt.cipher` for JWE and HIBE.

- [ ] **Step 1: Write failing counter tests**

Tests import `tn._perf`, enable `TN_PERF_TRACE`, verify reset/snapshot behavior, then run JWE and HIBE encrypt/decrypt and assert stage counts are non-zero.

- [ ] **Step 2: Run tests to verify failure**

Run the instrumentation test module. Expected initial failure: `ModuleNotFoundError: No module named 'tn._perf'` or missing stage counters.

- [ ] **Step 3: Add `_perf.py` and cipher wrappers**

Implement the counter module with `time.perf_counter_ns()` and a process-global lock. In `cipher.py`, wrap JWE `_jwe_seal` and `_jwe_open`, and HIBE `seal` and `open`, with `_perf.time_stage(...)`. Use a lazy helper so standalone cipher tests still load when `tn._perf` is absent.

- [ ] **Step 4: Run instrumentation tests**

Expected: pass.

- [ ] **Step 5: Rerun functional smoke**

Expected: pass.

- [ ] **Step 6: Commit instrumentation slice**

```powershell
git add python/tn/_perf.py python/tn/cipher.py python/tests/perf_smoke/instrumentation/test_python_perf_counters.py
git commit -m "feat: instrument python jwe and hibe cipher stages"
```

### Task 3: Verified Read Stage Instrumentation

**Files:**
- Create: `python/tests/perf_smoke/instrumentation/test_verified_read_perf_stages.py`
- Modify: `python/tn/reader.py`
- Modify: `crypto/tn-core/src/runtime/read.rs`

**Interfaces:**
- Produces read stage names `read:_TOTAL`, `read:line_parse`, `read:row_hash_verify`, `read:signature_verify`, `read:chain_verify`, `read:group_decode`, `read:group_decrypt`, `read:group_decrypt.cipher`, and `read:group_plaintext_parse`.

- [ ] **Step 1: Write failing verified-read stage test**

The test enables `TN_PERF_TRACE`, emits and verified-reads one record for each cipher, then asserts required read stages exist.

- [ ] **Step 2: Run test to verify failure**

Expected: missing read stages.

- [ ] **Step 3: Add Python read-stage counters**

Instrument Python read path around line parse, hash/signature/chain verification, group ciphertext decode, group decrypt, and plaintext parse.

- [ ] **Step 4: Add Rust read-stage counters**

Instrument `tn-core` read path with the same stage names for BTN/native reads.

- [ ] **Step 5: Run verified-read stage test and functional smoke**

Expected: pass.

- [ ] **Step 6: Commit read-stage instrumentation**

```powershell
git add python/tn/reader.py crypto/tn-core/src/runtime/read.rs python/tests/perf_smoke/instrumentation/test_verified_read_perf_stages.py
git commit -m "feat: instrument verified read stages"
```

### Task 4: Local Perf Artifact Runner

**Files:**
- Create directory: `tools/bench_artifact_py/tn_bench/`
- Create: `tools/bench_artifact_py/tn_bench/local_perf.py`
- Create: `tools/bench_artifact_py/tn_bench/artifact.py`
- Create: `tools/bench_artifact_py/tn_bench/cells.py`
- Create: `tools/bench_artifact_py/tn_bench/stats.py`
- Create: `tools/bench_artifact_py/tn_bench/sufficiency.py`
- Create: `python/tests/perf_smoke/artifact/test_local_perf_artifact.py`

**Interfaces:**
- Produces CLI `python -m tn_bench.local_perf --profile local-smoke`.
- Produces artifact directories under `artifacts/bench-artifact-local-<rev>-<timestamp>/`.

- [ ] **Step 1: Write failing artifact tests**

Tests require exact payload sizes `64`, `256`, and `1024`, env descriptor with `environment_class`, raw NDJSON parsing, warmup exclusion, and stage sufficiency failure on missing stages.

- [ ] **Step 2: Run tests to verify failure**

Expected: missing `tn_bench` module.

- [ ] **Step 3: Implement minimal runner**

Implement local smoke for 3 ciphers x 3 payloads x recipients `1,4,8`, with `--trials`, `--ops`, `--warmup-trials`, and `--btn-stress`.

- [ ] **Step 4: Run artifact tests**

Expected: pass.

- [ ] **Step 5: Run tiny local perf smoke**

```powershell
$env:PYTHONPATH='C:\codex\tn-worktrees\tn-proto-perf-instrumentation\python;C:\codex\tn-worktrees\tn-proto-perf-instrumentation\tools\bench_artifact_py'
$env:TN_PERF_TRACE='1'
C:\codex\tn\tn_proto\.venv\Scripts\python.exe -m tn_bench.local_perf --profile local-smoke --trials 1 --ops 3
```

Expected: all BTN/JWE/HIBE cells emit/read successfully and write artifacts marked `paper_eligible: false`.

- [ ] **Step 6: Commit runner**

```powershell
git add tools/bench_artifact_py python/tests/perf_smoke/artifact
git commit -m "feat: add local three-cipher perf smoke runner"
```

### Task 5: Final Verification

**Files:**
- No new files unless fixes are required.

**Commands:**

```powershell
$env:PYTHONPATH='C:\codex\tn-worktrees\tn-proto-perf-instrumentation\python'
C:\codex\tn\tn_proto\.venv\Scripts\python.exe -m pytest python\tests\perf_smoke -q
```

```powershell
$env:PYTHONPATH='C:\codex\tn-worktrees\tn-proto-perf-instrumentation\python;C:\codex\tn-worktrees\tn-proto-perf-instrumentation\tools\bench_artifact_py'
$env:TN_PERF_TRACE='1'
C:\codex\tn\tn_proto\.venv\Scripts\python.exe -m tn_bench.local_perf --profile local-smoke --trials 1 --ops 5
```

Expected: tests pass, runner writes an artifact, and `git status --short` is clean except ignored generated artifacts/native binaries.
