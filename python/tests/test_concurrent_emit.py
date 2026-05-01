"""Concurrent emit: chain integrity under threaded tn.log() callers.

The Python emit pipeline is multi-step:
    classify -> encrypt -> chain.advance -> _compute_row_hash -> sign
              -> append to log -> chain.commit

If two threads race through this path without a lock, both can read the
same prev_hash from chain.advance() before either calls chain.commit().
The result on disk: two envelopes claiming the same (event_type, sequence)
slot, with different row_hashes. The reader catches the broken chain
linkage on one of them, but the log is corrupted.

This test exercises that path with enough threads + iterations to expose
the race today on the GIL-only assumption (which doesn't hold across
the encrypt/sign/IO calls that release the GIL).

See Workstream D7 in 2026-04-24-tn-protocol-review-remediation.md.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _reset_runtime():
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _read_user_envelopes(log_path: Path) -> list[dict]:
    out = []
    if not log_path.exists():
        return out
    for raw in log_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        env = json.loads(raw)
        if not env.get("event_type", "").startswith("tn."):
            out.append(env)
    return out


def test_concurrent_emit_preserves_chain_and_uniqueness(tmp_path):
    """N threads each call tn.info() M times; assert N*M unique sequences,
    no interleaved bytes, and every envelope verifies clean."""
    yaml = tmp_path / "tn.yaml"
    # Force the Python path so we exercise the lock we just added (the
    # Rust runtime has its own internal Mutex; this test targets the
    # Python TNRuntime's _emit_lock).
    import os

    prior = os.environ.get("TN_FORCE_PYTHON")
    os.environ["TN_FORCE_PYTHON"] = "1"
    try:
        tn.init(yaml, cipher="btn")

        n_threads = 16
        per_thread = 50
        total_expected = n_threads * per_thread
        errors: list[BaseException] = []
        barrier = threading.Barrier(n_threads)

        def worker(tid: int) -> None:
            try:
                # Synchronize start so all threads hit emit at the same moment.
                barrier.wait()
                for i in range(per_thread):
                    tn.info("evt.race", thread=tid, i=i)
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(t,), name=f"emit-{t}")
            for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if errors:
            raise AssertionError(f"worker threads raised: {errors!r}")

        tn.flush_and_close()

        # FINDINGS #2 — logs namespaced under .tn/<yaml-stem>/.
        log_path = tmp_path / ".tn" / "tn" / "logs" / "tn.ndjson"
        assert log_path.exists(), "no log file produced"

        # Every line must parse as JSON: no torn lines, no interleaved bytes.
        raw_lines = [
            line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        for line in raw_lines:
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                raise AssertionError(
                    f"interleaved/torn write detected in log file: {exc!r}\nline={line!r}"
                ) from exc

        envs = _read_user_envelopes(log_path)
        assert len(envs) == total_expected, (
            f"expected {total_expected} envelopes, got {len(envs)}"
        )

        # All sequences are unique and form a contiguous range 1..N for
        # a single event_type (per-event-type chain).
        seqs = sorted(env["sequence"] for env in envs if env["event_type"] == "evt.race")
        assert seqs == list(range(1, total_expected + 1)), (
            f"sequence numbers not unique/contiguous: first 10 dups => "
            f"{[s for s in seqs if seqs.count(s) > 1][:10]}"
        )

        # Verify chain + signatures via the standard reader.
        # Use verify=True so the _valid block surfaces; assert each entry is sound.
        # all_runs=True because flush_and_close + first-read re-init mints a
        # fresh run_id, so the strict default would filter out our 800 events
        # (FINDINGS #4 / #12).
        count = 0
        for entry in tn.read(log_path, verify=True, all_runs=True):
            if entry["event_type"] != "evt.race":
                continue
            valid = entry.get("_valid") or {}
            assert all(valid.values()), f"corrupt evt.race entry: {entry}"
            count += 1
        assert count == total_expected
    finally:
        if prior is None:
            os.environ.pop("TN_FORCE_PYTHON", None)
        else:
            os.environ["TN_FORCE_PYTHON"] = prior
