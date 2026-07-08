"""Make the bench tool package importable for the perf_smoke suite.

``tn_bench`` lives in ``tools/bench_artifact_py`` (outside the installed
``tn`` package) by design — it is a repo-local benchmark harness, not a
shipped module. Insert its directory ahead of collection so
``pytest python/tests/perf_smoke`` works without a manual PYTHONPATH.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BENCH_DIR = Path(__file__).resolve().parents[3] / "tools" / "bench_artifact_py"
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))
