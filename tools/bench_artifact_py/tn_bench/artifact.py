from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class ArtifactLayout:
    root: Path
    raw_dir: Path
    stats_dir: Path
    work_dir: Path


def create_artifact_layout(root: Path) -> ArtifactLayout:
    raw = root / "raw"
    stats = root / "stats"
    work = root / "work"
    for path in (raw, stats, work):
        path.mkdir(parents=True, exist_ok=True)
    return ArtifactLayout(root=root, raw_dir=raw, stats_dir=stats, work_dir=work)


def write_ndjson(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":"), sort_keys=True))
            f.write("\n")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git_revision(cwd: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=cwd, text=True).strip()


def git_dirty(cwd: Path) -> bool:
    out = subprocess.check_output(["git", "status", "--short"], cwd=cwd, text=True)
    ignored = [line for line in out.splitlines() if not line.startswith("?? artifacts/")]
    return bool(ignored)


def write_env_descriptor(
    layout: ArtifactLayout,
    *,
    revision: str,
    dirty: bool,
    argv: list[str] | None = None,
) -> dict[str, Any]:
    paper_eligible = os.environ.get("TN_BENCH_PAPER_ELIGIBLE", "").strip().lower()
    env = {
        "schema": "tn-bench-env/v1",
        "environment_class": os.environ.get("TN_BENCH_ENVIRONMENT_CLASS", "local_windows_smoke"),
        "paper_eligible": paper_eligible in {"1", "true", "yes"},
        "revision": revision,
        "dirty": dirty,
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "argv": argv if argv is not None else sys.argv,
        "tn_perf_trace": os.environ.get("TN_PERF_TRACE", ""),
    }
    write_json(layout.raw_dir / "env.json", env)
    return env

