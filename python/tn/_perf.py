"""Tiny Python-side performance counters for TN local benchmark runs.

This mirrors the Rust ``tn_core::perf`` surface closely enough for the
local artifact runner to merge Python and Rust stage snapshots without
guesswork. Counters are enabled only when ``TN_PERF_TRACE`` is set to a
non-empty value other than ``"0"``.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator


@dataclass
class _StageStats:
    count: int = 0
    total_ns: int = 0


@dataclass
class _MetricStats:
    count: int = 0
    total: int = 0
    min_value: int | None = None
    max_value: int | None = None


_LOCK = threading.Lock()
_COUNTERS: dict[str, _StageStats] = {}
_METRICS: dict[str, _MetricStats] = {}


def enabled() -> bool:
    value = os.environ.get("TN_PERF_TRACE")
    return value is not None and value != "" and value != "0"


def record_ns(stage: str, ns: int) -> None:
    if not enabled():
        return
    if ns < 0:
        ns = 0
    with _LOCK:
        stats = _COUNTERS.setdefault(stage, _StageStats())
        stats.count += 1
        stats.total_ns += int(ns)


def record_metric(name: str, value: int) -> None:
    if not enabled():
        return
    value = int(value)
    with _LOCK:
        stats = _METRICS.setdefault(name, _MetricStats())
        stats.count += 1
        stats.total += value
        stats.min_value = value if stats.min_value is None else min(stats.min_value, value)
        stats.max_value = value if stats.max_value is None else max(stats.max_value, value)


@contextmanager
def time_stage(stage: str) -> Iterator[None]:
    if not enabled():
        yield
        return

    start = time.perf_counter_ns()
    try:
        yield
    finally:
        record_ns(stage, time.perf_counter_ns() - start)


def snapshot() -> list[tuple[str, int, int]]:
    with _LOCK:
        rows = [(stage, stats.count, stats.total_ns) for stage, stats in _COUNTERS.items()]
    rows.sort(key=lambda row: row[2], reverse=True)
    return rows


def snapshot_metrics() -> list[tuple[str, int, int, int, int]]:
    with _LOCK:
        rows = [
            (
                name,
                stats.count,
                stats.total,
                0 if stats.min_value is None else stats.min_value,
                0 if stats.max_value is None else stats.max_value,
            )
            for name, stats in _METRICS.items()
        ]
    rows.sort(key=lambda row: row[0])
    return rows


def reset() -> None:
    with _LOCK:
        _COUNTERS.clear()
        _METRICS.clear()
