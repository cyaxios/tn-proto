from __future__ import annotations

from collections import defaultdict
from typing import Any


def _percentile(sorted_values: list[int], p: float) -> int:
    if not sorted_values:
        return 0
    rank = max(1, int((p * len(sorted_values) + 0.999999999)))
    return sorted_values[min(rank - 1, len(sorted_values) - 1)]


def summarize_operation_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, int]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if int(row.get("trial", 0)) == 0:
            continue
        grouped[(str(row["cell"]), str(row["op"]))].append(row)

    out: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for (cell, op), items in grouped.items():
        latencies = sorted(int(item.get("lat_ns", item.get("batch_lat_ns", 0))) for item in items)
        failures = sum(1 for item in items if not item.get("ok", False))
        out[cell][op] = {
            "count": len(items),
            "failures": failures,
            "min_ns": latencies[0] if latencies else 0,
            "p50_ns": _percentile(latencies, 0.50),
            "p95_ns": _percentile(latencies, 0.95),
            "p99_ns": _percentile(latencies, 0.99),
            "max_ns": latencies[-1] if latencies else 0,
        }
    return {cell: dict(ops) for cell, ops in out.items()}

