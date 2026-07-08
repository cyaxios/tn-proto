from __future__ import annotations

from collections import defaultdict
import math
from typing import Any


def _percentile(sorted_values: list[int], p: float) -> int:
    if not sorted_values:
        return 0
    rank = max(1, int((p * len(sorted_values) + 0.999999999)))
    return sorted_values[min(rank - 1, len(sorted_values) - 1)]


def _mean(values: list[int]) -> int:
    if not values:
        return 0
    return int(round(sum(values) / len(values)))


def _stdev(values: list[int]) -> int:
    if len(values) < 2:
        return 0
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    return int(round(math.sqrt(variance)))


def _summarize_values(values: list[int], suffix: str) -> dict[str, int]:
    sorted_values = sorted(values)
    return {
        f"min{suffix}": sorted_values[0] if sorted_values else 0,
        f"p50{suffix}": _percentile(sorted_values, 0.50),
        f"p95{suffix}": _percentile(sorted_values, 0.95),
        f"p99{suffix}": _percentile(sorted_values, 0.99),
        f"max{suffix}": sorted_values[-1] if sorted_values else 0,
        f"mean{suffix}": _mean(sorted_values),
        f"stdev{suffix}": _stdev(sorted_values),
    }


def summarize_operation_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, int]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if int(row.get("trial", 0)) == 0:
            continue
        grouped[(str(row["cell"]), str(row["op"]))].append(row)

    out: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for (cell, op), items in grouped.items():
        latencies = [int(item.get("lat_ns", item.get("batch_lat_ns", 0))) for item in items]
        failures = sum(1 for item in items if not item.get("ok", False))
        payload_sizes = {int(item["payload_bytes"]) for item in items if "payload_bytes" in item}
        op_summary = {
            "count": len(items),
            "failures": failures,
            "payload_bytes": payload_sizes.pop() if len(payload_sizes) == 1 else 0,
            **_summarize_values(latencies, "_ns"),
        }
        for size_key in ("wire_bytes", "total_bytes"):
            values = [int(item[size_key]) for item in items if size_key in item]
            if values:
                op_summary.update(
                    {f"{size_key}_{key}": value for key, value in _summarize_values(values, "").items()}
                )
        out[cell][op] = op_summary
    return {cell: dict(ops) for cell, ops in out.items()}


def summarize_stage_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, dict[str, int]]]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if int(row.get("trial", 0)) == 0:
            continue
        grouped[(str(row["cell"]), str(row["op"]), str(row["stage"]))].append(row)

    out: dict[str, dict[str, dict[str, dict[str, int]]]] = defaultdict(lambda: defaultdict(dict))
    for (cell, op, stage), items in grouped.items():
        total_count = sum(int(item.get("count", 0)) for item in items)
        total_ns = sum(int(item.get("total_ns", 0)) for item in items)
        out[cell][op] = {
            **out[cell][op],
            stage: {
                "count": total_count,
                "trials": len(items),
                "total_ns": total_ns,
                "mean_ns": total_ns // total_count if total_count else 0,
            },
        }
    return {cell: {op: dict(stages) for op, stages in ops.items()} for cell, ops in out.items()}

