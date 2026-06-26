"""Timers, percentile helpers, metric store, CSV rollup.

No test thresholds. All numbers are recorded; charts are built
downstream from metrics.json / _summary.csv.
"""

from __future__ import annotations

import csv
import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Fixed column order for _summary.csv (spec §5.2).
SUMMARY_COLUMNS = [
    "runid",
    "persona",
    "scenario",
    "cell",
    "status",
    "error",
    "notes",
    "ceremony_ms",
    "tn_init_ms",
    "log_p50_us",
    "log_p99_us",
    "log_mean_us",
    "read_p50_us",
    "read_p99_us",
    "read_mean_us",
    "envelope_bytes_mean",
    "envelope_bytes_p99",
    "plaintext_bytes_mean",
    "envelope_plaintext_ratio",
    "rotation_ms",
    "revoke_ms",
    "vault_sync_ms",
    "vault_restore_ms",
    "per_recipient_wrap_us",
    "emit_file_us",
    "emit_kafka_us",
    "emit_delta_us",
    "recipient_count",
    "group_count",
    "log_count",
    "handler_count",
    "field_count",
    "chain_verified",
    "signature_verified",
    "no_plaintext_in_envelope",
    "revoked_cant_read",
    "wrong_group_gets_ciphertext",
    "vault_returns_encrypted_only",
]


def percentiles(samples: list[float], pcts: list[int]) -> dict[int, float | None]:
    """Return {pct: value} for each pct in pcts; None for empty input."""
    if not samples:
        return {p: None for p in pcts}
    srt = sorted(samples)
    n = len(srt)
    out: dict[int, float | None] = {}
    for p in pcts:
        # Nearest-rank, clamped
        idx = max(0, min(n - 1, int(round((p / 100.0) * n)) - 1))
        out[p] = srt[idx]
    return out


@dataclass
class MetricsStore:
    """Per-scenario (or per-cell) metric container."""

    scalars: dict[str, Any] = field(default_factory=dict)
    samples: dict[str, list[float]] = field(default_factory=dict)
    invariants: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add_sample(self, key: str, value: float) -> None:
        self.samples.setdefault(key, []).append(value)

    def set_scalar(self, key: str, value: Any) -> None:
        self.scalars[key] = value

    def set_invariant(self, name: str, passed: bool) -> None:
        self.invariants[name] = bool(passed)
        if not passed:
            self.notes.append(f"invariant_failed:{name}")

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def summary_row(
        self,
        *,
        persona: str,
        scenario: str,
        runid: str,
        cell: str | None,
        status: str = "ok",
        error: str | None = None,
    ) -> dict[str, Any]:
        """Flatten store into a dict keyed by SUMMARY_COLUMNS."""
        row: dict[str, Any] = {col: None for col in SUMMARY_COLUMNS}
        row["runid"] = runid
        row["persona"] = persona
        row["scenario"] = scenario
        row["cell"] = cell
        row["status"] = status
        row["error"] = error
        row["notes"] = ";".join(self.notes) if self.notes else None

        for k, v in self.scalars.items():
            if k in row:
                row[k] = v

        # Derive _p50/_p99/_mean for every sample series whose base name
        # (minus trailing _us/_ms) has matching summary columns.
        for key, series in self.samples.items():
            if not series:
                continue
            base, _, unit = key.rpartition("_")
            p = percentiles(series, [50, 99])
            p50 = f"{base}_p50_{unit}"
            p99 = f"{base}_p99_{unit}"
            mean_key = f"{base}_mean_{unit}"
            if p50 in row:
                row[p50] = p[50]
            if p99 in row:
                row[p99] = p[99]
            if mean_key in row:
                row[mean_key] = statistics.mean(series)

        for name, passed in self.invariants.items():
            if name in row:
                row[name] = passed
        return row

    def to_json(self) -> dict[str, Any]:
        """Full dump including raw sample arrays (for per-scenario JSON)."""
        return {
            "scalars": self.scalars,
            "samples": self.samples,
            "invariants": self.invariants,
            "notes": self.notes,
        }


class Timer:
    """Context manager: records wall-clock into a MetricsStore.

    unit='ms' or 'us'. sample=True → append to samples[key]; else
    overwrite scalars[key] with the single measurement.
    """

    def __init__(self, store: MetricsStore, key: str, unit: str = "ms", sample: bool = False):
        self.store = store
        self.key = key
        self.unit = unit
        self.sample = sample
        self._t0: float = 0.0

    def __enter__(self) -> Timer:
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        dt = time.perf_counter() - self._t0
        value = dt * 1000.0 if self.unit == "ms" else dt * 1_000_000.0
        if self.sample:
            self.store.add_sample(self.key, value)
        else:
            self.store.set_scalar(self.key, value)


def write_summary_row(csv_path: Path, row: dict[str, Any]) -> None:
    """Append a row to _summary.csv, writing the header if the file is new."""
    new = not csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k) for k in SUMMARY_COLUMNS})


def write_metrics_json(
    outdir: Path,
    store: MetricsStore,
    *,
    persona: str,
    scenario: str,
    runid: str,
    status: str,
    error: str | None,
) -> None:
    """Write <outdir>/metrics.json from a MetricsStore."""
    outdir.mkdir(parents=True, exist_ok=True)
    doc = {
        "runid": runid,
        "persona": persona,
        "scenario": scenario,
        "status": status,
        "error": error,
        **store.to_json(),
    }
    (outdir / "metrics.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
