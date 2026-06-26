"""Unit tests for scenarios._harness.metrics."""

from scenarios._harness.metrics import (
    MetricsStore,
    Timer,
    percentiles,
)


def test_percentiles_basic():
    samples = list(range(1, 101))  # 1..100
    p = percentiles(samples, [50, 99])
    assert 49 <= p[50] <= 51
    assert 98 <= p[99] <= 100


def test_percentiles_empty_returns_none():
    p = percentiles([], [50, 99])
    assert p[50] is None
    assert p[99] is None


def test_timer_records_ms_positive():
    store = MetricsStore()
    with Timer(store, "ceremony_ms", unit="ms"):
        pass
    assert "ceremony_ms" in store.scalars
    assert store.scalars["ceremony_ms"] >= 0


def test_timer_us_accumulates_samples():
    store = MetricsStore()
    for _ in range(5):
        with Timer(store, "log_us", unit="us", sample=True):
            pass
    assert len(store.samples["log_us"]) == 5


def test_summary_row_from_store_includes_p50_p99(tmp_path):
    store = MetricsStore()
    store.scalars["ceremony_ms"] = 12.3
    store.samples["log_us"] = list(range(1, 101))
    row = store.summary_row(persona="alice", scenario="s01_hello", runid="testrun", cell=None)
    assert row["ceremony_ms"] == 12.3
    assert row["log_p50_us"] is not None
    assert row["log_p99_us"] is not None
    assert row["log_mean_us"] is not None
