"""Sealing-throughput comparison: raw SHA-256 tokens (old) vs HMAC tokens (new).

Two benches in one script:

1. Microbench on the tokenization step alone (field_name + value -> token).
   Shows the pure per-field cost delta, with no BGW in the loop.

2. Full envelope sealing via tn.log(), end-to-end. Monkey-patches the
   logger's token function to the old SHA-256 path for the baseline pass,
   then restores it to the HMAC path. Measures entries/sec and ms/entry
   at realistic field counts.

Run (from WSL with the crypto build present):
    TNCRYPTO_LIB=/mnt/c/codex/content_platform/tn-protocol/crypto/build/libtncrypto.so \\
        /usr/bin/python bench/bench_indexing.py --events 2000 --fields 6
"""

from __future__ import annotations

import argparse
import hashlib
import statistics
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tn import indexing
from tn.canonical import canonical_bytes

# ----------------------------------------------------------------------
# Microbench: single-field tokenization
# ----------------------------------------------------------------------


def _sha256_token(field_name: str, value: object) -> str:
    """The pre-change behavior: raw SHA-256 over canonical(value).

    Note: the original code omitted field_name from the hash input
    (a pre-existing bug). Reproducing that exactly for a faithful
    baseline.
    """
    digest = hashlib.sha256(canonical_bytes(value)).hexdigest()
    return "sha256:" + digest


def micro(iterations: int) -> None:
    master = indexing.new_master_key()
    key = indexing.derive_group_index_key(master, "bench_ceremony", "default")

    sample_values = [
        ("amount", 4200),
        ("email", "alice@example.com"),
        ("ip", "10.0.0.17"),
        ("request_id", "req-abc-7f3a"),
        ("path", "/orders/checkout"),
        ("country", "ES"),
    ]

    # Warm up
    for fname, fval in sample_values:
        _sha256_token(fname, fval)
        indexing.index_token(key, fname, fval)

    def run(fn) -> float:
        t0 = time.perf_counter()
        for _ in range(iterations):
            for fname, fval in sample_values:
                fn(fname, fval)
        return time.perf_counter() - t0

    fields_per_iter = len(sample_values)
    total = iterations * fields_per_iter

    t_sha = run(_sha256_token)
    t_hmac = run(lambda f, v: indexing.index_token(key, f, v))

    print("\n=== Microbench: single-field tokenization ===")
    print(f"  fields hashed : {total:,}")
    print(
        f"  SHA-256 (old) : {t_sha * 1000:9.2f} ms total  "
        f"-> {(t_sha / total) * 1e6:6.2f} µs/field  "
        f"({total / t_sha:,.0f} fields/s)"
    )
    print(
        f"  HMAC    (new) : {t_hmac * 1000:9.2f} ms total  "
        f"-> {(t_hmac / total) * 1e6:6.2f} µs/field  "
        f"({total / t_hmac:,.0f} fields/s)"
    )
    delta_pct = ((t_hmac - t_sha) / t_sha) * 100.0
    print(f"  delta         : {delta_pct:+.1f}% (hmac vs sha256)")


# ----------------------------------------------------------------------
# Full-envelope sealing bench (tn.log end-to-end)
# ----------------------------------------------------------------------


def seal(events: int, fields: int) -> None:
    import tn  # deferred: needs native lib

    fvs = [
        ("amount", lambda i: 100 + i),
        ("email", lambda i: f"user{i}@example.com"),
        ("ip", lambda i: f"10.0.0.{i % 255}"),
        ("order_id", lambda i: f"A{i:06d}"),
        ("country", lambda i: ["US", "ES", "DE", "JP", "BR"][i % 5]),
        ("method", lambda i: ["POST", "PUT"][i % 2]),
    ][:fields]
    if len(fvs) < fields:
        raise SystemExit(f"only {len(fvs)} canned fields available, asked for {fields}")

    def _time_pass(token_fn) -> tuple[float, list[float]]:
        with tempfile.TemporaryDirectory(prefix="tnbench_") as td:
            ws = Path(td)
            yaml_path = ws / "tn.yaml"
            log_path = ws / "logs" / "tn.ndjson"
            tn.init(yaml_path, log_path=log_path, pool_size=4)

            import tn.logger as _lg

            original = _lg.index_token
            _lg.index_token = token_fn  # type: ignore[assignment]
            try:
                # Warm-up: one call to prime ChainState + handlers.
                tn.info("bench.warmup", warmup=True)

                latencies_us: list[float] = []
                t0 = time.perf_counter()
                for i in range(events):
                    payload = {name: fn(i) for name, fn in fvs}
                    t_entry = time.perf_counter()
                    tn.info("bench.event", **payload)
                    latencies_us.append((time.perf_counter() - t_entry) * 1e6)
                tn.flush_and_close()
                total = time.perf_counter() - t0
                return total, latencies_us
            finally:
                _lg.index_token = original  # type: ignore[assignment]
                try:
                    tn.flush_and_close()
                except Exception:
                    pass

    def _sha_baseline_token(_key, field_name, value):
        """Signature-compatible with indexing.index_token; ignores the key
        to reproduce the pre-change behavior (raw SHA-256 on value only)."""
        return _sha256_token(field_name, value)

    print("\n=== Full-envelope sealing via tn.log() ===")
    print(f"  events: {events:,}  fields/event: {fields}  pool_size: 4")

    rows = []
    for label, fn in [
        ("SHA-256 (old)", _sha_baseline_token),
        ("HMAC    (new)", indexing.index_token),
    ]:
        total, latencies = _time_pass(fn)
        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]  # 95th
        p99 = statistics.quantiles(latencies, n=100)[98]  # 99th
        rows.append((label, total, p50, p95, p99))
        print(f"\n  {label}")
        print(f"    total     : {total * 1000:.1f} ms  ({events / total:,.0f} entries/s)")
        print(f"    per entry : p50={p50:.1f}µs  p95={p95:.1f}µs  p99={p99:.1f}µs")

    # Summary
    t_sha = rows[0][1]
    t_hmac = rows[1][1]
    delta_pct = ((t_hmac - t_sha) / t_sha) * 100.0
    print(f"\n  overhead of HMAC tokens vs raw SHA-256: {delta_pct:+.1f}%")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=2000)
    ap.add_argument("--fields", type=int, default=6)
    ap.add_argument("--micro-iters", type=int, default=50_000)
    ap.add_argument(
        "--skip-seal",
        action="store_true",
        help="skip the full sealing pass (no native lib required)",
    )
    args = ap.parse_args()

    micro(args.micro_iters)
    if not args.skip_seal:
        seal(args.events, args.fields)
    return 0


if __name__ == "__main__":
    sys.exit(main())
