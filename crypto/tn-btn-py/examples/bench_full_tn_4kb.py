"""Full-TN-pipeline benchmark at a single 4 KB payload.

Runs the SAME full tn.info() / tn.read() pipeline for all three
ciphers: BGW, JWE, and btn. Measures seal-side and open-side
throughput at 4 KB, which is where all three are exercised on both
the crypto and the body-encryption paths. Matches the Table §6.2
methodology from crypto_model_JWE_Seal.md but at one payload size.

Pipeline for each variant (identical except the cipher):
  - tn.info(event_type, **fields)
    → canonical serialization
    → HMAC-SHA256 per-field index tokens
    → chain maintenance (prev_hash / row_hash linking)
    → Ed25519 signature over row_hash
    → cipher.encrypt(plaintext)
    → ndjson envelope write
  - tn.read(log_path)
    → parse ndjson
    → cipher.decrypt(ciphertext)
    → verify Ed25519 signature
    → verify chain linkage

Run from `tn-protocol/python/`:
    /c/codex/content_platform/.venv/Scripts/python.exe \\
        ../crypto/btn-py/examples/bench_full_tn_4kb.py
"""
from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

_TN_PY = Path(__file__).resolve().parents[3] / "python"
if str(_TN_PY) not in sys.path:
    sys.path.insert(0, str(_TN_PY))

PAYLOAD_SIZE = 4096
EVENTS = 2000


def _make_event(target_bytes: int, seq: int) -> dict:
    base = {"amount": 4200 + seq, "email": "alice@example.com",
            "order_id": f"A{seq:09d}"}
    base_len = len(json.dumps(base, separators=(",", ":")))
    overhead = base_len + len(',"blob":""')
    pad = max(0, target_bytes - overhead)
    base["blob"] = "x" * pad
    return base


def run_cipher(name: str, events: int, size: int) -> tuple[float, list[float], float, list[float], int, int]:
    import tn
    with tempfile.TemporaryDirectory() as tmp:
        yaml = Path(tmp) / "tn.yaml"
        log = Path(tmp) / "logs" / "tn.ndjson"

        tn.init(yaml, log_path=log, pool_size=4, cipher=name)

        seal_us: list[float] = []
        t0 = time.perf_counter()
        for i in range(events):
            evt = _make_event(size, i)
            t = time.perf_counter()
            tn.info("bench.event", **evt)
            seal_us.append((time.perf_counter() - t) * 1e6)
        tn.flush_and_close()
        seal_total = time.perf_counter() - t0

        # Measure actual log file size.
        log_dir = log.parent
        log_files = [p for p in log_dir.iterdir() if p.is_file()]
        bytes_on_disk = sum(p.stat().st_size for p in log_files)
        lines = 0
        for p in log_files:
            with open(p, "rb") as f:
                lines += sum(1 for _ in f)

        # Open pass: reopen the ceremony and iterate through tn.read().
        tn.init(yaml, log_path=log, pool_size=4, cipher=name)
        open_us: list[float] = []
        t1 = time.perf_counter()
        count = 0
        for entry in tn.read():
            t = time.perf_counter()
            _ = entry["plaintext"]
            _ = entry["envelope"]["event_type"]
            open_us.append((time.perf_counter() - t) * 1e6)
            count += 1
        tn.flush_and_close()
        open_total = time.perf_counter() - t1

        return seal_total, seal_us, open_total, open_us, bytes_on_disk, lines


def report(name: str, events: int, size: int, seal_total: float,
           seal_us: list[float], open_total: float, open_us: list[float],
           bytes_on_disk: int, lines: int):
    seal_rate = events / seal_total
    open_rate = lines / open_total if open_total > 0 else 0
    bytes_per = bytes_on_disk / max(lines, 1)
    seal_p50 = statistics.median(seal_us)
    open_p50 = statistics.median(open_us) if open_us else 0
    print(
        f"  {name:<4}  seal {seal_rate:>6,.0f}/s p50 {seal_p50:>6.1f}µs   "
        f"open {open_rate:>6,.0f}/s p50 {open_p50:>6.1f}µs   "
        f"bytes/event {bytes_per:>6.0f}   lines {lines}"
    )


def main():
    import tn
    print("Full TN pipeline head-to-head — BGW vs JWE vs btn")
    print(f"  Python:  {sys.version.split()[0]}  Platform: {sys.platform}")
    print(f"  Payload: {PAYLOAD_SIZE} B  Events: {EVENTS}  N=1 recipient")
    print("  Each variant: full tn.info() pipeline (HMAC index tokens +")
    print("  Ed25519 row_hash signature + chain + cipher seal + ndjson).")
    print("-" * 90)

    for name in ["bgw", "jwe", "btn"]:
        try:
            results = run_cipher(name, EVENTS, PAYLOAD_SIZE)
            report(name, EVENTS, PAYLOAD_SIZE, *results)
        except Exception as e:
            print(f"  {name:<4}  SKIPPED: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
