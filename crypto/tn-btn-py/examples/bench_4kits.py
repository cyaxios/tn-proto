"""Focused benchmark: measure log and decrypt throughput at two
revocation states.

Stage A: mint 4 kits, log for 30 seconds, measure throughput. Then
read back the whole log with one surviving kit and measure decrypt
throughput.

Stage B: revoke 2 of the 4 kits, keep the remaining 2, log for
another 30 seconds, measure. Read back and measure decrypt throughput
with a still-entitled kit.

No file leaks — single persistent log file per stage, closed cleanly.
No handle growth — the Runtime holds exactly one file handle for the
whole stage.

Usage:
  python examples/bench_4kits.py --stage-secs=30 --payload-size=256
"""
import argparse
import sys
import tempfile
import time
from pathlib import Path

import tn_btn as btn


def bench_log(rt: btn.Runtime, payload: bytes, duration_secs: float) -> tuple[int, float]:
    """Log `payload` repeatedly for `duration_secs`. Return (count, elapsed)."""
    start = time.perf_counter()
    count = 0
    while time.perf_counter() - start < duration_secs:
        # Batch 100 writes between time checks to amortize clock overhead.
        for _ in range(100):
            rt.log(payload)
        count += 100
    elapsed = time.perf_counter() - start
    return count, elapsed


def bench_read(log_path: Path, kit: bytes) -> tuple[int, float]:
    """Read + decrypt every entry in the log with `kit`.
    Returns (entry_count, elapsed)."""
    start = time.perf_counter()
    count = 0
    for _ in btn.read(log_path, kit):
        count += 1
    elapsed = time.perf_counter() - start
    return count, elapsed


def report_stage(
    name: str,
    log_count: int,
    log_elapsed: float,
    dec_count: int,
    dec_elapsed: float,
    file_size: int,
    payload_size: int,
):
    log_rate = log_count / log_elapsed
    log_mb = log_count * payload_size / (1024 * 1024)
    dec_rate = dec_count / dec_elapsed
    dec_mb = dec_count * payload_size / (1024 * 1024)
    print(f"=== {name} ===")
    print(f"  LOG:     {log_count:>8} entries in {log_elapsed:>5.2f}s  "
          f"{log_rate:>9,.0f} logs/s   {log_mb/log_elapsed:>6.2f} MB/s sealed")
    print(f"  DECRYPT: {dec_count:>8} entries in {dec_elapsed:>5.2f}s  "
          f"{dec_rate:>9,.0f} decrypts/s  {dec_mb/dec_elapsed:>6.2f} MB/s plaintext")
    print(f"  FILE:    {file_size:>8} bytes ({file_size / (1024*1024):.2f} MB)")
    print()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stage-secs", type=float, default=30.0)
    p.add_argument("--payload-size", type=int, default=256)
    args = p.parse_args()

    payload = b"x" * args.payload_size

    print(f"btn bench (4 kits, 2 stages)")
    print(f"  btn.tree_height: {btn.tree_height()}")
    print(f"  btn.max_leaves:  {btn.max_leaves()}")
    print(f"  stage_secs:      {args.stage_secs}")
    print(f"  payload_size:    {args.payload_size}")
    print("-" * 80)

    with tempfile.TemporaryDirectory(prefix="btn-bench-") as tmp:
        dir_path = Path(tmp) / "ceremony"

        # --- Stage A: mint 4, log, read. ---
        with btn.init(dir_path) as rt:
            kits = [rt.mint() for _ in range(4)]
            print(f"Minted 4 kits. issued_count={rt.issued_count}, revoked_count={rt.revoked_count}")
            print()

            print(f"Stage A: logging for {args.stage_secs}s with 4 active readers...")
            log_count_a, log_elapsed_a = bench_log(rt, payload, args.stage_secs)

        # Reopen to read. Must close first so the final log data is
        # flushed to disk.
        file_size_a = (dir_path / "log.btn").stat().st_size
        print(f"Stage A: reading + decrypting full log with kits[0]...")
        dec_count_a, dec_elapsed_a = bench_read(dir_path / "log.btn", kits[0])

        report_stage(
            "Stage A (4 active)",
            log_count_a, log_elapsed_a,
            dec_count_a, dec_elapsed_a,
            file_size_a, args.payload_size,
        )

        # --- Stage B: revoke 2, keep 2, log more, read. ---
        with btn.init(dir_path) as rt:
            print(f"Revoking kits[2] and kits[3]...")
            rt.revoke_kit(kits[2])
            rt.revoke_kit(kits[3])
            print(f"  issued_count={rt.issued_count}, revoked_count={rt.revoked_count}")
            print()

            print(f"Stage B: logging for {args.stage_secs}s with 2 active readers...")
            log_count_b, log_elapsed_b = bench_log(rt, payload, args.stage_secs)

        file_size_b = (dir_path / "log.btn").stat().st_size
        print(f"Stage B: reading + decrypting full log with kits[0] (still entitled)...")
        dec_count_b, dec_elapsed_b = bench_read(dir_path / "log.btn", kits[0])

        report_stage(
            "Stage B (4 minted, 2 revoked)",
            log_count_b, log_elapsed_b,
            dec_count_b, dec_elapsed_b,
            file_size_b, args.payload_size,
        )

        # Quick sanity: a revoked kit fails on Stage-B-era entries.
        print("Sanity: verifying kits[2] (revoked) fails on stage-B entries...")
        # A revoked kit CAN still read stage-A entries (pre-revoke) but
        # not stage-B entries (post-revoke). Full-log read with kits[2]
        # therefore returns only stage-A entries.
        count_as_revoked, _ = bench_read(dir_path / "log.btn", kits[2])
        print(f"  kits[2] decrypted {count_as_revoked} of {dec_count_b} total entries "
              f"(should equal stage A count = {log_count_a})")
        if count_as_revoked == log_count_a:
            print("  OK — revoked kit sees only pre-revocation entries.")
        else:
            print(f"  UNEXPECTED — expected exactly {log_count_a}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
