"""Compare tn.info timing with a synthetic Python file-write workload.

Measure the full Rust-backed emit call and a separate append-and-flush
loop using generated lines. The table reports both observed timings.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn  # type: ignore[import-not-found]

MSG_SIZES = [64, 256, 1024, 4096, 16384, 65536]
N = 500


def _p50(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else 0.0


def time_tn_info(size: int) -> float:
    with tempfile.TemporaryDirectory() as td:
        tn.init(Path(td) / "tn.yaml", cipher="btn")
        assert tn.using_rust()
        payload = "x" * size
        for _ in range(20):
            tn.info("warm", p=payload)
        samples = []
        for _ in range(N):
            t0 = time.perf_counter()
            tn.info("real", p=payload)
            samples.append((time.perf_counter() - t0) * 1e6)
        tn.flush_and_close()
    return _p50(samples)


def time_bare_file_write(size: int) -> float:
    # Generate a JSON line with fixed metadata and a size-dependent payload.
    header = (
        b'{"did":"did:key:zABC","timestamp":"2026-04-21T12:00:00.000000Z",'
        b'"event_id":"00000000-0000-0000-0000-00000000000a",'
        b'"event_type":"real","level":"info","sequence":1,'
        b'"prev_hash":"sha256:aa","row_hash":"sha256:bb",'
        b'"signature":"' + b"x" * 86 + b'","default":{"ciphertext":"'
    )
    # base64 length ~ ceil(n/3)*4
    ct_b64_len = ((size + 32) + 2) // 3 * 4
    trailer = b'","field_hashes":{"p":"hmac-sha256:v1:' + b"x" * 64 + b'"}}}\n'
    line = header + b"A" * ct_b64_len + trailer

    with tempfile.TemporaryDirectory() as td:
        fp = Path(td) / ".tn" / "logs" / "tn.ndjson"
        fp.parent.mkdir(parents=True)
        # Mirror the runtime: open with append, write_all, flush.
        f = open(fp, "ab")
        for _ in range(20):
            f.write(line)
            f.flush()
        samples = []
        for _ in range(N):
            t0 = time.perf_counter()
            f.write(line)
            f.flush()
            samples.append((time.perf_counter() - t0) * 1e6)
        f.close()
    return _p50(samples)


def main() -> int:
    print("\n=== tn.info and synthetic file-write timing ===")
    print(
        f"{'size':>6} | {'tn.info µs':>11} | {'synthetic file µs':>17}"
    )
    print("-" * 70)
    for size in MSG_SIZES:
        info_us = time_tn_info(size)
        file_us = time_bare_file_write(size)
        print(f"{size:>6} | {info_us:>11.1f} | {file_us:>17.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
