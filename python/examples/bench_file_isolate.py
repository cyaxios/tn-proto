"""Isolate the file-handler cost inside tn.info.

Each `tn.info` includes an ndjson append + flush on the log file. To answer
"what would I see without the file handler?" we measure:

  (a) full tn.info through the Rust path (everything)
  (b) same bytes, just the file write the runtime does (open once, then
      write_all + flush per call)

Subtracting (b) from (a) gives the upper-bound estimate of the crypto +
envelope + PyO3 cost with no file I/O. (Upper bound because the runtime's
file write in Rust avoids the Python-side write syscall.)
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
    # Estimate the bytes per envelope line. Ciphertext + base64 + envelope
    # header overhead. From the perf matrix: ~1569 bytes of ciphertext for
    # a 1 KB plaintext at 1 revocation; at 0 revocations the ct is smaller.
    # Pad to a reasonable estimate of ndjson line size.
    # We'll use: 400 header bytes + 4/3 * plaintext_size for base64 of ct.
    # For raw_size the line is base64 of ct + ~400 bytes of JSON scaffold.
    # The actual runtime writes exactly one line per emit so match that shape.
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
    print("\n=== Isolating file-handler cost inside tn.info ===")
    print(
        f"{'size':>6} | {'tn.info µs':>11} | {'file µs':>9} | {'no-file est µs':>15} | {'no-file events/s':>17}"
    )
    print("-" * 70)
    for size in MSG_SIZES:
        info_us = time_tn_info(size)
        file_us = time_bare_file_write(size)
        est_no_file = max(info_us - file_us, 0.1)
        eps = int(1_000_000 / est_no_file)
        print(f"{size:>6} | {info_us:>11.1f} | {file_us:>9.1f} | {est_no_file:>15.1f} | {eps:>17}")

    print(
        "\nnote: 'file µs' is a Python write_all + flush on a line shaped like\n"
        "the ndjson envelope. The Rust runtime does the same syscalls from\n"
        "Rust, so this is a reasonable proxy for the file-handler cost inside\n"
        "the emit path. 'no-file est' = tn.info - file."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
