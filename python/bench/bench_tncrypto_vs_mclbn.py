"""Head-to-head: new tncrypto (C lib via ctypes) vs existing mclbn256 BGW.

Uses the existing 10k-style event generator at
benchmarks/jwe_vs_tn/workload.py. Both paths encrypt and decrypt the same
events with pool_size=4, matching the PRD's "pool with full-set authorized"
encryption model.

Run:
    python3 bench_tncrypto_vs_mclbn.py --events 10000 --pool 4

From WSL with the crypto build present at ../../crypto/build/.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
# HERE = .../tn-protocol/python/bench ; repo root is 3 up (bench, python, tn-protocol).
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))  # for `benchmarks.jwe_vs_tn.*`
sys.path.insert(0, str(HERE.parents[0]))  # for our `tn` package (tn-protocol/python)

from benchmarks.jwe_vs_tn.workload import materialize

import tn


def _ser_events(events):
    """Canonical JSON bytes for each event's data dict (deterministic,
    compact, what a real tn.log call would feed into encrypt)."""
    return [
        json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
        for _, _, data in events
    ]


def _stats(ms):
    return {
        "n": len(ms),
        "mean": statistics.mean(ms),
        "median": statistics.median(ms),
        "p95": sorted(ms)[int(len(ms) * 0.95)] if len(ms) >= 20 else max(ms),
        "p99": sorted(ms)[int(len(ms) * 0.99)] if len(ms) >= 100 else max(ms),
        "min": min(ms),
        "max": max(ms),
    }


# ---------------- tncrypto (new C lib) ------------------------------------


def bench_tncrypto(payloads, pool: int):
    t0 = time.perf_counter()
    ctx = tn.BGWContext.setup(pool)
    setup_ms = (time.perf_counter() - t0) * 1000
    keys = [ctx.keygen(i) for i in range(pool)]

    # Encrypt
    enc_ms_each = []
    cts = []
    t_total0 = time.perf_counter()
    for p in payloads:
        t0 = time.perf_counter()
        ct = ctx.encrypt(p)
        enc_ms_each.append((time.perf_counter() - t0) * 1000)
        cts.append(ct)
    enc_total = time.perf_counter() - t_total0

    # Serialized size on disk
    serialized_bytes = sum(len(c.to_bytes()) for c in cts)

    # Decrypt (single slot - slot 0)
    dec_ms_each = []
    key = keys[0]
    t_total0 = time.perf_counter()
    matched = 0
    for i, ct in enumerate(cts):
        t0 = time.perf_counter()
        pt = key.decrypt(ct)
        dec_ms_each.append((time.perf_counter() - t0) * 1000)
        if pt == payloads[i]:
            matched += 1
    dec_total = time.perf_counter() - t_total0

    return {
        "setup_ms": setup_ms,
        "enc_total_s": enc_total,
        "dec_total_s": dec_total,
        "enc_per_event_ms": _stats(enc_ms_each),
        "dec_per_event_ms": _stats(dec_ms_each),
        "enc_ev_per_s": len(payloads) / enc_total,
        "dec_ev_per_s": len(payloads) / dec_total,
        "bytes_per_event": serialized_bytes / len(payloads),
        "matched": matched,
    }


# ---------------- mclbn256 reference (existing Python) --------------------


def bench_mclbn(payloads, pool: int):
    sys.path.insert(0, str(REPO / "benchmarks"))
    from jwe_vs_tn.bgw_client_mcl import BGWInstance  # type: ignore

    t0 = time.perf_counter()
    inst = BGWInstance.setup(n=pool)
    setup_ms = (time.perf_counter() - t0) * 1000
    S = list(range(1, pool + 1))
    slot_keys = {u: inst.issue_key(u) for u in S}

    enc_ms_each = []
    blobs = []
    t_total0 = time.perf_counter()
    for p in payloads:
        t0 = time.perf_counter()
        blob = inst.encrypt_body(S, p)
        enc_ms_each.append((time.perf_counter() - t0) * 1000)
        blobs.append(blob)
    enc_total = time.perf_counter() - t_total0

    # crude size: serialize the raw bytes fields
    ser_bytes = sum(len(b["C0"]) + len(b["C1"]) + len(b["iv"]) + len(b["ct"]) for b in blobs)

    dec_ms_each = []
    u = 1
    d_u = slot_keys[u]
    t_total0 = time.perf_counter()
    matched = 0
    for i, blob in enumerate(blobs):
        t0 = time.perf_counter()
        pt = inst.decrypt_body(u, S, d_u, blob)
        dec_ms_each.append((time.perf_counter() - t0) * 1000)
        if pt == payloads[i]:
            matched += 1
    dec_total = time.perf_counter() - t_total0

    return {
        "setup_ms": setup_ms,
        "enc_total_s": enc_total,
        "dec_total_s": dec_total,
        "enc_per_event_ms": _stats(enc_ms_each),
        "dec_per_event_ms": _stats(dec_ms_each),
        "enc_ev_per_s": len(payloads) / enc_total,
        "dec_ev_per_s": len(payloads) / dec_total,
        "bytes_per_event": ser_bytes / len(payloads),
        "matched": matched,
    }


# ------------------------------------------------------------------------


def fmt(r):
    return (
        f"  setup:  {r['setup_ms']:7.2f} ms\n"
        f"  enc:    {r['enc_total_s'] * 1000:8.1f} ms total   "
        f"{r['enc_per_event_ms']['mean']:6.3f} ms/ev mean "
        f"p95={r['enc_per_event_ms']['p95']:6.3f}  "
        f"p99={r['enc_per_event_ms']['p99']:6.3f}  "
        f"({r['enc_ev_per_s']:7.0f} ev/s)\n"
        f"  dec:    {r['dec_total_s'] * 1000:8.1f} ms total   "
        f"{r['dec_per_event_ms']['mean']:6.3f} ms/ev mean "
        f"p95={r['dec_per_event_ms']['p95']:6.3f}  "
        f"p99={r['dec_per_event_ms']['p99']:6.3f}  "
        f"({r['dec_ev_per_s']:7.0f} ev/s)\n"
        f"  bytes/event: {r['bytes_per_event']:6.1f}      "
        f"matched: {r['matched']}\n"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=10000)
    ap.add_argument("--pool", type=int, default=4)
    ap.add_argument(
        "--skip-mclbn",
        action="store_true",
        help="skip reference comparison (mclbn256 not installed)",
    )
    args = ap.parse_args()

    print(f"generating {args.events} events ...")
    events = materialize(args.events)
    payloads = _ser_events(events)
    total_bytes = sum(len(p) for p in payloads)
    print(
        f"  {len(payloads)} payloads, {total_bytes / 1024:.1f} KiB total "
        f"({total_bytes / len(payloads):.0f} bytes/event avg)\n"
    )

    print(f"=== tncrypto (C lib via ctypes, pool={args.pool}) ===")
    r_tn = bench_tncrypto(payloads, args.pool)
    print(fmt(r_tn))

    if not args.skip_mclbn:
        try:
            print(f"=== mclbn256 (Python ref, pool={args.pool}) ===")
            r_ref = bench_mclbn(payloads, args.pool)
            print(fmt(r_ref))

            print("=== speedup (tncrypto / mclbn256 ref) ===")
            print(f"  enc/s:   {r_tn['enc_ev_per_s'] / r_ref['enc_ev_per_s']:.2f}x")
            print(f"  dec/s:   {r_tn['dec_ev_per_s'] / r_ref['dec_ev_per_s']:.2f}x")
            print(f"  bytes:   {r_tn['bytes_per_event'] / r_ref['bytes_per_event']:.2f}x")
        except ImportError as e:
            print(f"(skipping mclbn256 comparison: {e})")


if __name__ == "__main__":
    main()
