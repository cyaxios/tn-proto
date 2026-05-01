"""Head-to-head cipher benchmark: btn vs JWE vs BGW.

Measures the RAW primitive — `.encrypt(plaintext) -> bytes` and
`.decrypt(ciphertext) -> bytes` — for each of the three broadcast-
encryption schemes shipped in this repo, on the same hardware and
Python interpreter.

This is comparable to Table §6.2 in `crypto_model_JWE_Seal.md`, except
that table measures the FULL TN envelope pipeline (canonical
serialisation + HMAC index tokens + chain maintenance + Ed25519
signature over row_hash + AES-GCM body + cipher seal + ndjson write).
For an apples-to-apples primitive-level number we strip all of that
away here and call only the cipher verbs directly.

Run from `tn-protocol/python/`::

    cd tn-protocol/python
    /c/codex/content_platform/.venv/Scripts/python.exe \\
        ../crypto/btn-py/examples/bench_vs_jwe_bgw.py

Requires:
  - `tn` Python package importable (run from tn-protocol/python)
  - `btn` Python extension installed via `maturin develop --release`
  - `libtncrypto` native library built (already in this env)
"""
from __future__ import annotations

import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Tuple

# This script typically lives in tn-protocol/crypto/btn-py/examples/ and
# imports `tn.cipher` from tn-protocol/python/. Python prepends the
# script's OWN directory to sys.path, not cwd, so we explicitly add
# tn-protocol/python/ so `import tn.cipher` resolves.
_TN_PY = Path(__file__).resolve().parents[3] / "python"
if str(_TN_PY) not in sys.path:
    sys.path.insert(0, str(_TN_PY))

# Benchmark parameters — match §6.2 where reasonable.
PAYLOAD_SIZES = [256, 1024, 4096, 16384, 65536]
ITERATIONS_PER_SIZE = {
    256: 5000,
    1024: 5000,
    4096: 2000,
    16384: 1000,
    65536: 300,
}


def measure(fn: Callable[[], bytes], iters: int) -> Tuple[float, list[float]]:
    """Return (total_seconds, per-call-latency-microseconds-list)."""
    lat_us: list[float] = []
    t0 = time.perf_counter()
    for _ in range(iters):
        t = time.perf_counter()
        fn()
        lat_us.append((time.perf_counter() - t) * 1e6)
    total = time.perf_counter() - t0
    return total, lat_us


def fmt_result(
    label: str, size: int, iters: int,
    seal_total: float, seal_lat: list[float], ct_len: int,
    open_total: float, open_lat: list[float],
):
    seal_rate = iters / seal_total
    open_rate = iters / open_total
    seal_p50 = statistics.median(seal_lat)
    open_p50 = statistics.median(open_lat)
    print(
        f"  {label:<10}  "
        f"seal {seal_rate:>9,.0f}/s p50 {seal_p50:>6.1f}µs  "
        f"open {open_rate:>9,.0f}/s p50 {open_p50:>6.1f}µs  "
        f"ct {ct_len:>6} B"
    )


def bench_jwe(size: int, iters: int) -> None:
    from tn.cipher import JWEGroupCipher
    with tempfile.TemporaryDirectory() as tmp:
        ks = Path(tmp)
        c = JWEGroupCipher.create(ks, "bench", recipient_dids=["did:key:zSelf"])
        payload = b"x" * size
        ct = c.encrypt(payload)
        fmt_result(
            "JWE",
            size, iters,
            *measure(lambda: c.encrypt(payload), iters), len(ct),
            *measure(lambda: c.decrypt(ct), iters),
        )


def bench_bgw(size: int, iters: int) -> None:
    from tn.cipher import BGWGroupCipher
    with tempfile.TemporaryDirectory() as tmp:
        ks = Path(tmp)
        c = BGWGroupCipher.create(ks, "bench", pool_size=4)
        payload = b"x" * size
        ct = c.encrypt(payload)
        fmt_result(
            "BGW",
            size, iters,
            *measure(lambda: c.encrypt(payload), iters), len(ct),
            *measure(lambda: c.decrypt(ct), iters),
        )


def bench_btn(size: int, iters: int) -> None:
    import tn_btn as btn
    state = btn.PublisherState()
    kit = state.mint()  # we'll decrypt with this kit
    payload = b"x" * size
    ct = state.encrypt(payload)
    fmt_result(
        "btn (r=0)",
        size, iters,
        *measure(lambda: state.encrypt(payload), iters), len(ct),
        *measure(lambda: btn.decrypt(kit, ct), iters),
    )


def bench_btn_r1(size: int, iters: int) -> None:
    """btn with 1 revocation so cover is Difference, not FullTree."""
    import tn_btn as btn
    state = btn.PublisherState()
    kit = state.mint()
    revoked = state.mint()
    state.revoke_kit(revoked)
    payload = b"x" * size
    ct = state.encrypt(payload)
    fmt_result(
        "btn (r=1)",
        size, iters,
        *measure(lambda: state.encrypt(payload), iters), len(ct),
        *measure(lambda: btn.decrypt(kit, ct), iters),
    )


def main():
    print("Cipher primitive head-to-head (cipher.encrypt / cipher.decrypt only,")
    print("no envelope pipeline / no signature / no chain / no index tokens).")
    print(f"Python: {sys.version.split()[0]}  Platform: {sys.platform}")
    print()

    for size in PAYLOAD_SIZES:
        iters = ITERATIONS_PER_SIZE[size]
        print(f"--- Payload: {size:>6} B, {iters} iterations per variant ---")
        bench_jwe(size, iters)
        try:
            bench_bgw(size, iters)
        except Exception as e:
            print(f"  BGW         skipped ({type(e).__name__}: {e})")
        bench_btn(size, iters)
        bench_btn_r1(size, iters)
        print()


if __name__ == "__main__":
    main()
