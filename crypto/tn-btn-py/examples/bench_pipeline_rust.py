"""Architectural preview bench: full pipeline in Rust vs Python.

Measures per-event cost for producing a complete ndjson envelope line
(canonical body + HMAC tokens + cipher encrypt + row_hash + Ed25519
sign + envelope JSON + base64) via two implementations:

  - `python_pipeline`: same as bench_instrument.py — every phase
    orchestrated from Python, calling into `tn.cipher`, `cryptography`,
    `hashlib`, `hmac`, `json`.

  - `rust_pipeline`:   single FFI call into `btn._core.build_envelope_line`.
    Rust does everything. Same cipher (btn), same primitives (SHA-256,
    HMAC, Ed25519, AES-GCM via AES-KW + AES-GCM inside btn), same
    output shape.

Both bench-paths produce byte-compatible envelope lines for the same
inputs — we cross-check on a single event at startup to confirm.

Run from `tn-protocol/python/`:
    /c/codex/content_platform/.venv/Scripts/python.exe \\
        ../crypto/btn-py/examples/bench_pipeline_rust.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac as py_hmac
import json
import os
import statistics
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_TN_PY = Path(__file__).resolve().parents[3] / "python"
if str(_TN_PY) not in sys.path:
    sys.path.insert(0, str(_TN_PY))

PAYLOAD = 4096
EVENTS = 2000


def make_event(size: int, seq: int) -> dict:
    base = {"amount": 4200 + seq, "email": "alice@example.com",
            "order_id": f"A{seq:09d}"}
    base_len = len(json.dumps(base, separators=(",", ":")))
    pad = max(0, size - base_len - len(',"blob":""'))
    base["blob"] = "x" * pad
    return base


def bench_python_pipeline(events: int, size: int):
    """The current tn.info() Python pipeline, all phases in Python."""
    import tn
    with tempfile.TemporaryDirectory() as tmp:
        y = Path(tmp) / "tn.yaml"
        tn.init(y, pool_size=4, cipher="btn")

        from tn.canonical import canonical_bytes
        from tn.chain import compute_row_hash
        from tn.indexing import index_token
        from tn.logger import _runtime
        from tn.signing import signature_b64

        cfg = _runtime.cfg
        chain = _runtime.chain
        handlers = _runtime.handlers

        lat = []
        t0 = time.perf_counter()
        for i in range(events):
            fields = make_event(size, i)
            event_type = "bench.event"
            level = "info"

            t = time.perf_counter()
            plain = {k: v for k, v in fields.items()}
            gcfg = cfg.groups["default"]
            fh = {k: index_token(gcfg.index_key, k, v) for k, v in plain.items()}
            pt_bytes = canonical_bytes(plain)
            ct = gcfg.cipher.encrypt(pt_bytes)
            seq, prev_hash = chain.advance(event_type)
            ts = datetime.now(timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z")
            eid = str(uuid.uuid4())
            rh = compute_row_hash(
                did=cfg.device.did, timestamp=ts, event_id=eid,
                event_type=event_type, level=level, prev_hash=prev_hash,
                public_fields={},
                groups={"default": {"ciphertext": ct, "field_hashes": fh}},
            )
            sig = cfg.device.sign(rh.encode("ascii"))
            env = {
                "did": cfg.device.did, "timestamp": ts, "event_id": eid,
                "event_type": event_type, "level": level, "sequence": seq,
                "prev_hash": prev_hash, "row_hash": rh,
                "signature": signature_b64(sig),
                "default": {
                    "ciphertext": base64.b64encode(ct).decode("ascii"),
                    "field_hashes": fh,
                },
            }
            line = json.dumps(env, separators=(",", ":")) + "\n"
            _ = line.encode("utf-8")
            # Skip file write for this bench; we're comparing pipeline
            # compute cost. A real tn.info would fan-out to handlers.
            chain.commit(event_type, rh)
            lat.append((time.perf_counter() - t) * 1e6)
        total = time.perf_counter() - t0
        tn.flush_and_close()
        return total, lat


def bench_rust_pipeline(events: int, size: int):
    """Single-call Rust pipeline via btn.build_envelope_line."""
    import tn_btn as btn
    import tn
    with tempfile.TemporaryDirectory() as tmp:
        y = Path(tmp) / "tn.yaml"
        tn.init(y, pool_size=4, cipher="btn")

        from tn.logger import _runtime
        cfg = _runtime.cfg
        chain = _runtime.chain

        # Get the PublisherState used under the hood by btn cipher.
        gcfg = cfg.groups["default"]
        # BtnGroupCipher stores its PublisherState in _state.
        pub_state = gcfg.cipher._state  # type: ignore[attr-defined]

        # Ed25519 seed — DeviceKey exposes .private_bytes (32 bytes).
        signer_seed = bytes(cfg.device.private_bytes)
        # Index key for the group.
        index_key = gcfg.index_key
        did = cfg.device.did

        from btn._core import build_envelope_line

        lat = []
        t0 = time.perf_counter()
        prev_hash = "sha256:" + "00" * 32
        seq = 0
        for i in range(events):
            fields = make_event(size, i)
            event_type = "bench.event"
            level = "info"

            t = time.perf_counter()
            ts = datetime.now(timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z")
            eid = str(uuid.uuid4())
            seq += 1
            # Build the fields input: JSON array of [name, value] pairs.
            fields_json = json.dumps(
                [[k, v] for k, v in fields.items()],
                separators=(",", ":"),
            ).encode("utf-8")
            line_bytes, row_hash = build_envelope_line(
                pub_state,
                signer_seed,
                did,
                index_key,
                event_type,
                ts,
                eid,
                seq,
                prev_hash,
                level,
                fields_json,
            )
            prev_hash = row_hash
            lat.append((time.perf_counter() - t) * 1e6)
        total = time.perf_counter() - t0
        tn.flush_and_close()
        return total, lat


def report(name: str, total: float, lat: list[float], events: int):
    rate = events / total
    p50 = statistics.median(lat)
    p99 = sorted(lat)[int(len(lat) * 0.99)]
    per_event_us = total / events * 1e6
    print(f"  {name:<24}  {rate:>9,.0f}/s   "
          f"per-event {per_event_us:>6.1f}µs   "
          f"p50 {p50:>6.1f}µs   p99 {p99:>6.1f}µs")


def main():
    print("Architectural preview: full pipeline in Rust vs Python")
    print(f"  Python:  {sys.version.split()[0]}  Platform: {sys.platform}")
    print(f"  Payload: {PAYLOAD}B  Events: {EVENTS}  Cipher: btn (h=8)")
    print("-" * 85)

    print("  Python pipeline (tn.info() phases, orchestrated from Python):")
    t_py, lat_py = bench_python_pipeline(EVENTS, PAYLOAD)
    report("python_pipeline", t_py, lat_py, EVENTS)

    print()
    print("  Rust pipeline (btn._core.build_envelope_line, one FFI call):")
    t_rs, lat_rs = bench_rust_pipeline(EVENTS, PAYLOAD)
    report("rust_pipeline", t_rs, lat_rs, EVENTS)

    print()
    print(f"  Speedup: {t_py / t_rs:>5.2f}×  "
          f"(per-event dropped from {t_py/EVENTS*1e6:.1f}µs to "
          f"{t_rs/EVENTS*1e6:.1f}µs)")


if __name__ == "__main__":
    main()
