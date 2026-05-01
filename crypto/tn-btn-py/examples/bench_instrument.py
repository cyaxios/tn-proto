"""Instrumented copy of tn.info() — measures each phase in µs per event.

Each phase of the pipeline is wrapped in a perf_counter pair and
totals are accumulated across N events. Output: a breakdown showing
exactly where per-event time goes, for one cipher at a time.

The structure mirrors TNRuntime.emit() in tn/logger.py (Apr 2026
HEAD). If that changes, re-derive this from the current emit().

Run from `tn-protocol/python/`:
    /c/codex/content_platform/.venv/Scripts/python.exe \\
        ../crypto/btn-py/examples/bench_instrument.py --cipher=btn
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_TN_PY = Path(__file__).resolve().parents[3] / "python"
if str(_TN_PY) not in sys.path:
    sys.path.insert(0, str(_TN_PY))


def make_event(size: int, seq: int) -> dict:
    base = {"amount": 4200 + seq, "email": "alice@example.com",
            "order_id": f"A{seq:09d}"}
    base_len = len(json.dumps(base, separators=(",", ":")))
    overhead = base_len + len(',"blob":""')
    pad = max(0, size - overhead)
    base["blob"] = "x" * pad
    return base


def bench(cipher_name: str, events: int, size: int):
    import tn
    from tn.canonical import canonical_bytes
    from tn.chain import compute_row_hash
    from tn.indexing import index_token
    from tn.signing import signature_b64

    with tempfile.TemporaryDirectory() as tmp:
        yaml = Path(tmp) / "tn.yaml"
        log = Path(tmp) / "logs" / "tn.ndjson"
        tn.init(yaml, log_path=log, pool_size=4, cipher=cipher_name)

        # Grab internals once — these are hot-loop constants.
        from tn.logger import _runtime
        rt = _runtime
        cfg = rt.cfg
        chain = rt.chain
        handlers = rt.handlers

        public_keys = set(cfg.public_fields)
        # field_to_group is a dict; `default` is the fallback group name.

        totals = defaultdict(float)

        t_start = time.perf_counter()
        for i in range(events):
            fields = make_event(size, i)
            event_type = "bench.event"
            level_norm = "info"

            # ---- 1 + 2: classify --------------------------------------
            t = time.perf_counter()
            public_out = {}
            per_group: dict[str, dict] = {}
            merged = dict(fields)  # no context to merge here
            for k, v in merged.items():
                if k in public_keys:
                    public_out[k] = v
                else:
                    gname = cfg.field_to_group.get(k, "default")
                    if gname not in cfg.groups:
                        gname = "default"
                    per_group.setdefault(gname, {})[k] = v
            totals["1_classify"] += time.perf_counter() - t

            # ---- 3: HMAC index tokens ---------------------------------
            group_payloads: dict[str, dict] = {}
            t = time.perf_counter()
            for gname, plain in per_group.items():
                gcfg = cfg.groups[gname]
                fh = {
                    fname: index_token(gcfg.index_key, fname, fval)
                    for fname, fval in plain.items()
                }
                group_payloads[gname] = {"field_hashes": fh,
                                         "_plain": plain,
                                         "_gcfg": gcfg}
            totals["3_hmac_tokens"] += time.perf_counter() - t

            # ---- 4a: canonical serialize body --------------------------
            t = time.perf_counter()
            pt_bytes_map = {}
            for gname, gp in group_payloads.items():
                pt_bytes_map[gname] = canonical_bytes(gp["_plain"])
            totals["4a_canonical_body"] += time.perf_counter() - t

            # ---- 4b: cipher encrypt -----------------------------------
            t = time.perf_counter()
            for gname, gp in group_payloads.items():
                gp["ciphertext"] = gp["_gcfg"].cipher.encrypt(pt_bytes_map[gname])
            totals["4b_cipher_encrypt"] += time.perf_counter() - t

            # ---- 5: chain advance -------------------------------------
            t = time.perf_counter()
            seq, prev_hash = chain.advance(event_type)
            timestamp = datetime.now(timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z")
            event_id = str(uuid.uuid4())
            totals["5_chain_advance"] += time.perf_counter() - t

            # ---- 6: row_hash ------------------------------------------
            t = time.perf_counter()
            # Build the groups-for-row-hash shape
            gph = {
                name: {"ciphertext": gp["ciphertext"],
                       "field_hashes": gp["field_hashes"]}
                for name, gp in group_payloads.items()
            }
            row_hash = compute_row_hash(
                did=cfg.device.did,
                timestamp=timestamp,
                event_id=event_id,
                event_type=event_type,
                level=level_norm,
                prev_hash=prev_hash,
                public_fields=public_out,
                groups=gph,
            )
            totals["6_row_hash"] += time.perf_counter() - t

            # ---- 7: sign ----------------------------------------------
            t = time.perf_counter()
            sig = cfg.device.sign(row_hash.encode("ascii"))
            sig_b64 = signature_b64(sig)
            totals["7_ed25519_sign"] += time.perf_counter() - t

            # ---- 8: envelope build + base64 of ciphertext --------------
            t = time.perf_counter()
            envelope = {
                "did": cfg.device.did,
                "timestamp": timestamp,
                "event_id": event_id,
                "event_type": event_type,
                "level": level_norm,
                "sequence": seq,
                "prev_hash": prev_hash,
                "row_hash": row_hash,
                "signature": sig_b64,
            }
            for k, v in public_out.items():
                envelope.setdefault(k, v)
            for gname, gp in group_payloads.items():
                envelope[gname] = {
                    "ciphertext": base64.b64encode(gp["ciphertext"]).decode("ascii"),
                    "field_hashes": gp["field_hashes"],
                }
            totals["8_envelope_build"] += time.perf_counter() - t

            # ---- 9: json.dumps envelope -------------------------------
            t = time.perf_counter()
            line = json.dumps(envelope, separators=(",", ":")) + "\n"
            raw = line.encode("utf-8")
            totals["9_json_dump"] += time.perf_counter() - t

            # ---- 10: fan out to handlers (file write) -----------------
            t = time.perf_counter()
            for h in handlers:
                if h.accepts(envelope):
                    h.emit(envelope, raw)
            chain.commit(event_type, row_hash)
            totals["10_write"] += time.perf_counter() - t

        total_elapsed = time.perf_counter() - t_start
        tn.flush_and_close()

        # Report -----------------------------------------------------
        print(f"=== {cipher_name.upper()}: {events} events, {size}B payload ===")
        print(f"  Total:          {total_elapsed*1e3:>8.1f} ms  "
              f"({events/total_elapsed:>8.0f}/s, {total_elapsed/events*1e6:>6.1f} µs/event)")
        print()
        sum_phases = sum(totals.values())
        other = total_elapsed - sum_phases
        print(f"  Phase               µs/event   % of total")
        for name in sorted(totals):
            us = totals[name] / events * 1e6
            pct = (totals[name] / total_elapsed) * 100
            print(f"  {name:<20} {us:>8.2f}   {pct:>5.1f}%")
        print(f"  {'(loop overhead)':<20} {other/events*1e6:>8.2f}   "
              f"{(other/total_elapsed)*100:>5.1f}%")
        print()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cipher", choices=["bgw", "jwe", "btn", "all"], default="all")
    p.add_argument("--events", type=int, default=2000)
    p.add_argument("--size", type=int, default=4096)
    args = p.parse_args()

    print(f"Instrumented tn.info() pipeline breakdown")
    print(f"  Python:  {sys.version.split()[0]}  Platform: {sys.platform}")
    print(f"  Payload: {args.size}B  Events: {args.events}  N=1 recipient")
    print("-" * 70)
    if args.cipher == "all":
        for c in ["bgw", "jwe", "btn"]:
            bench(c, args.events, args.size)
    else:
        bench(args.cipher, args.events, args.size)


if __name__ == "__main__":
    main()
