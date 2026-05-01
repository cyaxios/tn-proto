"""Python counterpart to tn-js. Same subcommands, same stdin/stdout
shapes, so interop can be proven by piping one into the other.

Uses the pure-Python `tn` module, not the Rust-backed tn_core. That's
the whole point: tn-js (WASM) must produce bytes that the reference
Python implementation accepts, and vice versa. If a subcommand here
drifts from the tn-js behavior, the bug is on whichever side diverged.

Usage:
    python tn_py_helper.py <seal|verify|canonical>
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

# Windows translates \n to \r\n in text-mode stdout, which breaks byte
# comparisons against tn-js output. Write through the raw buffer so \n
# stays \n on every platform.
_STDOUT = sys.stdout.buffer


def _write(s: str) -> None:
    _STDOUT.write(s.encode("utf-8"))


HERE = Path(__file__).resolve().parent
TN_SDK_PATH = HERE.parents[1] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))

from tn.canonical import canonical_bytes  # noqa: E402
from tn.chain import compute_row_hash  # noqa: E402
from tn.signing import DeviceKey, signature_b64, signature_from_b64  # noqa: E402


def seal() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        inp = json.loads(line)
        seed = base64.b64decode(inp["seed_b64"])
        dk = DeviceKey.from_private_bytes(seed)
        rh = compute_row_hash(
            did=dk.did,
            timestamp=inp["timestamp"],
            event_id=inp["event_id"],
            event_type=inp["event_type"],
            level=inp["level"],
            prev_hash=inp["prev_hash"],
            public_fields=inp.get("public_fields", {}),
            groups={},
        )
        sig = dk.sign(rh.encode("ascii"))
        env = {
            "did": dk.did,
            "timestamp": inp["timestamp"],
            "event_id": inp["event_id"],
            "event_type": inp["event_type"],
            "level": inp["level"],
            "sequence": inp["sequence"],
            "prev_hash": inp["prev_hash"],
            "row_hash": rh,
            "signature": signature_b64(sig),
        }
        for k, v in inp.get("public_fields", {}).items():
            env.setdefault(k, v)
        _write(json.dumps(env, separators=(",", ":")) + "\n")
    return 0


def verify() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        env = json.loads(line)
        try:
            required = ["did", "timestamp", "event_id", "event_type",
                        "level", "sequence", "prev_hash", "row_hash",
                        "signature"]
            for k in required:
                if k not in env:
                    raise ValueError(f"missing {k}")

            public_fields = {}
            for k, v in env.items():
                if k in required:
                    continue
                if isinstance(v, dict) and "ciphertext" in v:
                    raise ValueError(f"group payload {k} present, public-only verify")
                public_fields[k] = v

            recomputed = compute_row_hash(
                did=env["did"],
                timestamp=env["timestamp"],
                event_id=env["event_id"],
                event_type=env["event_type"],
                level=env["level"],
                prev_hash=env["prev_hash"],
                public_fields=public_fields,
                groups={},
            )
            if recomputed != env["row_hash"]:
                raise ValueError(f"row_hash mismatch: expected {recomputed}, got {env['row_hash']}")

            sig = signature_from_b64(env["signature"])
            if not DeviceKey.verify(env["did"], env["row_hash"].encode("ascii"), sig):
                raise ValueError("bad signature")

            out = {
                "ok": True,
                "did": env["did"],
                "event_type": env["event_type"],
                "event_id": env["event_id"],
                "row_hash": env["row_hash"],
                "sequence": env["sequence"],
            }
            _write(json.dumps(out) + "\n")
        except Exception as exc:
            _write(json.dumps({"ok": False, "reason": str(exc)}) + "\n")
    return 0


def canonical() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        _write(canonical_bytes(obj).decode("utf-8") + "\n")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("tn_py_helper.py <seal|verify|canonical>\n")
        return 1
    cmd = sys.argv[1]
    if cmd == "seal":
        return seal()
    if cmd == "verify":
        return verify()
    if cmd == "canonical":
        return canonical()
    sys.stderr.write(f"unknown command: {cmd}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
