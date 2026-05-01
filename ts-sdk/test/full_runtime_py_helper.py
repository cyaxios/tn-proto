"""Python counterpart for the full-runtime interop test.

Usage:
    python full_runtime_py_helper.py info  <yaml> <event> k=v [k=v ...]
    python full_runtime_py_helper.py read  <yaml>

Writes one JSON line per entry on stdout in read mode, same shape as
tn-js read.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Fast-route stdout to binary so \n stays \n on Windows.
_STDOUT = sys.stdout.buffer


def _write(s: str) -> None:
    _STDOUT.write(s.encode("utf-8"))


TN_SDK_PATH = HERE.parents[1] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))


def coerce(v: str) -> object:
    # Cheap coercion for CLI-style k=v values: ints, floats, bools, else
    # string.
    if v.lstrip("-").isdigit():
        return int(v)
    try:
        return float(v)
    except ValueError:
        pass
    lower = v.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    return v


def info() -> int:
    yaml_path = sys.argv[2]
    event_type = sys.argv[3]
    import tn
    tn.init(yaml_path, cipher="btn")
    fields: dict[str, object] = {}
    for kv in sys.argv[4:]:
        k, _, v = kv.partition("=")
        fields[k] = coerce(v)
    tn.info(event_type, **fields)
    return 0


def read() -> int:
    yaml_path = sys.argv[2]
    import tn
    tn.init(yaml_path, cipher="btn")
    for entry in tn.read(verify=False):
        out = {
            "event_type": entry.event_type,
            "sequence": entry.sequence,
            "row_hash": entry.audit.row_hash,
            "fields": dict(entry.fields),
        }
        _write(json.dumps(out) + "\n")
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("usage: full_runtime_py_helper.py <info|read> <yaml> [args]\n")
        return 1
    cmd = sys.argv[1]
    if cmd == "info":
        return info()
    if cmd == "read":
        return read()
    sys.stderr.write(f"unknown command: {cmd}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
