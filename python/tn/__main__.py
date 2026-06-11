"""``python -m tn`` — quick-look at the current ceremony's log.

Auto-discovers an EXISTING ceremony via the standard chain ($TN_YAML →
./tn.yaml → ~/.tn/tn.yaml). Prints each entry as one JSON line per row.

Refuses to mint a fresh ceremony — read paths never auto-create. Run
``python -c "import tn; tn.init()"`` once if you want to scaffold one.

Examples
--------
    python -m tn                  # tn.read() — Entry.model_dump_json per row
    python -m tn --raw            # tn.read(raw=True) — on-disk envelope dicts
    python -m tn --verify skip    # tn.read(verify="skip")
    python -m tn --verify raise   # tn.read(verify="raise")
    TN_YAML=./tn.yaml python -m tn

The opt-out for stdout handler stays the same: ``TN_NO_STDOUT=1``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import tn


def _emit_jsonl(rows) -> int:
    n = 0
    for row in rows:
        if hasattr(row, "model_dump_json"):
            sys.stdout.write(row.model_dump_json() + "\n")
        else:
            # raw=True path — row is a dict.
            sys.stdout.write(json.dumps(row, separators=(",", ":")) + "\n")
        n += 1
    sys.stdout.flush()
    return n


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tn",
        description="Read the current TN ceremony's log to stdout.",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="emit on-disk envelope dicts (raw=True) instead of Entry rows",
    )
    parser.add_argument(
        "--verify", choices=("skip", "raise"), default=None,
        help="run integrity checks; 'skip' drops invalid rows, 'raise' aborts",
    )
    args = parser.parse_args(argv)

    # Quiet stdout handler so the read output isn't interleaved with init
    # noise. Caller can override.
    os.environ.setdefault("TN_NO_STDOUT", "1")

    try:
        n = _emit_jsonl(tn.read(raw=args.raw, verify=args.verify or False))
    except RuntimeError as e:
        print(f"tn: {e}", file=sys.stderr)
        return 1

    print(f"# {n} entries", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
