"""``python -m tn`` — quick-look at the current ceremony's log.

Auto-discovers an EXISTING ceremony via the standard chain ($TN_YAML →
./tn.yaml → ~/.tn/tn.yaml). Prints each entry as one JSON line per row
(the same canonical envelope the file/stdout handlers produce).

Refuses to mint a fresh ceremony — read paths never auto-create. Run
``python -c "import tn; tn.init()"`` once if you want to scaffold one.

Examples
--------
    python -m tn                # bare iteration of tn.read() across the live log
    python -m tn --raw          # envelope+plaintext+valid (audit shape)
    python -m tn --secure       # secure_read (skip mode)
    python -m tn --secure raise # secure_read on_invalid='raise'
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
        # tn.read() returns flat dicts; tn.read_raw() returns
        # {envelope, plaintext, valid}. Either serializes cleanly.
        sys.stdout.write(json.dumps(row, separators=(",", ":")) + "\n")
        n += 1
    sys.stdout.flush()
    return n


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tn",
        description="Read the current TN ceremony's log to stdout.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--raw", action="store_true",
                      help="emit raw {envelope, plaintext, valid} entries")
    mode.add_argument("--secure", nargs="?", const="skip",
                      choices=("skip", "raise", "forensic"),
                      help="use tn.secure_read with the given on_invalid mode")
    args = parser.parse_args(argv)

    # Quiet stdout handler so the read output isn't interleaved with init
    # noise. Caller can override.
    os.environ.setdefault("TN_NO_STDOUT", "1")

    try:
        if args.raw:
            n = _emit_jsonl(tn.read_raw())
        elif args.secure:
            n = _emit_jsonl(tn.secure_read(on_invalid=args.secure))
        else:
            n = _emit_jsonl(tn.read())
    except RuntimeError as e:
        print(f"tn: {e}", file=sys.stderr)
        return 1

    print(f"# {n} entries", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
