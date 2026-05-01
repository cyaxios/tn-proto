"""Example 8: see your logs as they fly by.

Story
-----
Jamie just installed `tn-protocol` and wants to actually SEE what's
landing in the log without `tail -f`-ing a file. They open a Python
REPL or run a one-shot script and call `tn.info()` a few times. Out of
the box, every event lands as a JSON line on stdout — same shape as
what's persisted to disk — so they can dogfood the SDK in seconds.

What this shows
---------------
  - `tn.init()` enables the stdout handler by default. No flags, no
    extra config.
  - Every emit writes the canonical envelope JSON to stdout AND to
    the file.
  - Opt-out paths (for prod / CI / pytest):
      * `TN_NO_STDOUT=1` env var
      * `tn.init(yaml, stdout=False)` kwarg

Run it
------
    python ex08_stdout.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import tn


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jamie8_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        # Default-on: emits land on stdout AND the file.
        tn.init(yaml_path)
        print("\n# default-on: every emit shows up below as a JSON line", file=sys.stderr)
        tn.info("app.booted", pid=12345)
        tn.info("order.created", order_id="A100", amount=4200, currency="USD")
        tn.warning("auth.retry", attempts=3)
        tn.flush_and_close()

        # Opt-out via kwarg.
        print("\n# stdout=False: silent, file still written", file=sys.stderr)
        tn.init(yaml_path, stdout=False)
        tn.info("silent.event", x=1)
        tn.flush_and_close()
        log_path = ws / ".tn" / "logs" / "tn.ndjson"
        line_count = sum(1 for _ in log_path.read_text(encoding="utf-8").splitlines() if _.strip())
        print(f"# (file still has {line_count} lines)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
