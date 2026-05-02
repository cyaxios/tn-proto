"""tn.watch — emit decoded TN log entries as JSONL to stdout.

TN's only job is to decrypt and verify. Formatting, coloring, filtering,
searching, paging — that's what existing log tools already do extremely
well. So `tn.watch` is deliberately small: it opens your ceremony, tails
the log, and writes one flat JSON object per entry to stdout. Pipe that
into whichever tailer you already love.

Usage:
    python -m tn.watch ./alice/tn.yaml                 # follow, decoded JSONL
    python -m tn.watch ./alice/tn.yaml --once          # dump and exit
    python -m tn.watch ./alice/tn.yaml --log PATH      # custom log path
    python -m tn.watch ./alice/tn.yaml --since SEQ_OR_ISO_OR_start_OR_now

Pipe into any JSON-aware tailer, e.g.:
    python -m tn.watch ./alice/tn.yaml | jq -C .
    python -m tn.watch ./alice/tn.yaml | humanlog
    python -m tn.watch ./alice/tn.yaml | fblog
    python -m tn.watch ./alice/tn.yaml | lnav

Each emitted object is a flat dict matching `tn.read()` / `tn.watch()`.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path


async def _async_main(args) -> int:
    import tn
    tn.init(Path(args.yaml).resolve())
    try:
        # Coerce --since: pure-digit value → int (sequence); otherwise
        # leave as string ("start", "now", or ISO timestamp).
        since: str | int = args.since
        if isinstance(since, str) and since.isdigit():
            since = int(since)

        if args.once:
            cfg = tn.current_config()
            log_path = Path(args.log).resolve() if args.log else cfg.resolve_log_path()
            for entry in tn.read(log_path, cfg, verify=True, all_runs=True):
                # Filter by --since for snapshot mode.
                if since == "start":
                    pass
                elif since == "now":
                    continue   # --once + --since now = no-op
                elif isinstance(since, int):
                    if entry.get("sequence", 0) < since:
                        continue
                else:
                    if entry.get("timestamp", "") < since:
                        continue
                sys.stdout.write(json.dumps(entry, default=str) + "\n")
                sys.stdout.flush()
            return 0

        # Tail forever (until SIGINT).
        async for entry in tn.watch(
            since=since,
            verify=True,
            poll_interval=args.interval,
            log_path=Path(args.log).resolve() if args.log else None,
        ):
            sys.stdout.write(json.dumps(entry, default=str) + "\n")
            sys.stdout.flush()
        return 0
    finally:
        tn.flush_and_close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m tn.watch",
        description=(
            "Decrypt and stream a TN log as JSONL to stdout. "
            "Pipe into jq, humanlog, fblog, lnav, or any JSONL-aware tool."
        ),
    )
    ap.add_argument("yaml", help="Path to tn.yaml (your ceremony)")
    ap.add_argument(
        "--log",
        help="Path to the ndjson log (default: cfg.resolve_log_path())",
    )
    ap.add_argument(
        "--once",
        action="store_true",
        help="Print current log contents and exit (do not follow)",
    )
    ap.add_argument(
        "--since",
        default="now",
        help="Starting point: 'start' (default for --once), 'now' (default for follow), a sequence number, or an ISO-8601 timestamp",
    )
    ap.add_argument(
        "--interval",
        type=float,
        default=0.3,
        help="Poll interval in seconds when following (default: 0.3)",
    )
    args = ap.parse_args(argv)

    # UTF-8 stdout so non-ASCII data round-trips correctly.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

    yaml_path = Path(args.yaml).resolve()
    if not yaml_path.exists():
        print(f"tn.watch: {yaml_path} does not exist", file=sys.stderr)
        return 1

    try:
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
