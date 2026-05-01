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

Pipe into any JSON-aware tailer, e.g.:
    python -m tn.watch ./alice/tn.yaml | jq -C .
    python -m tn.watch ./alice/tn.yaml | humanlog
    python -m tn.watch ./alice/tn.yaml | fblog
    python -m tn.watch ./alice/tn.yaml | lnav

Each emitted object has this shape (matches tn.read() Entry objects):
    {
        "timestamp":  "2026-04-21T20:20:55.689799Z",
        "level":      "INFO",
        "event_type": "order.created",
        "sequence":   42,
        "did":        "did:key:z6Mk...",
        "fields":     {"amount": 1000, "order_id": "A100"},
        "valid":      true
    }
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_ENVELOPE_KEYS = ("timestamp", "level", "event_type", "sequence", "did", "event_id")
_MARKER_KEYS = ("_hidden_groups", "_decrypt_errors", "_valid")


def _flatten(entry) -> dict:
    """Entry-shaped JSON output matching tn.read().

    Accepts either:
      - the new flat-dict shape (default ``tn.read()`` output, post-2026-04-25),
      - the legacy ``{envelope, plaintext, valid}`` dict (``tn.read(raw=True)``),
      - or the old ``Entry`` object for transitional compatibility.

    Returns a flat JSON-friendly dict with no ciphertext, no envelope
    internals, no group-keyed plaintext.
    """
    # Entry objects from tn.read() — transitional compatibility path.
    if hasattr(entry, "fields") and hasattr(entry, "event_type"):
        ts = entry.timestamp
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat().replace("+00:00", "Z")
        return {
            "timestamp": ts,
            "level": getattr(entry, "level", ""),
            "event_type": entry.event_type,
            "sequence": getattr(entry, "sequence", None),
            "did": getattr(entry, "did", None),
            "fields": dict(entry.fields),
            "valid": getattr(entry, "valid", True),
        }
    # Legacy raw dict fallback.
    if isinstance(entry, dict) and "envelope" in entry and "plaintext" in entry:
        env = entry["envelope"]
        plaintext = entry.get("plaintext") or {}
        fields: dict = {}
        for _group, body in plaintext.items() if isinstance(plaintext, dict) else ():
            if isinstance(body, dict):
                fields.update(body)
        valid_block = entry.get("valid") or {}
        return {
            "timestamp": env.get("timestamp"),
            "level": env.get("level", "info"),
            "event_type": env.get("event_type"),
            "sequence": env.get("sequence"),
            "did": env.get("did"),
            "fields": fields,
            "valid": bool(valid_block.get("signature", True))
            and bool(valid_block.get("chain", True)),
        }
    # New flat-dict shape from tn.read() default.
    env_view = {k: entry.get(k) for k in _ENVELOPE_KEYS if k in entry}
    fields = {
        k: v for k, v in entry.items() if k not in _ENVELOPE_KEYS and k not in _MARKER_KEYS
    }
    valid_block = entry.get("_valid") or {}
    return {
        "timestamp": env_view.get("timestamp"),
        "level": env_view.get("level", "info"),
        "event_type": env_view.get("event_type"),
        "sequence": env_view.get("sequence"),
        "did": env_view.get("did"),
        "fields": fields,
        # When verify wasn't requested, default to True (no _valid block means
        # the caller didn't ask; treat as "trusted by the runtime").
        "valid": (
            bool(valid_block.get("signature", True)) and bool(valid_block.get("chain", True))
            if valid_block
            else True
        ),
    }


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
        help="Path to the ndjson log (default: cfg.log_path, e.g. <yaml_dir>/.tn/logs/tn.ndjson)",
    )
    ap.add_argument(
        "--once",
        action="store_true",
        help="Print current log contents and exit (do not follow)",
    )
    ap.add_argument(
        "--interval",
        type=float,
        default=0.3,
        help="Poll interval in seconds when following (default: 0.3)",
    )
    args = ap.parse_args(argv)

    # UTF-8 stdout so non-ASCII data in entries round-trips correctly.
    # sys.stdout is typed as TextIO which doesn't declare reconfigure, but the
    # actual stdout on CPython is a TextIOWrapper that does; guard with getattr
    # for the rare non-standard stdout and skip cleanly.
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

    from . import current_config, flush_and_close, read
    from . import init as tn_init

    tn_init(yaml_path)
    cfg = current_config()
    log_path = Path(args.log).resolve() if args.log else cfg.resolve_log_path()

    seen = 0
    try:
        while True:
            if log_path.exists():
                # verify=True so the `valid` flag in the output reflects
                # signature + chain checks (matches the documented shape).
                entries = list(read(log_path, cfg, verify=True))
                for e in entries[seen:]:
                    sys.stdout.write(json.dumps(_flatten(e), default=str) + "\n")
                    sys.stdout.flush()
                seen = len(entries)
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        flush_and_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
