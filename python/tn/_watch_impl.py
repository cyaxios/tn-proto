"""Tail-aware async generator over the local TN ndjson log.

Tracks byte offset so we never re-read prior bytes on append. Survives
rotation (inode change) by reopening at offset 0 of the new file. On
unexpected truncation (file shorter than tracked offset, no inode
change), we resume from the new end and emit a tamper-class admin event
(`tn.watch.truncation_observed`).

Cross-language counterpart: ts-sdk/src/watch.ts. Both implementations
must yield the same entries in the same order for the same log file.

Stat-poll based — no watchdog / native fs-event dependency. The
default 0.3s poll interval matches the TS default.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, AsyncIterator


async def _watch_impl(
    *,
    since: str | int = "now",
    verify: bool = False,
    poll_interval: float = 0.3,
    log_path: str | os.PathLike | None = None,
) -> AsyncIterator[dict[str, Any]]:
    from . import current_config
    from .reader import flatten_raw_entry, parse_envelope_line

    cfg = current_config()
    p = Path(log_path) if log_path else cfg.resolve_log_path()

    # Per-session chain tracking: keyed by event_type, value = last row_hash.
    prev_hash_by_event: dict[str, str] = {}

    # Determine the initial byte offset.
    if since == "start":
        offset = 0
    elif since == "now":
        offset = p.stat().st_size if p.exists() else 0
    elif isinstance(since, int):
        offset = _find_offset_for_sequence(p, since)
    else:
        # ISO timestamp string
        offset = _find_offset_for_timestamp(p, since)

    inode: int | None = p.stat().st_ino if p.exists() else None

    while True:
        if not p.exists():
            await asyncio.sleep(poll_interval)
            continue

        st = p.stat()
        current_inode = st.st_ino

        if inode is not None and current_inode != inode:
            # Rotation — file replaced. Reset to offset 0 of the new file.
            offset = 0
            inode = current_inode
            prev_hash_by_event.clear()
        elif st.st_size < offset:
            # Truncation — file shorter than tracked offset, same inode.
            try:
                from . import _require_dispatch
                rt = _require_dispatch()
                rt.emit("warning", "tn.watch.truncation_observed", {
                    "log_path": str(p),
                    "prior_offset": offset,
                    "new_size": st.st_size,
                })
            except Exception:
                pass
            offset = st.st_size
        else:
            inode = current_inode

        if st.st_size > offset:
            with p.open("rb") as f:
                f.seek(offset)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        # Partial line; rewind so the next tick re-reads it whole.
                        offset = f.tell() - len(line)
                        break
                    line_str = line.decode("utf-8").rstrip("\n")
                    if not line_str:
                        offset = f.tell()
                        continue
                    raw = parse_envelope_line(
                        line_str, cfg,
                        verify=verify,
                        prev_hash_by_event=prev_hash_by_event,
                    )
                    if raw is None:
                        offset = f.tell()
                        continue
                    yield flatten_raw_entry(raw, include_valid=verify)
                    offset = f.tell()

        await asyncio.sleep(poll_interval)


def _find_offset_for_sequence(path: Path, target_seq: int) -> int:
    """Linear scan from byte 0; return offset of first envelope with sequence >= target_seq.

    Note: per-event-type sequence semantics — the comparison is on the
    envelope's ``sequence`` field as-is. Cross-language tests use a single
    event type so the per-type counter increments monotonically.
    """
    if not path.exists():
        return 0
    with path.open("rb") as f:
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                return pos
            try:
                env = json.loads(line)
                if env.get("sequence", 0) >= target_seq:
                    return pos
            except json.JSONDecodeError:
                pass


def _find_offset_for_timestamp(path: Path, target_ts: str) -> int:
    """Like _find_offset_for_sequence but compares timestamp strings.

    ISO-8601 timestamps sort lexicographically in chronological order
    (assuming all UTC / fixed format), so ``>=`` works directly.
    """
    if not path.exists():
        return 0
    with path.open("rb") as f:
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                return pos
            try:
                env = json.loads(line)
                if env.get("timestamp", "") >= target_ts:
                    return pos
            except json.JSONDecodeError:
                pass
