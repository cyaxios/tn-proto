"""Tail-aware async generator over the local TN ndjson log(s).

Tracks byte offset per source file so we never re-read prior bytes on
append. Survives rotation (inode change) by reopening at offset 0 of
the new file. On unexpected truncation (file shorter than tracked
offset, no inode change), we resume from the new end and emit a
tamper-class admin event (``tn.watch.truncation_observed``).

By default ``tn.watch`` tails **only the main user log**. Admin events
(``tn.*``) live in a separate log and must be addressed explicitly:

    tn.watch(log="admin")                       # sugar (use this)
    tn.watch(log=cfg.admin_log_location)        # explicit config address
    tn.watch(log="./logs/payments.ndjson")      # literal path to any log

This is intentionally symmetric with ``tn.read`` — the two verbs share
the resolver in ``tn._log_targets`` so any addressing form works
uniformly. The previous always-include-admin default was a regression
fix; the new default rule is "admin events are addressed, never
merged implicitly."

Cross-language counterpart: ts-sdk/src/watch.ts. Both implementations
must yield the same entries in the same order for the same log file.

Stat-poll based — no watchdog / native fs-event dependency. The
default 0.3s poll interval matches the TS default.
"""
from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class _SourceState:
    """Per-source-file tail state. One instance per file being watched."""
    path: Path
    offset: int = 0
    inode: int | None = None
    prev_hash_by_event: dict[str, str] = field(default_factory=dict)


def _resolve_watch_sources(
    cfg, log_path: Any
) -> list[Path]:
    """Decide which files ``tn.watch`` should tail.

    Symmetric with ``tn.read``: routes the public ``log=`` argument
    through :func:`tn._log_targets.resolve_log_target` so any form a
    caller might pass — literal path, template with ``{event_type}``
    style tokens, or the ``"admin"`` alias — yields the same file set
    here and in ``tn.read``.

    With ``log_path is None`` we tail **only the main log**. Admin
    envelopes (``tn.*``) live in their own log since the
    runtime-correctness work split them off; merging them into the
    default watch surface was a regression-period workaround. Callers
    that actually want to see admin events in their tail say so:

        tn.watch(log="admin")                       # sugar (use this)
        tn.watch(log=cfg.admin_log_location)        # explicit config address
    """
    if log_path is None:
        return [cfg.resolve_log_path()]
    from ._log_targets import resolve_log_target

    return resolve_log_target(log_path, cfg)


def _initial_offset_for(
    path: Path, since: str | int
) -> int:
    """Compute the starting byte offset for one source given ``since``."""
    if since == "start":
        return 0
    if since == "now":
        return path.stat().st_size if path.exists() else 0
    if isinstance(since, int):
        return _find_offset_for_sequence(path, since)
    return _find_offset_for_timestamp(path, since)


async def _watch_impl(
    *,
    since: str | int = "now",
    verify: bool = False,
    poll_interval: float = 0.3,
    log_path: str | os.PathLike | None = None,
) -> AsyncIterator[dict[str, Any]]:
    # Bug W5 (0.4.2a4 follow-up): match ``tn.read``'s autoinit path so
    # a fresh process without a bound runtime gets the same friendly
    # "no ceremony found" error (with discovery-chain hint) instead
    # of the bare ``no active runtime`` raise that ``current_config``
    # would otherwise produce. read.py:191 does this for the same
    # reason; the asymmetry made watch's empty-result mode confusing.
    import tn as _tn
    _tn._maybe_autoinit_load_only()

    from . import current_config
    from .reader import flatten_raw_entry, parse_envelope_line

    cfg = current_config()
    paths = _resolve_watch_sources(cfg, log_path)

    sources = [
        _SourceState(
            path=p,
            offset=_initial_offset_for(p, since),
            inode=(p.stat().st_ino if p.exists() else None),
        )
        for p in paths
    ]

    while True:
        any_yielded = False
        for src in sources:
            async for entry in _drain_one_source(
                src, cfg, verify=verify,
                parse_envelope_line=parse_envelope_line,
                flatten_raw_entry=flatten_raw_entry,
            ):
                any_yielded = True
                yield entry
        # Sleep once per full tick. If nothing was yielded this tick
        # it's a clean wait; if something was, the caller saw it via
        # the yields above and we still sleep before the next stat.
        del any_yielded
        await asyncio.sleep(poll_interval)


async def _drain_one_source(
    src: _SourceState,
    cfg,
    *,
    verify: bool,
    parse_envelope_line,
    flatten_raw_entry,
) -> AsyncIterator[dict[str, Any]]:
    """Drain a single source file's new lines since the last tick.

    Updates ``src`` in place (offset, inode, prev_hash chain). Yields
    one flattened entry per parseable envelope. Skips invalid lines
    silently (offset still advances so a bad line doesn't block the
    tail).
    """
    p = src.path
    if not p.exists():
        return

    st = p.stat()
    current_inode = st.st_ino

    if src.inode is not None and current_inode != src.inode:
        # Rotation — file replaced. Reset to offset 0 of the new file.
        src.offset = 0
        src.inode = current_inode
        src.prev_hash_by_event.clear()
    elif st.st_size < src.offset:
        # Truncation — file shorter than tracked offset, same inode.
        _emit_truncation_warning(p, src.offset, st.st_size)
        src.offset = st.st_size
    else:
        src.inode = current_inode

    if st.st_size <= src.offset:
        return

    with p.open("rb") as f:
        f.seek(src.offset)
        while True:
            line = f.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                # Partial line; rewind so the next tick re-reads it whole.
                src.offset = f.tell() - len(line)
                break
            line_str = line.decode("utf-8").rstrip("\n")
            if not line_str:
                src.offset = f.tell()
                continue
            raw = parse_envelope_line(
                line_str, cfg,
                verify=verify,
                prev_hash_by_event=src.prev_hash_by_event,
            )
            if raw is None:
                src.offset = f.tell()
                continue
            yield flatten_raw_entry(raw, include_valid=verify)
            src.offset = f.tell()


def _emit_truncation_warning(
    path: Path, prior_offset: int, new_size: int
) -> None:
    """Best-effort emit of ``tn.watch.truncation_observed`` admin event.

    Truncation under a stable inode signals tampering or surprising
    operator action (manual file edit, log-rotation tool that didn't
    rename, etc.). We surface it as a warning-level admin event so it
    rides the attested log and survives forensics. Swallowed if the
    dispatch isn't ready yet.
    """
    try:
        from . import _require_dispatch
        rt = _require_dispatch()
        rt.emit("warning", "tn.watch.truncation_observed", {
            "log_path": str(path),
            "prior_offset": prior_offset,
            "new_size": new_size,
        })
    except Exception:  # noqa: BLE001 — best-effort: swallow if dispatch isn't ready
        pass


def _find_offset_for_sequence(path: Path, target_seq: int) -> int:
    """Linear scan from byte 0; return offset of first envelope with sequence >= target_seq.

    Note: per-event-type sequence semantics — the comparison is on the
    envelope's ``sequence`` field as-is. Cross-language tests use a single
    event_type so ``tn.watch(since=N)`` and an N-th absolute entry coincide.
    """
    if not path.exists():
        return 0
    pos = 0
    with path.open("rb") as f:
        while True:
            start = f.tell()
            line = f.readline()
            if not line:
                return pos
            if not line.endswith(b"\n"):
                return start
            try:
                env = json.loads(line)
            except json.JSONDecodeError:
                pos = f.tell()
                continue
            seq = env.get("sequence")
            if isinstance(seq, int) and seq >= target_seq:
                return start
            pos = f.tell()


def _find_offset_for_timestamp(path: Path, target_ts: str) -> int:
    """Linear scan; return offset of first envelope with timestamp >= target_ts.

    Timestamps are ISO-8601 strings in TN envelopes (RFC 3339 / lexicographic
    ordering); we do a string compare rather than parsing each one.
    """
    if not path.exists():
        return 0
    pos = 0
    with path.open("rb") as f:
        while True:
            start = f.tell()
            line = f.readline()
            if not line:
                return pos
            if not line.endswith(b"\n"):
                return start
            try:
                env = json.loads(line)
            except json.JSONDecodeError:
                pos = f.tell()
                continue
            ts = env.get("timestamp")
            if isinstance(ts, str) and ts >= target_ts:
                return start
            pos = f.tell()
