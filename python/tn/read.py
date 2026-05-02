"""Read verbs: read, read_raw, read_all, read_as_recipient, secure_read."""
from __future__ import annotations

from typing import Any  # used in secure_read(*, log_path: Any, cfg: Any) annotation


def read(log_path=None, cfg=None, *, verify: bool = False, raw: bool = False, all_runs: bool = False, where=None):
    from . import _read_impl
    yield from _read_impl(log_path, cfg, verify=verify, raw=raw, all_runs=all_runs, where=where)


def read_raw(log_path=None, cfg=None, *, all_runs: bool = False, where=None):
    from . import _read_raw_impl
    yield from _read_raw_impl(log_path, cfg, all_runs=all_runs, where=where)


def read_all(log_path=None, cfg=None, *, all_runs: bool = False, where=None):
    from . import _read_all_impl
    yield from _read_all_impl(log_path, cfg, all_runs=all_runs, where=where)


def read_as_recipient(log_path, keystore_dir, *, group: str = "default", verify_signatures: bool = True):
    from . import _read_as_recipient_impl
    yield from _read_as_recipient_impl(log_path, keystore_dir, group=group, verify_signatures=verify_signatures)


def secure_read(*, on_invalid: str = "skip", log_path: Any = None, cfg: Any = None, all_runs: bool = False, where=None):
    from . import _secure_read_impl
    yield from _secure_read_impl(on_invalid=on_invalid, log_path=log_path, cfg=cfg, all_runs=all_runs, where=where)


async def watch(*, since: str | int = "now", verify: bool = False, poll_interval: float = 0.3, log_path=None):
    """Tail the local TN log, yielding decoded entries as they're appended.

    Async generator. Use as ``async for entry in tn.watch(...)``.

    Parameters
    ----------
    since : "start" | "now" | int | str
        Where to begin yielding from. "start" replays from byte 0;
        "now" (default) yields only new appends; an int is a sequence
        number (resumes at first envelope with sequence >= N); a str
        is an ISO-8601 timestamp.
    verify : bool
        Pass entries through signature-verify validation. Default False.
    poll_interval : float
        Seconds between polls. Default 0.3.
    log_path : str | PathLike | None
        Override the log path (defaults to cfg.resolve_log_path()).

    Yields
    ------
    dict
        Decoded entry — same flat shape as ``tn.read()``.

    Notes
    -----
    Stat-poll based; no watchdog dependency. On rotation (inode change)
    the watcher resumes at offset 0 of the new file. On truncation a
    ``tn.watch.truncation_observed`` admin event is emitted.
    """
    from . import _watch_impl
    async for entry in _watch_impl._watch_impl(
        since=since, verify=verify, poll_interval=poll_interval, log_path=log_path
    ):
        yield entry
