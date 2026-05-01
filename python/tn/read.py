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
