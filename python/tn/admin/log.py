"""Dedicated admin log routing.

Per the 2026-04-24 admin log architecture plan, admin events
(``tn.ceremony.*``, ``tn.group.*``, ``tn.recipient.*``,
``tn.rotation.*``, ``tn.coupon.*``, ``tn.enrolment.*``, ``tn.vault.*``)
are routed to ``<yaml_dir>/.tn/admin/admin.ndjson`` by default rather
than mixed into the main log.

This module owns:

* the default-path resolution (``resolve_admin_log_path``)
* the "is this an admin event" predicate (``is_admin_event_type``)
* a small append helper (``append_admin_envelope``)
* idempotent dedupe by ``row_hash``

The actual emit-side write happens in ``tn.logger`` — when
``cfg.protocol_events_location != "main_log"`` it routes admin events
through ``cfg.resolve_protocol_events_path``. This module's
``resolve_admin_log_path`` returns the same answer for the new default
``./.tn/admin/admin.ndjson`` path.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..config import LoadedConfig

DEFAULT_ADMIN_LOG_LOCATION = "./.tn/admin/admin.ndjson"

_ADMIN_PREFIXES: tuple[str, ...] = (
    "tn.ceremony.",
    "tn.group.",
    "tn.recipient.",
    "tn.rotation.",
    "tn.coupon.",
    "tn.enrolment.",
    "tn.vault.",
    # Agents-policy lifecycle (per 2026-04-25 read-ergonomics spec §2.7).
    # ``tn.agents.policy_published`` carries the inline markdown text + hash
    # so an auditor replaying the log knows which policy was active at any
    # point. The reducer doesn't act on these yet — they're replayable
    # provenance only.
    "tn.agents.",
    # Tampered-row visibility (per spec §3.3). ``tn.read.tampered_row_skipped``
    # is emitted by ``tn.secure_read()`` when a row fails (sig|row_hash|chain)
    # verification under the default ``on_invalid="skip"`` mode. Public
    # fields only — the bad row's payload is NOT exposed.
    "tn.read.",
)


def is_admin_event_type(event_type: str) -> bool:
    """True iff ``event_type`` is an admin event subject to the dedicated
    log. Mirrors the prefix list scanned by ``tn.admin_state``."""
    if not isinstance(event_type, str):
        return False
    return any(event_type.startswith(p) for p in _ADMIN_PREFIXES)


def resolve_admin_log_path(cfg: LoadedConfig) -> Path:
    """Resolve the absolute admin log path for ``cfg``.

    If the yaml's ``protocol_events_location`` (or the new
    ``admin_log_location``) is set to a single-file path (no template
    tokens) we honor that. Otherwise we use the new default
    ``<yaml_dir>/.tn/admin/admin.ndjson``.

    The dedicated `.tn/admin/` directory is created lazily by callers
    on first emit; this function does not create directories.
    """
    yaml_dir = cfg.yaml_path.parent
    pel = getattr(cfg, "protocol_events_location", "main_log")
    if pel and pel != "main_log" and "{" not in pel:
        # Existing single-file PEL setting — respect it.
        p = Path(pel)
        return p if p.is_absolute() else (yaml_dir / p).resolve()
    return (yaml_dir / DEFAULT_ADMIN_LOG_LOCATION).resolve()


def existing_row_hashes(admin_log: Path) -> set[str]:
    """Return the set of ``row_hash`` strings already present in the
    admin log. Used by absorb to dedupe incoming envelopes."""
    if not admin_log.exists():
        return set()
    out: set[str] = set()
    with admin_log.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
            except json.JSONDecodeError:
                continue
            rh = env.get("row_hash")
            if isinstance(rh, str):
                out.add(rh)
    return out


def append_admin_envelopes(admin_log: Path, envelopes: Iterable[dict[str, Any]]) -> int:
    """Append a sequence of envelope dicts to the admin log file.

    Returns the number of envelopes written. Creates parent directory
    lazily. Each envelope is JSON-serialized with compact separators —
    matches the on-disk format produced by ``tn.logger``.
    """
    admin_log.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with admin_log.open("a", encoding="utf-8") as f:
        for env in envelopes:
            line = json.dumps(env, separators=(",", ":")) + "\n"
            f.write(line)
            written += 1
    return written


# Short aliases for the tn.admin.log.* namespace. The verbose names stay
# as the underlying definitions; these are the convenience shorthand.
path_for = resolve_admin_log_path
append = append_admin_envelopes


__all__ = [
    "DEFAULT_ADMIN_LOG_LOCATION",
    "append",
    "append_admin_envelopes",
    "existing_row_hashes",
    "is_admin_event_type",
    "path_for",
    "resolve_admin_log_path",
]
