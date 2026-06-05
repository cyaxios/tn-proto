"""``tn info`` — emit ONE attested log entry from the CLI.

Python parity for the TypeScript ``tn-js info`` verb (see
``ts-sdk/bin/tn-js.mjs`` ``infoCmd`` + ``parseFieldArgs``). The TS verb:

    tn-js info --yaml <path> --event <type> [--level <level>] [--field k=v]...

initialises the ceremony at ``--yaml`` and emits a single attested entry
of the given ``event_type`` / ``level`` carrying the ``--field`` key/value
pairs. This module does the same thing through the existing Python SDK
verbs — ``tn.init`` for the ceremony and ``tn.info`` (or ``tn.log`` for a
non-standard ``--level``) for the emit. It does NOT reimplement the
encryption / chain / signing machinery; that all lives behind ``tn.info``.

The verb is intentionally tiny: parse ``--field k=v`` strings into a plain
``fields`` dict, bind the ceremony, emit, print a one-line confirmation.
Field values are kept as strings (matching the TS ``--field`` path —
``--int`` / ``--bool`` typed variants are out of scope here, exactly as the
default string form in ``parseFieldArgs``).
"""

from __future__ import annotations

import sys
from typing import Any

import tn

# Levels that map onto a dedicated ``tn.<level>`` verb. Anything else
# (e.g. ``--level trace``) goes through ``tn.log(..., level=...)`` so the
# string lands verbatim in the envelope, mirroring the TS ``rt.emit(level,
# ...)`` which accepts any level string.
_STANDARD_VERBS = {"debug", "info", "warning", "error"}


def parse_field_args(raw_fields: list[str] | None) -> dict[str, str]:
    """Turn ``--field k=v`` strings into a ``{k: v}`` dict.

    Mirrors the string branch of the TS ``parseFieldArgs``: split on the
    FIRST ``=`` only, so a value may itself contain ``=`` signs
    (``--field note=a=b`` -> ``{"note": "a=b"}``). A bare ``--field key``
    with no ``=`` is rejected loudly rather than silently dropped.
    """
    fields: dict[str, str] = {}
    for item in raw_fields or []:
        if "=" not in item:
            raise ValueError(
                f"info: --field expects k=v, got {item!r} (no '=' separator)"
            )
        key, value = item.split("=", 1)
        if not key:
            raise ValueError(f"info: --field has empty key: {item!r}")
        fields[key] = value
    return fields


def cmd_info(args: Any) -> int:
    """Emit one attested entry; return a process exit code.

    ``args`` is the argparse ``Namespace`` carrying ``yaml`` (str),
    ``event`` (str), ``level`` (str), and ``field`` (list[str] | None).

    Exit codes mirror the TS verb's ``die`` (code 2) for the missing
    required-flag cases; 0 on a successful emit.
    """
    if not args.yaml:
        sys.stderr.write("info: --yaml <path> is required\n")
        return 2
    if not args.event:
        sys.stderr.write("info: --event <type> is required\n")
        return 2

    try:
        fields = parse_field_args(getattr(args, "field", None))
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    level = (args.level or "info").strip()

    # Bind the ceremony at the explicit yaml path (parity with the TS
    # ``NodeRuntime.init(args.yaml)``).
    tn.init(args.yaml)

    # Emit the single entry. The four standard levels route through the
    # dedicated verb (so ``--level info`` -> ``tn.info``); any other level
    # string goes through ``tn.log`` verbatim, matching the TS
    # ``rt.emit(level, ...)`` which accepts arbitrary level strings.
    if level in _STANDARD_VERBS:
        getattr(tn, level)(args.event, **fields)
    else:
        tn.log(args.event, level=level, **fields)

    sys.stdout.write(
        f"info: emitted event_type={args.event!r} level={level!r} "
        f"fields={len(fields)}\n"
    )
    return 0
