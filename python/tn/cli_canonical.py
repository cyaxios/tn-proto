"""``tn canonical`` — echo the canonical UTF-8 bytes of stdin JSON.

Diagnostic verb mirroring the TypeScript ``tn-js canonical`` command
(``ts-sdk/bin/tn-js.mjs`` ``canonicalCmd``). For every non-empty line of
stdin it parses the line as JSON and writes the TN canonical-bytes form
— the exact serialization that feeds ``row_hash`` — back to stdout,
newline-terminated. The output is byte-identical to the TS verb so it
can be diffed for cross-implementation ``row_hash`` parity.

The canonicalization itself is NOT reimplemented here: this delegates to
:func:`tn.canonical._canonical_bytes`, the same function ``row_hash``
uses.
"""

from __future__ import annotations

import argparse
import json
import sys

from .canonical import _canonical_bytes


def cmd_canonical(args: argparse.Namespace) -> int:
    """Echo the canonical bytes of each JSON line read from stdin.

    Reads ``sys.stdin`` line by line. Blank / whitespace-only lines are
    skipped (matching the TS ``forEachLine`` helper). Each remaining line
    is parsed as JSON; the canonical UTF-8 bytes are written to
    ``sys.stdout`` followed by ``\\n``.

    Args:
        args: Parsed argparse namespace. Unused — the verb takes no
            options; stdin is the sole input.

    Returns:
        ``0`` on success.

    Raises:
        SystemExit: Exit code ``2`` if a line is not valid JSON, written
            after a ``tn: invalid JSON on stdin`` diagnostic on stderr.
            Mirrors the TS ``die`` behavior.
    """
    out = getattr(sys.stdout, "buffer", sys.stdout)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError as exc:
            sys.stderr.write(f"tn: invalid JSON on stdin: {exc}\n")
            raise SystemExit(2) from exc
        out.write(_canonical_bytes(value) + b"\n")
    return 0
