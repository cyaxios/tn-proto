"""TN MCP server: stdio transport, tool dispatch, error mapping.

This is the stub. Task 5 fleshes out the dispatch loop; Tasks 6-8 register
the three Sprint-1-foundation tools.
"""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tn-mcp-server",
        description=(
            "TN MCP server: exposes the TN cookbook surface (logging, "
            "reading, recipients, groups, wallet) over Model Context "
            "Protocol stdio. Project-rooted; inherits CWD from the "
            "spawning agent."
        ),
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print server version and exit.",
    )
    args = parser.parse_args(argv)

    if args.version:
        from . import __version__
        print(__version__)
        return 0

    # Real stdio dispatch comes in Task 5.
    print(
        "tn-mcp-server: dispatch loop not yet implemented (see Task 5).",
        file=sys.stderr,
    )
    return 0
