"""tn-mcp-server: Model Context Protocol server exposing the TN cookbook surface.

Run via:
    python -m tn.mcp           # stdio server
    tn-mcp-server              # console script (after install)

The server is project-rooted: it inherits CWD from the spawning agent
and uses the cookbook's discovery chain (./tn.yaml -> $TN_HOME/tn.yaml ->
mint fresh) to resolve which ceremony to operate on.

See docs/superpowers/specs/2026-04-30-tn-agent-plugin-and-mcp-server-design.md
for the full design.
"""
from __future__ import annotations

__version__ = "0.2.0a1"

# Re-export the entry point for `python -c "from tn.mcp import main; main()"`.
from .server import main  # noqa: E402

__all__ = ["main", "__version__"]
