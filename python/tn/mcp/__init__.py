"""tn-mcp-server: the unified TN Model Context Protocol server.

One server, three tool families:

  - exhaust governance pipeline (tn.mcp.exhaust): profile / inventory /
    template mining / kit matching / classification / linkage / hook stages
    plus the durable group registry and the report assembler
  - vault connector (tn.mcp.vault_tools): cold-claim binding and read-side
    sync of entitled kits
  - core verbs (tn.mcp.tools_core): tn_status / tn_read / tn_decrypt

Run via:
    python -m tn.mcp           # stdio server (agent-owned)
    python -m tn.mcp http      # standalone streamable-http on 127.0.0.1
    tn-mcp-server              # console script (after install)

The server is project-rooted: it inherits CWD from the spawning agent and
resolves the active ceremony the same way the SDK does (TN_YAML ->
./tn.yaml -> ~/.tn/tn.yaml). The core verbs never mint a ceremony on their
own; creating one is an explicit tool call (new_workstream).

See the tn.mcp.server module docstring for the full tool surface and the
security posture.
"""
from __future__ import annotations

__version__ = "0.5.6a1"  # keep aligned with pyproject.toml [project] version

# Re-export the entry point for `python -c "from tn.mcp import main; main()"`.
from .server import main

__all__ = ["__version__", "main"]
