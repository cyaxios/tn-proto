"""tn-protocol introspection toolchain.

Vendored from `creator_platform/backend/introspect/` and adapted for the
tn-protocol Python SDK. Produces:

  - symbol inventory (every function/class with signature + decorators)
  - import dependency graph
  - extension-point catalog (emit("...") sites)
  - module + class diagrams via pyreverse
  - environment-variable inventory (TN_*, CP_TN_*, etc.)
  - flag inventory (bool/Optional[bool] kwargs + call sites)
  - phantom-features audit re-grounding
  - Rust public-surface inventory (regex-based, no Cargo build needed)
  - admin module coupling visualization
  - coverage manifest (proof every file was visited)

Artifacts land in `tn-protocol/docs/audit-baseline/` and are committed.

Run:
    python -m tools.introspect run-all
"""
from __future__ import annotations

from .config import IntrospectConfig, default_config

__all__ = ["IntrospectConfig", "default_config"]
