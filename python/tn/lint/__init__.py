"""tn.lint - static analyzer for the TN logging protocol.

Walks Python source, cross-references a project's tn.yaml plus extended
industry packs, and reports violations such as PII in event_type literals,
undeclared fields, and references to forbidden_post_auth fields.

Public entry point: ``python -m tn.lint``.
"""

from tn.lint.config import ConfigError, LintConfig, load_config
from tn.lint.engine import lint_paths
from tn.lint.findings import Finding
from tn.lint.rules import ALL_RULES

__all__ = [
    "ALL_RULES",
    "ConfigError",
    "Finding",
    "LintConfig",
    "lint_paths",
    "load_config",
]
