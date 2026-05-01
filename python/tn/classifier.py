"""LLM field classifier — PRD §6.4 (STUBBED).

When a field arrives that is not listed in `fields:` in tn.yaml, the SDK
would call a local LLM to pick the right group. First occurrence still
goes to `default` (non-blocking). A background classification then
updates the YAML for next time.

This file exists as a placeholder so the feature isn't forgotten. The
runtime just returns `"default"` today. To enable later, set
`llm_classifier.enabled: true` in tn.yaml and _register a callable via
`tn.classifier._register(fn)` where `fn(field_name, value_type, groups)
-> group_name`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

ClassifierFn = Callable[[str, str, list[str]], str]


@dataclass
class ClassifierConfig:
    enabled: bool = False
    provider: str = ""  # "anthropic" | "openai" | "local" | ...
    model: str = ""  # e.g. "claude-haiku-4-5"


_active: ClassifierFn | None = None
_config: ClassifierConfig = ClassifierConfig()


def _configure(cfg_dict: dict[str, Any] | None) -> None:
    """Called by tn.config when loading YAML; stores the config section."""
    global _config
    if not cfg_dict:
        _config = ClassifierConfig()
        return
    _config = ClassifierConfig(
        enabled=bool(cfg_dict.get("enabled", False)),
        provider=str(cfg_dict.get("provider", "")),
        model=str(cfg_dict.get("model", "")),
    )


def _register(fn: ClassifierFn) -> None:
    """Register an LLM-backed classifier callable."""
    global _active
    _active = fn


def _classify(field_name: str, value: Any, group_names: list[str]) -> str:
    """Return the group name for an unknown field.

    STUB: returns "default" unconditionally. When enabled + a callable is
    registered, delegate to it. Exceptions fall back to "default".
    """
    if not _config.enabled or _active is None:
        return "default"
    try:
        result = _active(field_name, type(value).__name__, list(group_names))
        return result if isinstance(result, str) and result in group_names else "default"
    except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
        return "default"


def _current_config() -> ClassifierConfig:
    return _config
