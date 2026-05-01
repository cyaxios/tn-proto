"""Discover Scenario subclasses by walking the scenarios package."""

from __future__ import annotations

import importlib
import pkgutil

from .scenario import Scenario


def discover_all() -> list[Scenario]:
    """Import every scenarios.<persona>.* module and collect instances."""
    import scenarios  # parent package

    out: list[Scenario] = []
    for mod_info in pkgutil.walk_packages(
        scenarios.__path__,
        prefix="scenarios.",
    ):
        if "_harness" in mod_info.name:
            continue
        try:
            mod = importlib.import_module(mod_info.name)
        except Exception as e:
            print(f"[registry] skipped {mod_info.name}: {e}")
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (
                isinstance(obj, type)
                and issubclass(obj, Scenario)
                and obj is not Scenario
                and getattr(obj, "persona", "")
                and getattr(obj, "name", "")
            ):
                out.append(obj())
    return out


def filter_scenarios(
    all_scenarios: list[Scenario],
    *,
    personas: list[str] | None = None,
    tags: list[str] | None = None,
    only: str | None = None,
) -> list[Scenario]:
    out = all_scenarios
    if personas:
        out = [s for s in out if s.persona in personas]
    if tags:
        tset = set(tags)
        out = [s for s in out if s.tags & tset]
    if only:
        # format: "<persona>/<name>"
        persona, _, name = only.partition("/")
        out = [s for s in out if s.persona == persona and s.name == name]
    return out
