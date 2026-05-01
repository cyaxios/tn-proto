"""Extension-point catalog.

Scans every .py file for `emit("hook.name", {...})` calls AND for
`tn.log()` / `client.log()` admin event types as positional/string
arguments. Useful for tracking the TN admin event catalog from code.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from .config import IntrospectConfig
from .manifest import write_manifest


def _is_emit_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id == "emit":
        return True
    if isinstance(func, ast.Attribute) and func.attr in ("emit", "emit_async"):
        return True
    return False


def _is_tn_log_call(node: ast.Call) -> bool:
    """Detect tn.log(...) / client.log(...) / runtime.log(...) / log(...) etc.

    We look for calls whose callee's rightmost name is `log`. The first
    argument, if a string literal, is interpreted as the event_type.
    """
    func = node.func
    if isinstance(func, ast.Name) and func.id == "log":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "log":
        return True
    return False


def _literal_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dict_keys(node: ast.expr) -> list[str]:
    if not isinstance(node, ast.Dict):
        return []
    keys: list[str] = []
    for k in node.keys:
        s = _literal_string(k) if k is not None else None
        if s is not None:
            keys.append(s)
    return keys


def _iter_py_files(cfg: IntrospectConfig):
    for root in cfg.source_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


def build_catalog(cfg: IntrospectConfig) -> dict[str, Any]:
    by_emit: dict[str, dict[str, Any]] = {}
    by_log: dict[str, dict[str, Any]] = {}

    for path in _iter_py_files(cfg):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        rel = path.relative_to(cfg.repo_root).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not node.args:
                continue
            name = _literal_string(node.args[0])
            if name is None:
                # Could also check kwargs for event_type=...
                for kw in node.keywords:
                    if kw.arg in ("event_type", "name") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        name = kw.value.value
                        break
            if name is None:
                continue

            # Heuristic: TN event types contain a dot or look like 'tn.*' / 'admin.*'
            looks_like_event = "." in name or name.startswith(("tn_", "tn."))

            target = None
            if _is_emit_call(node):
                target = by_emit
            elif _is_tn_log_call(node) and looks_like_event:
                target = by_log
            if target is None:
                continue

            payload_keys: list[str] = []
            if len(node.args) >= 2:
                payload_keys = _dict_keys(node.args[1])
            for kw in node.keywords:
                if kw.arg == "data" and isinstance(kw.value, ast.Dict):
                    payload_keys = _dict_keys(kw.value)

            hook = target.setdefault(
                name,
                {"name": name, "call_sites": [], "inferred_payload_keys": []},
            )
            hook["call_sites"].append({"file": rel, "lineno": node.lineno})
            for k in payload_keys:
                if k not in hook["inferred_payload_keys"]:
                    hook["inferred_payload_keys"].append(k)

    for d in (by_emit, by_log):
        for hook in d.values():
            hook["call_sites"].sort(key=lambda cs: (cs["file"], cs["lineno"]))
            hook["inferred_payload_keys"].sort()

    return {
        "emit_hooks": sorted(by_emit.values(), key=lambda h: h["name"]),
        "tn_log_event_types": sorted(by_log.values(), key=lambda h: h["name"]),
    }


def write_catalog(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    catalog = build_catalog(cfg)
    path = cfg.output_dir / "extension_points.json"
    path.write_text(
        json.dumps(catalog, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(cfg, extras={"producer": "extension_points"})
    return path
