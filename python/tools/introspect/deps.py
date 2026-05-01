"""Pure-AST import graph builder."""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from .config import IntrospectConfig
from .manifest import write_manifest


def _module_qualname(path: Path, repo_root: Path) -> str:
    rel = path.relative_to(repo_root).with_suffix("")
    parts = rel.parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _extract_imports(tree: ast.Module, current_module_qn: str) -> list[str]:
    """Return the (resolved-absolute) module names this AST imports.

    Handles relative imports: `from .x import y` inside `pkg.mod.foo` resolves
    to `pkg.mod.x`. Bare `from . import y` resolves to `pkg.mod`.
    """
    imports: list[str] = []
    parts = current_module_qn.split(".") if current_module_qn else []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            level = node.level or 0
            if level > 0:
                # Drop `level` components from the importing module's qualname.
                # The current module's own name is the last component, so we drop
                # `level` from the package list (which is parts[:-1]).
                package_parts = parts[:-1]
                if level > len(package_parts):
                    # Going up beyond top-level — bail out.
                    continue
                base = package_parts[: len(package_parts) - (level - 1)]
                if node.module:
                    resolved = ".".join(base + node.module.split("."))
                else:
                    resolved = ".".join(base)
                if resolved:
                    imports.append(resolved)
            elif node.module is not None:
                imports.append(node.module)
    return imports


def _iter_py_files(cfg: IntrospectConfig):
    for root in cfg.source_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


def _longest_prefix_in(name: str, universe: set[str]) -> str | None:
    parts = name.split(".")
    for i in range(len(parts), 0, -1):
        candidate = ".".join(parts[:i])
        if candidate in universe:
            return candidate
    return None


def build_deps(cfg: IntrospectConfig) -> dict[str, Any]:
    edges: dict[str, list[str]] = {}
    known_modules: set[str] = set()

    for path in _iter_py_files(cfg):
        known_modules.add(_module_qualname(path, cfg.repo_root))

    for path in _iter_py_files(cfg):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        module_qn = _module_qualname(path, cfg.repo_root)
        raw = _extract_imports(tree, module_qn)
        resolved: set[str] = set()
        for imp in raw:
            canonical = _longest_prefix_in(imp, known_modules)
            if canonical is not None:
                resolved.add(canonical)
        edges[module_qn] = sorted(resolved)

    reverse: dict[str, list[str]] = {m: [] for m in edges}
    for src, dests in edges.items():
        for d in dests:
            canonical = _longest_prefix_in(d, known_modules) or d
            reverse.setdefault(canonical, []).append(src)
    for k in reverse:
        reverse[k] = sorted(set(reverse[k]))

    return {
        "edges": dict(sorted(edges.items())),
        "reverse_edges": dict(sorted(reverse.items())),
    }


def _mermaid_for(graph: dict[str, Any]) -> str:
    lines = ["graph LR"]
    ids: dict[str, str] = {}
    for i, name in enumerate(sorted(graph["edges"].keys())):
        ids[name] = f"n{i}"
        lines.append(f'  {ids[name]}["{name}"]')
    for src in sorted(graph["edges"].keys()):
        for dst in graph["edges"][src]:
            if dst in ids:
                lines.append(f"  {ids[src]} --> {ids[dst]}")
    return "\n".join(lines) + "\n"


def _dot_for(graph: dict[str, Any]) -> str:
    """Render as Graphviz DOT — better for large graphs and renders without npx."""
    lines = ["digraph deps {", "  rankdir=LR;", '  node [shape=box, fontname="Helvetica"];']
    ids: dict[str, str] = {}
    for i, name in enumerate(sorted(graph["edges"].keys())):
        nid = f"n{i}"
        ids[name] = nid
        lines.append(f'  {nid} [label="{name}"];')
    for src in sorted(graph["edges"].keys()):
        for dst in graph["edges"][src]:
            if dst in ids:
                lines.append(f"  {ids[src]} -> {ids[dst]};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_deps_artifacts(cfg: IntrospectConfig) -> tuple[Path, Path, Path]:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    graph = build_deps(cfg)
    json_path = cfg.output_dir / "deps.json"
    mmd_path = cfg.output_dir / "deps.mmd"
    dot_path = cfg.output_dir / "deps.dot"
    json_path.write_text(
        json.dumps(graph, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    mmd_path.write_text(_mermaid_for(graph), encoding="utf-8")
    dot_path.write_text(_dot_for(graph), encoding="utf-8")
    write_manifest(cfg, extras={"producer": "deps"})
    return json_path, mmd_path, dot_path
