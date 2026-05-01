"""Admin module coupling visualization.

Subset the deps graph to just the modules whose name contains 'admin' (in
any package), producing a focused dependency view of admin.py +
admin_cache.py + admin_log.py and their immediate neighbors.

Output:
- admin_coupling.json (subset graph + neighbor closure)
- admin_coupling.dot  (Graphviz)
- admin_coupling.mmd  (Mermaid)

The CLI's renderer step turns these into .svg / .png if dot/mmdc are
on PATH.
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import IntrospectConfig
from .deps import build_deps
from .manifest import write_manifest


def build_admin_coupling(cfg: IntrospectConfig) -> dict:
    full = build_deps(cfg)
    edges = full["edges"]
    reverse = full["reverse_edges"]

    # Match any module whose qualname includes 'admin' as a substring of any
    # path component — picks up admin.py, admin_cache.py, admin_log.py, and
    # any future admin/<submodule>.py.
    admin_nodes = {
        m for m in edges
        if any("admin" in part.lower() for part in m.split("."))
    }
    # Neighbors: anything admin imports + anything that imports admin.
    neighbors: set[str] = set()
    for m in admin_nodes:
        neighbors.update(edges.get(m, []))
        neighbors.update(reverse.get(m, []))

    keep = admin_nodes | neighbors
    sub_edges = {m: [d for d in edges.get(m, []) if d in keep] for m in keep if m in edges}
    sub_reverse = {m: [s for s in reverse.get(m, []) if s in keep] for m in keep}

    return {
        "admin_nodes": sorted(admin_nodes),
        "neighbors": sorted(neighbors - admin_nodes),
        "edges": dict(sorted(sub_edges.items())),
        "reverse_edges": dict(sorted(sub_reverse.items())),
    }


def _dot_for(graph: dict, admin_nodes: set[str]) -> str:
    lines = [
        "digraph admin_coupling {",
        "  rankdir=LR;",
        '  node [shape=box, fontname="Helvetica"];',
    ]
    ids: dict[str, str] = {}
    for i, name in enumerate(sorted(graph["edges"].keys()) + [n for n in graph.get("reverse_edges", {}) if n not in graph["edges"]]):
        if name in ids:
            continue
        nid = f"n{i}"
        ids[name] = nid
        if name in admin_nodes:
            lines.append(f'  {nid} [label="{name}", style=filled, fillcolor=lightyellow];')
        else:
            lines.append(f'  {nid} [label="{name}"];')
    for src, dests in graph["edges"].items():
        for dst in dests:
            if dst in ids:
                lines.append(f"  {ids[src]} -> {ids[dst]};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _mmd_for(graph: dict, admin_nodes: set[str]) -> str:
    lines = ["graph LR"]
    ids: dict[str, str] = {}
    nodes = list(graph["edges"].keys()) + [n for n in graph.get("reverse_edges", {}) if n not in graph["edges"]]
    for i, name in enumerate(sorted(set(nodes))):
        nid = f"n{i}"
        ids[name] = nid
        marker = ":::admin" if name in admin_nodes else ""
        lines.append(f'  {nid}["{name}"]{marker}')
    for src, dests in graph["edges"].items():
        for dst in dests:
            if dst in ids:
                lines.append(f"  {ids[src]} --> {ids[dst]}")
    lines.append("classDef admin fill:#ffeaa7,stroke:#fdcb6e;")
    return "\n".join(lines) + "\n"


def write_admin_coupling(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    payload = build_admin_coupling(cfg)
    json_path = cfg.output_dir / "admin_coupling.json"
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    admin_set = set(payload["admin_nodes"])
    dot_path = cfg.output_dir / "admin_coupling.dot"
    mmd_path = cfg.output_dir / "admin_coupling.mmd"
    dot_path.write_text(_dot_for(payload, admin_set), encoding="utf-8")
    mmd_path.write_text(_mmd_for(payload, admin_set), encoding="utf-8")
    write_manifest(cfg, extras={"producer": "admin_coupling"})
    return json_path
