"""Coverage manifest — proof that every file under source_roots was visited.

Produces `coverage_manifest.json`:
- list of every Python file walked (path, sha256, LOC, AST node count)
- list of every Rust file walked (path, sha256, LOC)
- totals reconcilable with `find ... | wc -l` so no file slipped through
- list of Python files that FAILED to parse (SyntaxError) — the only
  legitimate reason a file would not contribute to surface_inventory
"""
from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, asdict
from pathlib import Path

from .config import IntrospectConfig


@dataclass
class FileRecord:
    path: str
    sha256: str
    loc: int
    ast_node_count: int | None  # None for non-Python files


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _loc(path: Path) -> int:
    try:
        return sum(1 for _ in path.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError):
        return 0


def _ast_count(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return None
    return sum(1 for _ in ast.walk(tree))


def _iter_py_files(cfg: IntrospectConfig):
    for root in cfg.source_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


def _iter_rust_files(cfg: IntrospectConfig):
    for root in cfg.rust_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.rs")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


def build_coverage(cfg: IntrospectConfig) -> dict:
    py_records: list[FileRecord] = []
    rust_records: list[FileRecord] = []
    parse_failures: list[str] = []

    py_loc_total = 0
    py_ast_total = 0
    for path in _iter_py_files(cfg):
        rel = path.relative_to(cfg.repo_root).as_posix()
        loc = _loc(path)
        py_loc_total += loc
        ast_count = _ast_count(path)
        if ast_count is None:
            parse_failures.append(rel)
        else:
            py_ast_total += ast_count
        py_records.append(
            FileRecord(
                path=rel,
                sha256=_hash(path),
                loc=loc,
                ast_node_count=ast_count,
            )
        )

    rust_loc_total = 0
    for path in _iter_rust_files(cfg):
        rel = path.relative_to(cfg.repo_root).as_posix()
        loc = _loc(path)
        rust_loc_total += loc
        rust_records.append(
            FileRecord(
                path=rel,
                sha256=_hash(path),
                loc=loc,
                ast_node_count=None,
            )
        )

    py_records.sort(key=lambda r: r.path)
    rust_records.sort(key=lambda r: r.path)

    return {
        "files_visited": len(py_records),
        "rust_files_visited": len(rust_records),
        "python_loc": py_loc_total,
        "python_ast_nodes": py_ast_total,
        "rust_loc": rust_loc_total,
        "parse_failures": parse_failures,
        "python_files": [asdict(r) for r in py_records],
        "rust_files": [asdict(r) for r in rust_records],
    }


def write_coverage_manifest(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    payload = build_coverage(cfg)
    out = cfg.output_dir / "coverage_manifest.json"
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out
