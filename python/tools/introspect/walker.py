"""AST-based symbol inventory builder.

Walks every Python file under the configured source roots and produces a
list of Symbol records: functions, async functions, and classes. Nested
classes and methods are captured with dotted qualnames.
"""
from __future__ import annotations

import ast
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import IntrospectConfig
from .manifest import write_manifest


@dataclass
class Symbol:
    """A single top-level or nested function/class."""

    kind: str  # "function", "async_function", "class"
    name: str
    qualname: str  # dotted path: module.Class.method
    file: str  # repo-relative path (POSIX)
    lineno: int
    signature: str
    docstring: str | None
    decorators: list[str] = field(default_factory=list)
    is_public: bool = True  # not name-mangled, no leading underscore
    in_all: bool | None = None  # True if module declares __all__ and this name is in it; False if declared and not in; None if no __all__


def _module_qualname(path: Path, repo_root: Path) -> str:
    rel = path.relative_to(repo_root).with_suffix("")
    parts = rel.parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _format_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = []
    for arg in node.args.args:
        if arg.annotation is not None:
            args.append(f"{arg.arg}: {ast.unparse(arg.annotation)}")
        else:
            args.append(arg.arg)
    if node.args.vararg:
        args.append(f"*{node.args.vararg.arg}")
    for arg in node.args.kwonlyargs:
        if arg.annotation is not None:
            args.append(f"{arg.arg}: {ast.unparse(arg.annotation)}")
        else:
            args.append(arg.arg)
    if node.args.kwarg:
        args.append(f"**{node.args.kwarg.arg}")
    ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    return f"{node.name}({', '.join(args)}){ret}"


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    try:
        return ast.unparse(node)
    except Exception:
        return "<decorator>"


def _extract_all(tree: ast.Module) -> set[str] | None:
    """If module declares __all__ as a list/tuple of string literals, return that set."""
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    out = set()
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            out.add(elt.value)
                    return out
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "__all__":
            if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                out = set()
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        out.add(elt.value)
                return out
    return None


def _walk_module(tree: ast.Module, module_qn: str, file_rel: str) -> list[Symbol]:
    out: list[Symbol] = []
    all_set = _extract_all(tree)

    def visit(node: ast.AST, parent_qn: str, depth: int) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qn = f"{parent_qn}.{child.name}"
                kind = "async_function" if isinstance(child, ast.AsyncFunctionDef) else "function"
                is_public = not child.name.startswith("_")
                in_all = (child.name in all_set) if (all_set is not None and depth == 0) else None
                out.append(
                    Symbol(
                        kind=kind,
                        name=child.name,
                        qualname=qn,
                        file=file_rel,
                        lineno=child.lineno,
                        signature=_format_signature(child),
                        docstring=ast.get_docstring(child),
                        decorators=[_decorator_name(d) for d in child.decorator_list],
                        is_public=is_public,
                        in_all=in_all,
                    )
                )
                visit(child, qn, depth + 1)
            elif isinstance(child, ast.ClassDef):
                qn = f"{parent_qn}.{child.name}"
                is_public = not child.name.startswith("_")
                in_all = (child.name in all_set) if (all_set is not None and depth == 0) else None
                out.append(
                    Symbol(
                        kind="class",
                        name=child.name,
                        qualname=qn,
                        file=file_rel,
                        lineno=child.lineno,
                        signature=f"class {child.name}",
                        docstring=ast.get_docstring(child),
                        decorators=[_decorator_name(d) for d in child.decorator_list],
                        is_public=is_public,
                        in_all=in_all,
                    )
                )
                visit(child, qn, depth + 1)

    visit(tree, module_qn, 0)
    return out


def _iter_py_files(cfg: IntrospectConfig):
    for root in cfg.source_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


def walk_symbols(cfg: IntrospectConfig) -> list[Symbol]:
    symbols: list[Symbol] = []
    for path in _iter_py_files(cfg):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        module_qn = _module_qualname(path, cfg.repo_root)
        rel = path.relative_to(cfg.repo_root).as_posix()
        symbols.extend(_walk_module(tree, module_qn, rel))
    symbols.sort(key=lambda s: (s.qualname, s.lineno))
    return symbols


def write_symbols_json(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    symbols = walk_symbols(cfg)
    payload = {"symbols": [asdict(s) for s in symbols]}
    path = cfg.output_dir / "surface_inventory.json"
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(cfg, extras={"producer": "walker"})
    return path
