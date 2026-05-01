"""Flag inventory: find bool / Optional[bool] kwargs across the SDK.

These are the most common form of feature flag. For each one we record:
- where it's defined (function qualname + file:lineno)
- annotation (if any)
- default value
- count of call sites passing this kwarg by name

Call-site count is approximated by scanning all source for keyword
arguments with the matching name; this overcounts shadowed names but is
good enough for "is this flag still load-bearing?" judgments.
"""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass, asdict
from pathlib import Path

from .config import IntrospectConfig
from .manifest import write_manifest


@dataclass
class Flag:
    function_qualname: str
    kwarg_name: str
    annotation: str | None
    default: str | None
    file: str
    lineno: int
    call_site_count: int = 0


def _is_bool_annotation(node: ast.expr | None) -> bool:
    """True if the annotation looks like bool / bool | None / Optional[bool]."""
    if node is None:
        return False
    src = _try_unparse(node)
    if src is None:
        return False
    s = src.replace(" ", "")
    if s == "bool":
        return True
    if s in ("bool|None", "None|bool", "Optional[bool]", "bool|None=False"):
        return True
    if s.startswith("Optional[") and s.endswith("]") and "bool" in s:
        return True
    if "|" in s and "bool" in s and "None" in s:
        return True
    return False


def _is_bool_default(node: ast.expr | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return True
    # `None` default is acceptable when we're tracking kwargs that include None as off-switch
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    return False


def _try_unparse(node: ast.expr | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return None


def _module_qualname(path: Path, repo_root: Path) -> str:
    rel = path.relative_to(repo_root).with_suffix("")
    parts = rel.parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _iter_py_files(cfg: IntrospectConfig):
    for root in cfg.source_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


def _walk_for_flags(tree: ast.Module, module_qn: str, file_rel: str) -> list[Flag]:
    out: list[Flag] = []

    def visit(node: ast.AST, parent_qn: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qn = f"{parent_qn}.{child.name}"
                # Iterate args + kwonlyargs and pair with defaults.
                # ast.arguments: posonlyargs + args + kwonlyargs.
                # defaults applies to (posonlyargs + args)[-len(defaults):].
                # kw_defaults is parallel to kwonlyargs (None means no default).
                normal_args = list(child.args.posonlyargs) + list(child.args.args)
                defaults = list(child.args.defaults)
                # Pad defaults from the right.
                pad = [None] * (len(normal_args) - len(defaults))
                paired: list[tuple[ast.arg, ast.expr | None]] = list(zip(normal_args, pad + defaults))
                for arg, dflt in paired:
                    if _is_bool_annotation(arg.annotation) or (
                        arg.annotation is None and _is_bool_default(dflt)
                    ):
                        if dflt is None and arg.annotation is None:
                            continue  # untyped, undefaulted
                        out.append(
                            Flag(
                                function_qualname=qn,
                                kwarg_name=arg.arg,
                                annotation=_try_unparse(arg.annotation),
                                default=_try_unparse(dflt),
                                file=file_rel,
                                lineno=arg.lineno or child.lineno,
                            )
                        )
                # kwonly
                for arg, dflt in zip(child.args.kwonlyargs, child.args.kw_defaults):
                    if _is_bool_annotation(arg.annotation) or _is_bool_default(dflt):
                        out.append(
                            Flag(
                                function_qualname=qn,
                                kwarg_name=arg.arg,
                                annotation=_try_unparse(arg.annotation),
                                default=_try_unparse(dflt),
                                file=file_rel,
                                lineno=arg.lineno or child.lineno,
                            )
                        )
                visit(child, qn)
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{parent_qn}.{child.name}")

    visit(tree, module_qn)
    return out


def _count_call_sites_by_name(cfg: IntrospectConfig, kwarg_name: str) -> int:
    """Count Call expressions across the source tree that pass ``kwarg_name=...``."""
    count = 0
    for path in _iter_py_files(cfg):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == kwarg_name:
                        count += 1
                        break
    return count


def build_flag_inventory(cfg: IntrospectConfig) -> dict:
    flags: list[Flag] = []
    for path in _iter_py_files(cfg):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        module_qn = _module_qualname(path, cfg.repo_root)
        rel = path.relative_to(cfg.repo_root).as_posix()
        flags.extend(_walk_for_flags(tree, module_qn, rel))

    # Count call sites per UNIQUE kwarg name (cheap caching).
    counts: dict[str, int] = {}
    for f in flags:
        if f.kwarg_name not in counts:
            counts[f.kwarg_name] = _count_call_sites_by_name(cfg, f.kwarg_name)
        f.call_site_count = counts[f.kwarg_name]

    flags.sort(key=lambda f: (f.function_qualname, f.kwarg_name))
    return {"flags": [asdict(f) for f in flags]}


def write_flag_inventory(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    out = cfg.output_dir / "flag_inventory.json"
    payload = build_flag_inventory(cfg)
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(cfg, extras={"producer": "flag_inventory"})
    return out
