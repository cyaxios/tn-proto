"""Environment-variable inventory.

Detects every `os.environ.get("X")`, `os.getenv("X")`, `os.environ["X"]`,
and `os.environ.setdefault("X", ...)` site in the source tree, captures
the literal name, the call-site, and any literal default.

Bonus: reports any string literal anywhere in source matching `TN_*`,
`CP_TN_*`, or `ATPROTO_*` patterns so we don't miss exotic access paths
(e.g. shell scripts that get cat'd into Python).
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path

from .config import IntrospectConfig
from .manifest import write_manifest


@dataclass
class EnvVarHit:
    file: str
    lineno: int
    accessor: str  # 'os.environ.get' / 'os.getenv' / 'os.environ[]' / 'os.environ.setdefault' / 'literal-only'
    default: str | None  # repr of the default expression, if any


@dataclass
class EnvVar:
    name: str
    call_sites: list[dict] = field(default_factory=list)
    default: str | None = None  # last-seen literal default; None if no default observed
    accessors: list[str] = field(default_factory=list)


def _literal_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_os_environ_get(node: ast.Call) -> bool:
    """os.environ.get(...) — ast.Attribute over (Attribute(Name(os), 'environ'), 'get')."""
    f = node.func
    if not isinstance(f, ast.Attribute) or f.attr != "get":
        return False
    if not isinstance(f.value, ast.Attribute) or f.value.attr != "environ":
        return False
    base = f.value.value
    return isinstance(base, ast.Name) and base.id == "os"


def _is_os_environ_setdefault(node: ast.Call) -> bool:
    f = node.func
    if not isinstance(f, ast.Attribute) or f.attr != "setdefault":
        return False
    if not isinstance(f.value, ast.Attribute) or f.value.attr != "environ":
        return False
    base = f.value.value
    return isinstance(base, ast.Name) and base.id == "os"


def _is_os_getenv(node: ast.Call) -> bool:
    f = node.func
    if not isinstance(f, ast.Attribute) or f.attr != "getenv":
        return False
    base = f.value
    return isinstance(base, ast.Name) and base.id == "os"


def _is_environ_get(node: ast.Call) -> bool:
    """environ.get(...) — for `from os import environ`."""
    f = node.func
    if not isinstance(f, ast.Attribute) or f.attr != "get":
        return False
    base = f.value
    return isinstance(base, ast.Name) and base.id == "environ"


def _is_environ_subscript(node: ast.Subscript) -> bool:
    """os.environ["X"] / environ["X"]."""
    val = node.value
    if isinstance(val, ast.Attribute) and val.attr == "environ":
        base = val.value
        return isinstance(base, ast.Name) and base.id == "os"
    if isinstance(val, ast.Name) and val.id == "environ":
        return True
    return False


def _format_default(node: ast.expr | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return None


def _iter_py_files(cfg: IntrospectConfig):
    for root in cfg.source_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


# Regex for catching env-var names in any string literal that looks like one.
_ENV_NAME_RE = re.compile(r"\b(TN_[A-Z0-9_]+|CP_TN_[A-Z0-9_]+|ATPROTO_[A-Z0-9_]+)\b")


def build_env_vars(cfg: IntrospectConfig) -> dict:
    by_name: dict[str, EnvVar] = {}

    def _record(name: str, file: str, lineno: int, accessor: str, default: str | None) -> None:
        ev = by_name.setdefault(name, EnvVar(name=name))
        ev.call_sites.append({"file": file, "lineno": lineno, "accessor": accessor, "default": default})
        if accessor not in ev.accessors:
            ev.accessors.append(accessor)
        if default is not None and ev.default is None:
            ev.default = default

    for path in _iter_py_files(cfg):
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = path.relative_to(cfg.repo_root).as_posix()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                accessor = None
                args = node.args
                default_node: ast.expr | None = None
                if not args:
                    continue
                name_lit = _literal_string(args[0])
                if name_lit is None:
                    continue

                if _is_os_environ_get(node):
                    accessor = "os.environ.get"
                    default_node = args[1] if len(args) > 1 else None
                    if default_node is None:
                        for kw in node.keywords:
                            if kw.arg in ("default",):
                                default_node = kw.value
                elif _is_os_getenv(node):
                    accessor = "os.getenv"
                    default_node = args[1] if len(args) > 1 else None
                elif _is_environ_get(node):
                    accessor = "environ.get"
                    default_node = args[1] if len(args) > 1 else None
                elif _is_os_environ_setdefault(node):
                    accessor = "os.environ.setdefault"
                    default_node = args[1] if len(args) > 1 else None

                if accessor is None:
                    continue
                _record(
                    name_lit,
                    rel,
                    node.lineno,
                    accessor,
                    _format_default(default_node),
                )

            elif isinstance(node, ast.Subscript) and _is_environ_subscript(node):
                # os.environ["X"]
                key = node.slice if not isinstance(node.slice, ast.Index) else node.slice.value  # type: ignore[attr-defined]
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    _record(
                        key.value,
                        rel,
                        node.lineno,
                        "os.environ[]",
                        None,
                    )

        # Pattern-match any string literal mentioning a TN_* / CP_TN_* / ATPROTO_* name we didn't already see.
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for m in _ENV_NAME_RE.findall(node.value):
                    if m not in by_name:
                        # Pure literal mention, no accessor binding observed.
                        _record(m, rel, node.lineno, "literal-only", None)

    items = sorted(by_name.values(), key=lambda e: e.name)
    return {"env_vars": [asdict(e) for e in items]}


def write_env_vars(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    out = cfg.output_dir / "env_vars.json"
    payload = build_env_vars(cfg)
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(cfg, extras={"producer": "env_vars"})
    return out
