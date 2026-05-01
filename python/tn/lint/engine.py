"""AST walker: discovers tn.<method>(...) calls and runs rules on them."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Iterator

from tn.lint.config import TN_METHODS, LintConfig
from tn.lint.findings import Finding
from tn.lint.rules import ALL_RULES, Rule, TNCall, TNKwarg


# --------------------------------------------------------------------------- #
# AST visitor
# --------------------------------------------------------------------------- #


def _is_tn_call(node: ast.Call) -> str | None:
    """If the call is ``tn.<method>(...)`` and method is in TN_METHODS,
    return the method name. Otherwise None."""
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    if not isinstance(func.value, ast.Name):
        return None
    if func.value.id != "tn":
        return None
    if func.attr not in TN_METHODS:
        return None
    return func.attr


def _extract_event_type(node: ast.Call) -> tuple[str | None, int, int]:
    """If the first positional arg is a str literal, return (value, line, col).
    Otherwise return (None, call.line, call.col)."""
    if node.args:
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value, first.lineno, first.col_offset + 1
    return None, node.lineno, node.col_offset + 1


def _extract_kwargs(node: ast.Call) -> tuple[TNKwarg, ...]:
    out: list[TNKwarg] = []
    for kw in node.keywords:
        if kw.arg is None:
            # **kwargs unpack -- can't statically check.
            continue
        # ast keywords don't always carry their own lineno on older versions,
        # but Python 3.8+ does. Fall back to the value's lineno.
        line = getattr(kw, "lineno", None) or kw.value.lineno
        col = (getattr(kw, "col_offset", None) or kw.value.col_offset) + 1
        out.append(TNKwarg(name=kw.arg, line=line, col=col))
    return tuple(out)


class _TNCallVisitor(ast.NodeVisitor):
    def __init__(self, file: str) -> None:
        self.file = file
        self.calls: list[TNCall] = []

    def visit_Call(self, node: ast.Call) -> None:
        method = _is_tn_call(node)
        if method is not None:
            event_lit, ev_line, ev_col = _extract_event_type(node)
            self.calls.append(
                TNCall(
                    file=self.file,
                    method=method,
                    line=node.lineno,
                    col=node.col_offset + 1,
                    event_type_literal=event_lit,
                    event_type_line=ev_line,
                    event_type_col=ev_col,
                    kwargs=_extract_kwargs(node),
                )
            )
        self.generic_visit(node)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def _iter_python_files(paths: Iterable[Path]) -> Iterator[Path]:
    seen: set[Path] = set()
    for raw in paths:
        p = raw.resolve()
        if p.is_file() and p.suffix == ".py":
            if p not in seen:
                seen.add(p)
                yield p
        elif p.is_dir():
            for sub in sorted(p.rglob("*.py")):
                rp = sub.resolve()
                if rp not in seen:
                    seen.add(rp)
                    yield rp


def lint_file(
    path: Path,
    cfg: LintConfig,
    rules: Iterable[Rule] = ALL_RULES,
    *,
    display_path: str | None = None,
) -> list[Finding]:
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:
        # Surface as a finding rather than crashing the whole run.
        return [
            Finding(
                file=display_path or str(path),
                line=exc.lineno or 1,
                col=(exc.offset or 1),
                rule="SYN",
                message=f"could not parse: {exc.msg}",
                severity="error",
            )
        ]

    visitor = _TNCallVisitor(file=display_path or str(path))
    visitor.visit(tree)

    findings: list[Finding] = []
    for call in visitor.calls:
        for rule in rules:
            findings.extend(rule.check(call, cfg))
    return findings


def lint_paths(
    paths: Iterable[Path],
    cfg: LintConfig,
    rules: Iterable[Rule] = ALL_RULES,
    *,
    relative_to: Path | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for f in _iter_python_files(paths):
        display: str
        if relative_to is not None:
            try:
                display = str(f.relative_to(relative_to.resolve()))
            except ValueError:
                display = str(f)
        else:
            display = str(f)
        findings.extend(lint_file(f, cfg, rules, display_path=display))
    findings.sort(key=Finding.sort_key)
    return findings
