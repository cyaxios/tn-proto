#!/usr/bin/env python3
"""Code-health report for the tn-proto source tree.

Scans the first-party source across all three language surfaces:

    python/tn/**.py
    ts-sdk/src/**.ts
    ts-sdk/bin/**.mjs
    crypto/*/src/**.rs

and reports, worst-first:

    * lines of code per file
    * the longest function in each file (brace/indent heuristic per language)
    * (Python only) radon cyclomatic complexity, reusing the same radon
      tooling the "complexity budget" CI job already depends on

It prints a human-readable table to stdout and, with ``--json PATH`` (or
``--json -`` for stdout), emits the same data as machine-readable JSON for
the ratchet check and any other downstream tooling.

This script is intentionally dependency-light: only ``radon`` is required,
and only for the Python complexity column. If radon is missing the report
still runs and the complexity column reads ``n/a``.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Repo root = parent of this script's directory (scripts/ lives at the root).
ROOT = Path(__file__).resolve().parent.parent

# Directory names that are never first-party source. Matched against any
# path component so they prune anywhere in the tree.
EXCLUDED_DIR_NAMES = {
    ".venv",
    "node_modules",
    "pkg",
    "pkg-web",
    "target",
    "__pycache__",
    "dist",
    ".worktrees",
    "tests",
    "test",
    "__tests__",
    ".git",
}

# (glob, language) pairs, anchored at ROOT.
SCAN_GLOBS: list[tuple[str, str]] = [
    ("python/tn/**/*.py", "python"),
    ("ts-sdk/src/**/*.ts", "ts"),
    ("ts-sdk/bin/**/*.mjs", "mjs"),
    ("crypto/*/src/**/*.rs", "rust"),
]


@dataclass
class FileReport:
    path: str  # repo-relative, forward-slashed
    language: str
    loc: int  # non-blank, non-comment lines
    raw_lines: int  # total physical lines (the ratchet budget unit)
    longest_function: str
    longest_function_lines: int
    max_cc: int | None = None  # radon cyclomatic complexity (python only)
    max_cc_symbol: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "language": self.language,
            "loc": self.loc,
            "raw_lines": self.raw_lines,
            "longest_function": self.longest_function,
            "longest_function_lines": self.longest_function_lines,
            "max_cc": self.max_cc,
            "max_cc_symbol": self.max_cc_symbol,
        }


# --- comment stripping (cheap, per-language) ----------------------------------

_LINE_COMMENT = {
    "python": "#",
    "ts": "//",
    "mjs": "//",
    "rust": "//",
}


def _count_loc(text: str, language: str) -> tuple[int, int]:
    """Return (loc, raw_lines).

    raw_lines is the physical line count (the unit the ratchet budgets on,
    matching ``wc -l`` intuition). loc strips blank lines and pure
    line-comment lines for the "real" code measure shown in the table.
    """
    lines = text.splitlines()
    raw = len(lines)
    marker = _LINE_COMMENT.get(language, "#")
    loc = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(marker):
            continue
        loc += 1
    return loc, raw


# --- longest-function heuristics ----------------------------------------------

_PY_DEF = re.compile(r"^(?P<indent>\s*)(async\s+)?def\s+(?P<name>\w+)\s*\(")


def _python_longest_function(text: str) -> tuple[str, int]:
    """Indent-based span: a def runs until a line at <= its indent appears."""
    lines = text.splitlines()
    best_name, best_len = "", 0
    i = 0
    n = len(lines)
    while i < n:
        m = _PY_DEF.match(lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group("indent"))
        name = m.group("name")
        j = i + 1
        last = i
        while j < n:
            line = lines[j]
            if line.strip() == "":
                j += 1
                continue
            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= indent:
                break
            last = j
            j += 1
        span = last - i + 1
        if span > best_len:
            best_len, best_name = span, name
        i += 1
    return best_name, best_len


_BRACE_FN = {
    "ts": re.compile(
        r"(?:function\s+(?P<n1>\w+)|"
        r"(?:public|private|protected|static|async|export|readonly|\s)*"
        r"(?P<n2>\w+)\s*(?:<[^>]*>)?\s*\([^;{]*\)\s*(?::[^={]+)?)\s*\{"
    ),
    "mjs": re.compile(
        r"(?:function\s+(?P<n1>\w+)|"
        r"(?:export\s+|async\s+)*(?P<n2>\w+)\s*\([^;{]*\)\s*)\{"
    ),
    "rust": re.compile(r"\bfn\s+(?P<n1>\w+)\s*(?:<[^>]*>)?\s*\("),
}


def _brace_longest_function(text: str, language: str) -> tuple[str, int]:
    """Brace-matched span for C-family languages (ts/mjs/rust)."""
    pat = _BRACE_FN[language]
    lines = text.splitlines()
    best_name, best_len = "", 0
    for idx, line in enumerate(lines):
        m = pat.search(line)
        if not m:
            continue
        name = m.groupdict().get("n1") or m.groupdict().get("n2") or "?"
        # Walk forward counting braces until balance returns to zero.
        depth = 0
        started = False
        end = idx
        for j in range(idx, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                end = j
                break
        else:
            end = len(lines) - 1
        span = end - idx + 1
        if span > best_len:
            best_len, best_name = span, name
    return best_name, best_len


def _longest_function(text: str, language: str) -> tuple[str, int]:
    if language == "python":
        return _python_longest_function(text)
    if language in _BRACE_FN:
        return _brace_longest_function(text, language)
    return "", 0


# --- radon cyclomatic complexity (python only) --------------------------------


def _radon_cc(py_paths: list[Path]) -> dict[str, tuple[int, str]]:
    """Map repo-relative path -> (max_cc, symbol) using radon.

    Returns an empty dict if radon is unavailable; callers degrade to n/a.
    """
    if not py_paths:
        return {}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "radon", "cc", "-j", *[str(p) for p in py_paths]],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            check=False,
        )
    except OSError:
        return {}
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    out: dict[str, tuple[int, str]] = {}
    for raw_path, blocks in data.items():
        if not isinstance(blocks, list):
            continue
        rel = _rel(Path(raw_path))
        best_cc, best_sym = -1, ""
        for b in blocks:
            cc = b.get("complexity")
            if cc is None:
                continue
            if cc > best_cc:
                best_cc = cc
                best_sym = b.get("name", "")
        if best_cc >= 0:
            out[rel] = (best_cc, best_sym)
    return out


# --- scanning -----------------------------------------------------------------


def _rel(path: Path) -> str:
    try:
        rel = path.resolve().relative_to(ROOT)
    except ValueError:
        rel = path
    return str(rel).replace("\\", "/")


def _is_excluded(path: Path) -> bool:
    return any(part in EXCLUDED_DIR_NAMES for part in path.parts)


def discover_files() -> list[tuple[Path, str]]:
    seen: dict[Path, str] = {}
    for glob, language in SCAN_GLOBS:
        for path in ROOT.glob(glob):
            if not path.is_file():
                continue
            rel = path.resolve().relative_to(ROOT)
            if _is_excluded(rel):
                continue
            # .d.ts are generated type stubs, not hand-written source.
            if path.name.endswith(".d.ts"):
                continue
            seen.setdefault(path.resolve(), language)
    return sorted(seen.items(), key=lambda kv: str(kv[0]))


def build_reports() -> list[FileReport]:
    files = discover_files()
    py_paths = [p for p, lang in files if lang == "python"]
    cc_map = _radon_cc(py_paths)

    reports: list[FileReport] = []
    for path, language in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        loc, raw = _count_loc(text, language)
        fn_name, fn_len = _longest_function(text, language)
        rel = _rel(path)
        max_cc, max_cc_symbol = None, None
        if language == "python":
            entry = cc_map.get(rel)
            if entry is not None:
                max_cc, max_cc_symbol = entry
        reports.append(
            FileReport(
                path=rel,
                language=language,
                loc=loc,
                raw_lines=raw,
                longest_function=fn_name,
                longest_function_lines=fn_len,
                max_cc=max_cc,
                max_cc_symbol=max_cc_symbol,
            )
        )
    return reports


# --- rendering ----------------------------------------------------------------


def render_table(reports: list[FileReport], top: int | None) -> str:
    by_lines = sorted(reports, key=lambda r: r.raw_lines, reverse=True)
    if top:
        by_lines = by_lines[:top]

    rows = []
    header = ("LINES", "LOC", "LANG", "LONGEST FN", "FN-LOC", "CC", "FILE")
    rows.append(header)
    for r in by_lines:
        cc = "n/a" if r.max_cc is None else str(r.max_cc)
        fn = r.longest_function or "-"
        if len(fn) > 28:
            fn = fn[:25] + "..."
        rows.append(
            (
                str(r.raw_lines),
                str(r.loc),
                r.language,
                fn,
                str(r.longest_function_lines),
                cc,
                r.path,
            )
        )

    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines = []
    for ri, row in enumerate(rows):
        cells = [row[i].ljust(widths[i]) for i in range(len(header))]
        lines.append("  ".join(cells).rstrip())
        if ri == 0:
            lines.append("  ".join("-" * widths[i] for i in range(len(header))))

    total_lines = sum(r.raw_lines for r in reports)
    summary = (
        f"\nScanned {len(reports)} files, {total_lines} total lines "
        f"({len([r for r in reports if r.raw_lines >= 800])} file(s) >= 800 lines)."
    )
    return "\n".join(lines) + "\n" + summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="write machine-readable JSON to PATH ('-' for stdout)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=30,
        help="show only the worst N files in the table (default 30; 0 = all)",
    )
    parser.add_argument(
        "--no-table",
        action="store_true",
        help="suppress the human table (useful with --json -)",
    )
    args = parser.parse_args(argv)

    reports = build_reports()

    if args.json:
        payload = {
            "root": str(ROOT).replace("\\", "/"),
            "files": [r.to_dict() for r in sorted(
                reports, key=lambda r: r.raw_lines, reverse=True
            )],
        }
        text = json.dumps(payload, indent=2)
        if args.json == "-":
            print(text)
        else:
            out_path = Path(args.json)
            out_path.write_text(text + "\n", encoding="utf-8")
            print(f"Wrote JSON report to {out_path}", file=sys.stderr)

    if not args.no_table:
        top = None if args.top == 0 else args.top
        print(render_table(reports, top))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
