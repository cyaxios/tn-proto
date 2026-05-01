"""Rust public-surface inventory (regex-based).

Walks every .rs file under the configured rust_roots and records:
- pub fn / pub async fn
- pub struct / pub enum / pub trait
- pub const / pub static
- #[pymodule] / #[pyfunction] / #[pyclass] / #[pymethods]
- visibility-restricted public items: pub(crate), pub(super), etc.

This is regex-based by design — we don't need cargo to compile, and
syn/proc-macro analysis would be major scope creep. Good enough for
"what's the public API surface of this Rust crate".
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path

from .config import IntrospectConfig
from .manifest import write_manifest


@dataclass
class RustItem:
    kind: str  # 'fn' / 'async_fn' / 'struct' / 'enum' / 'trait' / 'const' / 'static' / 'pyfunction' / 'pyclass' / 'pymodule' / 'pymethods'
    name: str
    visibility: str  # 'pub' / 'pub(crate)' / 'pub(super)' / 'pub(in path)'
    file: str
    lineno: int
    crate: str  # tn-core / tn-btn / tn-proto-py
    decorator: str | None = None  # raw attribute line if relevant (#[pyfunction] etc.)


_PUB_VIS = r"pub(?:\(\s*(?:crate|super|in\s+[a-zA-Z0-9_:]+)\s*\))?"

# Order: longer attribute names first so we match #[pymethods] etc. before #[pymodule].
_ATTR_RE = re.compile(
    r"^\s*(#\[\s*(?:pyo3::)?(?P<attr>pymodule|pyfunction|pyclass|pymethods|pyo3)\b[^\]]*\])",
    re.MULTILINE,
)

# Item declarations
_FN_RE = re.compile(
    rf"^\s*(?P<vis>{_PUB_VIS})\s+(?P<async_>async\s+)?fn\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)",
    re.MULTILINE,
)
_STRUCT_RE = re.compile(
    rf"^\s*(?P<vis>{_PUB_VIS})\s+struct\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)",
    re.MULTILINE,
)
_ENUM_RE = re.compile(
    rf"^\s*(?P<vis>{_PUB_VIS})\s+enum\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)",
    re.MULTILINE,
)
_TRAIT_RE = re.compile(
    rf"^\s*(?P<vis>{_PUB_VIS})\s+trait\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)",
    re.MULTILINE,
)
_CONST_RE = re.compile(
    rf"^\s*(?P<vis>{_PUB_VIS})\s+const\s+(?P<name>[A-Z_][A-Z0-9_]*)",
    re.MULTILINE,
)
_STATIC_RE = re.compile(
    rf"^\s*(?P<vis>{_PUB_VIS})\s+static\s+(?P<name>[A-Z_][A-Z0-9_]*)",
    re.MULTILINE,
)


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _crate_for(path: Path, cfg: IntrospectConfig) -> str:
    """Determine which crate the file belongs to."""
    parts = path.relative_to(cfg.repo_root).as_posix().split("/")
    # tn-protocol/crypto/<crate>/src/<file>
    if len(parts) >= 3 and parts[0] == "crypto":
        return parts[1]
    return parts[1] if len(parts) > 1 else "?"


def _scan_file(path: Path, cfg: IntrospectConfig) -> list[RustItem]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    rel = path.relative_to(cfg.repo_root).as_posix()
    crate = _crate_for(path, cfg)

    out: list[RustItem] = []

    # Pyo3 attributes first — capture the line they're on.
    for m in _ATTR_RE.finditer(text):
        attr = m.group("attr")
        # Skip generic 'pyo3' attribute lines (they're rename hints, not items).
        if attr == "pyo3":
            continue
        kind_map = {
            "pymodule": "pymodule",
            "pyfunction": "pyfunction",
            "pyclass": "pyclass",
            "pymethods": "pymethods",
        }
        out.append(
            RustItem(
                kind=kind_map[attr],
                name=f"<{attr}>",
                visibility="pub",  # they're effectively public surface even if Rust visibility differs
                file=rel,
                lineno=_line_no(text, m.start()),
                crate=crate,
                decorator=m.group(0).strip(),
            )
        )

    for kind, regex in [
        ("fn", _FN_RE),
        ("struct", _STRUCT_RE),
        ("enum", _ENUM_RE),
        ("trait", _TRAIT_RE),
        ("const", _CONST_RE),
        ("static", _STATIC_RE),
    ]:
        for m in regex.finditer(text):
            name = m.group("name")
            vis = m.group("vis").strip()
            real_kind = kind
            if kind == "fn" and m.groupdict().get("async_"):
                real_kind = "async_fn"
            out.append(
                RustItem(
                    kind=real_kind,
                    name=name,
                    visibility=vis,
                    file=rel,
                    lineno=_line_no(text, m.start()),
                    crate=crate,
                )
            )
    return out


def build_rust_surface(cfg: IntrospectConfig) -> dict:
    items: list[RustItem] = []
    files_visited = 0
    rust_loc = 0

    for root in cfg.rust_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.rs")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            files_visited += 1
            try:
                rust_loc += sum(1 for _ in path.read_text(encoding="utf-8").splitlines())
            except (OSError, UnicodeDecodeError):
                pass
            items.extend(_scan_file(path, cfg))

    items.sort(key=lambda i: (i.crate, i.file, i.lineno, i.name))
    return {
        "files_visited": files_visited,
        "rust_loc": rust_loc,
        "items": [asdict(i) for i in items],
    }


def write_rust_surface(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    payload = build_rust_surface(cfg)
    out = cfg.output_dir / "rust_surface.json"
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(cfg, extras={"producer": "rust_surface"})
    return out
