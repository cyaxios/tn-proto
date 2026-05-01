"""Introspect configuration for tn-protocol.

Repo layout this targets:

    tn-protocol/
        python/
            tn/                 <- SDK (primary scan target)
            tools/              <- helpers (scanned, but tools/introspect/ is excluded)
            scripts/            <- CLIs (scanned)
            tests/              <- scanned for call-site reference only (phantom_regrounding)
        crypto/
            tn-core/src/        <- Rust surface scan target
            tn-btn/src/         <- Rust surface scan target
            tn-proto-py/src/    <- Rust surface scan target (pyo3 bindings)
        docs/audit-baseline/    <- artifact output dir
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IntrospectConfig:
    """Configuration for an introspection run."""

    # Repo root (the tn-protocol/ directory).
    repo_root: Path

    # Python source directories to walk.
    source_roots: tuple[Path, ...]

    # Test directories — scanned for reference counts only, not symbol inventory.
    test_roots: tuple[Path, ...]

    # Rust crate src/ directories for surface inventory.
    rust_roots: tuple[Path, ...]

    # Output directory for artifacts.
    output_dir: Path

    # Directories to skip entirely (any path component match).
    skip_dirs: frozenset[str] = frozenset(
        {
            ".venv", "venv", "__pycache__", "node_modules", ".git",
            ".pytest_cache", ".mypy_cache", ".ruff_cache",
            "dist", "build", "target", "egg-info",
            # tn-protocol-specific runtime dirs:
            ".tn_admin", ".tn_logs", "vault_blobs", "logs",
            "tn_protocol.egg-info", "stage-personas-workspace",
            # Don't scan our own output dir:
            "audit-baseline",
            # Don't scan vendored tooling that isn't part of the surface:
            "tn_annotate",
        }
    )

    # File globs to skip.
    skip_globs: tuple[str, ...] = (
        "*.pyc", "*.pyo", "*.egg-info", "__pycache__",
    )


def _detect_repo_root() -> Path:
    """Find the tn-protocol/ directory containing this tools package.

    `tools/introspect/config.py` -> tools/introspect -> tools -> python -> tn-protocol
    """
    here = Path(__file__).resolve()
    # parents[0]=introspect, [1]=tools, [2]=python, [3]=tn-protocol
    return here.parents[3]


def default_config() -> IntrospectConfig:
    """Default config: scans tn-protocol/python/tn + tools + scripts;
    Rust crates under tn-protocol/crypto; outputs to docs/audit-baseline/.
    """
    root = _detect_repo_root()
    py = root / "python"
    return IntrospectConfig(
        repo_root=root,
        source_roots=(
            py / "tn",
            py / "tools",
            py / "scripts",
        ),
        test_roots=(py / "tests",),
        rust_roots=(
            root / "crypto" / "tn-core" / "src",
            root / "crypto" / "tn-btn" / "src",
            root / "crypto" / "tn-proto-py" / "src",
        ),
        output_dir=root / "docs" / "audit-baseline",
    )
