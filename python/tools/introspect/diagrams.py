"""Wrapper around pyreverse to generate class and package Mermaid diagrams."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .config import IntrospectConfig
from .manifest import write_manifest


def _pyreverse_cmd() -> list[str]:
    exe = shutil.which("pyreverse")
    if exe:
        return [exe]
    return [sys.executable, "-m", "pylint.pyreverse.main"]


def write_diagrams(cfg: IntrospectConfig, project_name: str = "tn") -> tuple[Path, Path]:
    """Generate classes.mmd and packages.mmd in cfg.output_dir.

    Targets the first source root (typically tn/). Returns paths even if
    pyreverse failed (caller handles missing files).
    """
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    primary = cfg.source_roots[0]

    cmd = [
        *_pyreverse_cmd(),
        "-o", "mmd",
        "-p", project_name,
        str(primary),
    ]
    try:
        subprocess.run(
            cmd,
            cwd=cfg.output_dir,
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        # Surface error to caller; pyreverse is optional.
        raise RuntimeError(f"pyreverse failed: {e}") from e

    classes = cfg.output_dir / f"classes_{project_name}.mmd"
    packages = cfg.output_dir / f"packages_{project_name}.mmd"
    canonical_classes = cfg.output_dir / "classes.mmd"
    canonical_packages = cfg.output_dir / "packages.mmd"
    if classes.exists():
        classes.replace(canonical_classes)
    if packages.exists():
        packages.replace(canonical_packages)
    write_manifest(cfg, extras={"producer": "diagrams", "project_name": project_name})
    return canonical_classes, canonical_packages
