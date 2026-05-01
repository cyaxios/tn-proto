"""Capture tn.yaml snapshots into a scenario's output dir.

Each scenario may call snapshot_yaml() multiple times — once per
matrix cell — with distinct suffixes.
"""

from __future__ import annotations

from pathlib import Path


def snapshot_yaml(src: Path, outdir: Path, suffix: str | None = None) -> Path:
    """Copy src YAML into outdir with a deterministic name.

    Returns the destination path. If src is missing, writes a stub so
    the outdir still documents the attempt.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    name = "tn.yaml.snapshot" if suffix is None else f"tn.yaml.{suffix}.snapshot"
    dst = outdir / name
    if src.is_file():
        dst.write_bytes(src.read_bytes())
    else:
        dst.write_text(f"# MISSING: source yaml not found at {src}\n")
    return dst
