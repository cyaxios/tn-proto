"""Source-hash manifest for staleness detection."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .config import IntrospectConfig


def _iter_source_files(cfg: IntrospectConfig):
    for root in cfg.source_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in cfg.skip_dirs for part in path.parts):
                continue
            yield path


def compute_source_hashes(cfg: IntrospectConfig) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in _iter_source_files(cfg):
        rel = path.relative_to(cfg.repo_root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hashes[rel] = digest
    return dict(sorted(hashes.items()))


def write_manifest(cfg: IntrospectConfig, extras: dict[str, Any] | None = None) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "source_hashes": compute_source_hashes(cfg),
        "extras": extras or {},
    }
    path = cfg.output_dir / "MANIFEST.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def read_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def is_stale(cfg: IntrospectConfig) -> bool:
    manifest_path = cfg.output_dir / "MANIFEST.json"
    if not manifest_path.exists():
        return True
    on_disk = read_manifest(manifest_path).get("source_hashes", {})
    return on_disk != compute_source_hashes(cfg)
