"""Mermaid → SVG / PNG via mmdc, and DOT → SVG via Graphviz dot.

If neither tool is available we silently skip — the .mmd/.dot source
files are still produced and renderable on demand.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class RendererUnavailable(RuntimeError):
    pass


def render_mmd_to_svg(mmd_path: Path, svg_path: Path) -> None:
    npx = shutil.which("npx")
    if npx is None:
        raise RendererUnavailable("npx not on PATH; cannot invoke mmdc")
    try:
        subprocess.run(
            [npx, "--yes", "@mermaid-js/mermaid-cli",
             "-i", str(mmd_path), "-o", str(svg_path)],
            check=True,
            capture_output=True,
            timeout=180,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        msg = getattr(exc, "stderr", b"") or b""
        raise RendererUnavailable(
            f"mmdc failed: {msg.decode('utf-8', errors='replace') if isinstance(msg, bytes) else msg}"
        ) from exc


def render_dot_to_svg(dot_path: Path, svg_path: Path) -> None:
    dot = shutil.which("dot")
    if dot is None:
        raise RendererUnavailable("graphviz `dot` not on PATH")
    try:
        subprocess.run(
            [dot, "-Tsvg", str(dot_path), "-o", str(svg_path)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        msg = getattr(exc, "stderr", b"") or b""
        raise RendererUnavailable(
            f"dot failed: {msg.decode('utf-8', errors='replace') if isinstance(msg, bytes) else msg}"
        ) from exc


def render_dot_to_png(dot_path: Path, png_path: Path) -> None:
    dot = shutil.which("dot")
    if dot is None:
        raise RendererUnavailable("graphviz `dot` not on PATH")
    try:
        subprocess.run(
            [dot, "-Tpng", str(dot_path), "-o", str(png_path)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        msg = getattr(exc, "stderr", b"") or b""
        raise RendererUnavailable(
            f"dot failed: {msg.decode('utf-8', errors='replace') if isinstance(msg, bytes) else msg}"
        ) from exc
