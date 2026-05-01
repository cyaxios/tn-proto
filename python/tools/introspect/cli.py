"""CLI: python -m tools.introspect <command>."""
from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from .config import default_config
from .deps import write_deps_artifacts
from .diagrams import write_diagrams
from .extension_points import write_catalog
from .html_templates import (
    write_extension_points_html,
    write_symbols_html,
    write_env_vars_html,
    write_flag_inventory_html,
)
from .summarize import write_summary
from .walker import write_symbols_json
from .renderers import (
    render_dot_to_svg,
    render_dot_to_png,
    render_mmd_to_svg,
    RendererUnavailable,
)
from .env_vars import write_env_vars
from .flag_inventory import write_flag_inventory
from .phantom_regrounding import write_phantom_regrounding
from .rust_surface import write_rust_surface
from .admin_coupling import write_admin_coupling
from .coverage_manifest import write_coverage_manifest


def _run_step(name: str, fn) -> tuple[str, bool, str]:
    try:
        fn()
        return (name, True, "")
    except Exception as e:
        return (name, False, f"{type(e).__name__}: {e}\n{traceback.format_exc()}")


def _cmd_run_all(args: argparse.Namespace) -> int:
    cfg = default_config()
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    steps = [
        ("walker (surface_inventory)", lambda: write_symbols_json(cfg)),
        ("deps (import graph)", lambda: write_deps_artifacts(cfg)),
        ("extension_points", lambda: write_catalog(cfg)),
        ("env_vars", lambda: write_env_vars(cfg)),
        ("flag_inventory", lambda: write_flag_inventory(cfg)),
        ("phantom_regrounding", lambda: write_phantom_regrounding(cfg)),
        ("rust_surface", lambda: write_rust_surface(cfg)),
        ("admin_coupling", lambda: write_admin_coupling(cfg)),
        ("coverage_manifest", lambda: write_coverage_manifest(cfg)),
        ("symbols.html", lambda: write_symbols_html(cfg)),
        ("extension_points.html", lambda: write_extension_points_html(cfg)),
        ("env_vars.html", lambda: write_env_vars_html(cfg)),
        ("flag_inventory.html", lambda: write_flag_inventory_html(cfg)),
        ("summary.md", lambda: write_summary(cfg.output_dir)),
    ]
    if not args.skip_pyreverse:
        steps.append(("diagrams (pyreverse)", lambda: write_diagrams(cfg, project_name="tn")))

    results = []
    for name, fn in steps:
        result = _run_step(name, fn)
        results.append(result)
        ok, err = result[1], result[2]
        flag = "OK " if ok else "FAIL"
        print(f"  [{flag}] {name}")
        if not ok:
            # Print short error; full trace lands in the report
            short = err.split("\n", 1)[0]
            print(f"        {short}")

    # Render visualizations (best-effort).
    print()
    print("Rendering visualizations:")
    render_targets = [
        (cfg.output_dir / "deps.dot", cfg.output_dir / "deps.svg", render_dot_to_svg),
        (cfg.output_dir / "deps.dot", cfg.output_dir / "deps.png", render_dot_to_png),
        (cfg.output_dir / "admin_coupling.dot", cfg.output_dir / "admin_coupling.svg", render_dot_to_svg),
        (cfg.output_dir / "admin_coupling.dot", cfg.output_dir / "admin_coupling.png", render_dot_to_png),
        # Mermaid → SVG via mmdc; one entry per .mmd we expect to exist.
        (cfg.output_dir / "deps.mmd", cfg.output_dir / "deps_mermaid.svg", render_mmd_to_svg),
        (cfg.output_dir / "admin_coupling.mmd", cfg.output_dir / "admin_coupling_mermaid.svg", render_mmd_to_svg),
        (cfg.output_dir / "classes.mmd", cfg.output_dir / "classes.svg", render_mmd_to_svg),
        (cfg.output_dir / "packages.mmd", cfg.output_dir / "packages.svg", render_mmd_to_svg),
    ]
    for src, target, fn in render_targets:
        if not src.exists():
            print(f"  [SKIP] {target.name} (no source)")
            continue
        try:
            fn(src, target)
            print(f"  [OK ] {target.name}")
        except RendererUnavailable as exc:
            print(f"  [SKIP] {target.name} ({exc})")
        except Exception as exc:
            print(f"  [FAIL] {target.name} ({type(exc).__name__}: {exc})")

    # Save run report
    report_path = cfg.output_dir / "run_report.txt"
    lines = ["# Phase 0 introspect run report", ""]
    for name, ok, err in results:
        status = "OK" if ok else "FAIL"
        lines.append(f"[{status}] {name}")
        if err:
            lines.append("")
            for ln in err.splitlines():
                lines.append(f"    {ln}")
            lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nReport: {report_path}")
    print(f"Output: {cfg.output_dir}")
    return 0 if all(ok for _, ok, _ in results) else 1


def _cmd_summary(args: argparse.Namespace) -> int:
    cfg = default_config()
    out = write_summary(cfg.output_dir)
    print(out.read_text(encoding="utf-8"))
    return 0


def _cmd_paths(args: argparse.Namespace) -> int:
    cfg = default_config()
    print(f"repo_root: {cfg.repo_root}")
    print(f"source_roots:")
    for r in cfg.source_roots:
        marker = "  " if r.exists() else "? "
        print(f"  {marker}{r}")
    print(f"test_roots:")
    for r in cfg.test_roots:
        marker = "  " if r.exists() else "? "
        print(f"  {marker}{r}")
    print(f"rust_roots:")
    for r in cfg.rust_roots:
        marker = "  " if r.exists() else "? "
        print(f"  {marker}{r}")
    print(f"output_dir: {cfg.output_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m tools.introspect")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("run-all", help="Run every walker + render every artifact")
    sp.add_argument("--skip-pyreverse", action="store_true",
                    help="Skip pyreverse class/package diagrams (slow on large codebases)")
    sp.set_defaults(func=_cmd_run_all)

    sp = sub.add_parser("summary", help="Regenerate and print summary.md")
    sp.set_defaults(func=_cmd_summary)

    sp = sub.add_parser("paths", help="Print resolved configuration paths")
    sp.set_defaults(func=_cmd_paths)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
