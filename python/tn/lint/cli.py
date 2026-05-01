"""Command-line entry point for tn.lint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from tn.lint.config import ConfigError, load_config
from tn.lint.engine import lint_paths
from tn.lint.findings import Finding
from tn.lint.rules import ALL_RULES, select_rules


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tn.lint",
        description="Static analyzer for the TN logging protocol.",
    )
    p.add_argument(
        "paths",
        nargs="*",
        default=["."],
        metavar="PATH",
        help="Files or directories to lint (default: '.').",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to tn.yaml. Default: search up from cwd.",
    )
    p.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Emit a JSON array of findings instead of human text.",
    )
    p.add_argument(
        "--no-extends",
        dest="use_extends",
        action="store_false",
        help="Ignore the extends: list in tn.yaml.",
    )
    p.add_argument(
        "--rules",
        type=str,
        default=None,
        help=(
            "Comma-separated rule ids to run (default: all). "
            f"Available: {','.join(r.id for r in ALL_RULES)}."
        ),
    )
    return p


def _emit_human(findings: Sequence[Finding]) -> str:
    return "\n".join(f.format_human() for f in findings)


def _emit_json(findings: Sequence[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    rule_ids = None
    if args.rules:
        rule_ids = [x for x in args.rules.split(",") if x.strip()]
    rules = select_rules(rule_ids)

    try:
        cfg = load_config(
            args.config,
            cwd=Path.cwd(),
            use_extends=args.use_extends,
        )
    except ConfigError as exc:
        msg = f"tn.lint: config error: {exc}"
        if args.emit_json:
            sys.stdout.write(
                json.dumps({"error": str(exc), "kind": "config"}, indent=2)
            )
            sys.stdout.write("\n")
        else:
            sys.stderr.write(msg + "\n")
        return 2

    paths = [Path(p) for p in args.paths]
    relative_to = cfg.config_path.parent
    findings = lint_paths(paths, cfg, rules, relative_to=relative_to)

    if args.emit_json:
        sys.stdout.write(_emit_json(findings))
        sys.stdout.write("\n")
    else:
        if findings:
            sys.stdout.write(_emit_human(findings) + "\n")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
