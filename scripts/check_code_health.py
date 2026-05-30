#!/usr/bin/env python3
"""Ratchet check for the code-health line-count budget.

Reads ``.code-health-budget.json`` and the live source tree (via
``scripts/code_health.py``) and fails if any file has grown past its
allowance. Two gates:

  (a) GRANDFATHERED files (those listed in the budget) may not EXCEED their
      recorded ceiling. They are free to shrink.
  (b) NEW / unlisted source files may not exceed ``global_ceiling``.

The rule is one-directional: files may only shrink. When a refactor brings a
listed file below its recorded budget, run this script with ``--update`` to
lower the budget to the new (smaller) value and commit the result. The check
never raises a budget automatically -- growth is always a human decision.

Exit codes:
  0  every file within budget (CI green)
  1  one or more violations
  2  budget file missing or malformed, or it references a path that no
     longer exists (stale entry)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUDGET_PATH = ROOT / ".code-health-budget.json"

# Import the scanner the report uses, so both agree exactly on which files
# count and how lines are counted.
sys.path.insert(0, str(ROOT / "scripts"))
import code_health  # noqa: E402


def load_budget() -> dict:
    if not BUDGET_PATH.exists():
        print(f"::error::budget file not found: {BUDGET_PATH}", file=sys.stderr)
        raise SystemExit(2)
    data = json.loads(BUDGET_PATH.read_text(encoding="utf-8"))
    if "global_ceiling" not in data or "files" not in data:
        print(
            "::error::budget file must contain 'global_ceiling' and 'files'",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return data


def current_line_counts() -> dict[str, int]:
    return {r.path: r.raw_lines for r in code_health.build_reports()}


def run_check(update: bool) -> int:
    budget = load_budget()
    ceiling = int(budget["global_ceiling"])
    listed: dict[str, int] = {k: int(v) for k, v in budget["files"].items()}
    live = current_line_counts()

    grew: list[tuple[str, int, int]] = []  # path, current, allowed
    new_over: list[tuple[str, int]] = []  # path, current
    stale: list[str] = []
    shrunk: list[tuple[str, int, int]] = []  # path, old, new

    for path, allowed in listed.items():
        if path not in live:
            stale.append(path)
            continue
        cur = live[path]
        if cur > allowed:
            grew.append((path, cur, allowed))
        elif cur < allowed:
            shrunk.append((path, allowed, cur))

    for path, cur in live.items():
        if path in listed:
            continue
        if cur > ceiling:
            new_over.append((path, cur))

    # --update: ratchet listed budgets DOWN to current (shrink only).
    if update and shrunk:
        for path, _old, new in shrunk:
            listed[path] = new
        ordered = dict(sorted(listed.items(), key=lambda kv: (-kv[1], kv[0])))
        budget["files"] = ordered
        BUDGET_PATH.write_text(json.dumps(budget, indent=2) + "\n", encoding="utf-8")
        print(
            f"Lowered {len(shrunk)} budget(s) to match shrunken files. "
            "Commit .code-health-budget.json.",
        )

    ok = not grew and not new_over and not stale

    if shrunk and not update:
        print("Files now BELOW budget (run with --update to ratchet down):")
        for path, old, new in sorted(shrunk, key=lambda t: t[1] - t[2], reverse=True):
            print(f"  {path}: {old} -> {new} (-{old - new})")
        print()

    if stale:
        print("::error::budget references files that no longer exist (remove them):")
        for path in stale:
            print(f"  {path}")
        print()

    if grew:
        print("::error::files exceeded their recorded code-health budget:")
        for path, cur, allowed in sorted(grew, key=lambda t: t[1] - t[2], reverse=True):
            print(f"  {path}: {cur} > {allowed} (+{cur - allowed} over budget)")
        print()

    if new_over:
        print(
            f"::error::new/unlisted files exceed the global ceiling ({ceiling} lines):"
        )
        for path, cur in sorted(new_over, key=lambda t: t[1], reverse=True):
            print(f"  {path}: {cur} > {ceiling}")
        print()

    if ok:
        print(
            f"code-health budget OK: {len(listed)} grandfathered file(s) within "
            f"budget; no new file over the {ceiling}-line ceiling."
        )
        return 0

    print(
        "code-health budget FAILED. Files may only shrink; no file may grow. "
        "Refactor the offending file(s), or -- if a listed file shrank -- run "
        "`python scripts/check_code_health.py --update` and commit the lowered "
        "budget. See docs/CODE_HEALTH.md."
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="lower listed budgets to match files that have shrunk, then write "
        "the budget file (never raises a budget)",
    )
    args = parser.parse_args(argv)
    return run_check(update=args.update)


if __name__ == "__main__":
    raise SystemExit(main())
