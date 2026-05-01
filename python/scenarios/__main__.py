"""CLI entry point: python -m scenarios [...]"""

from __future__ import annotations

import argparse
import datetime as dt
import secrets
import sys
from pathlib import Path

from scenarios._harness.env import load_repo_env
from scenarios._harness.registry import discover_all, filter_scenarios
from scenarios._harness.scenario import run_scenario


def default_runid() -> str:
    now = dt.datetime.now()
    return now.strftime("%Y-%m-%d-%H-%M-") + secrets.token_hex(4)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scenarios",
        description="Run TN persona-driven E2E + performance scenarios.",
    )
    parser.add_argument("--persona", default="", help="comma-separated persona list")
    parser.add_argument("--tag", default="", help="comma-separated tag list (OR match)")
    parser.add_argument("--only", default="", help="single scenario: <persona>/<name>")
    parser.add_argument("--runid", default=None, help="override runid")
    parser.add_argument("--list", action="store_true", help="list discovered scenarios and exit")
    parser.add_argument("--results-root", default=None, help="override bench/results location")
    args = parser.parse_args(argv)

    load_repo_env()

    all_sc = discover_all()
    if args.list:
        for s in sorted(all_sc, key=lambda x: (x.persona, x.name)):
            tags = ",".join(sorted(s.tags))
            print(f"{s.persona}/{s.name}  tags={tags}  vault={s.needs_vault}")
        return 0

    selected = filter_scenarios(
        all_sc,
        personas=[p for p in args.persona.split(",") if p] or None,
        tags=[t for t in args.tag.split(",") if t] or None,
        only=args.only or None,
    )
    if not selected:
        print("No scenarios selected.")
        return 0

    runid = args.runid or default_runid()
    here = Path(__file__).resolve().parent.parent
    results_root = Path(args.results_root) if args.results_root else here / "bench" / "results"
    results_root.mkdir(parents=True, exist_ok=True)
    (results_root / runid).mkdir(parents=True, exist_ok=True)

    # Lazy-import vault factory so local-only runs don't touch tnproto-org
    vault_factory = None
    if any(s.needs_vault for s in selected):
        from scenarios._harness.vault import vault_fixture

        vault_factory = vault_fixture

    print(f"runid={runid}  scenarios={len(selected)}")
    for sc in selected:
        res = run_scenario(sc, results_root=results_root, runid=runid, vault_factory=vault_factory)
        flag = "OK" if res.status == "ok" else "ERR"
        print(f"  [{flag}] {sc.persona}/{sc.name}")

    print(f"Results: {results_root / runid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
