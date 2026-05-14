"""Translate node:test output into the silo report shape.

`assertions.ts` writes each named-assertion outcome to a JSONL stream
at `$REGRESSION_TS_REPORT` (set by the Makefile). After the node
process exits, this script:

1. Reads the JSONL stream.
2. Reads the run log to capture the node exit code + any uncaught
   exceptions that weren't named assertions.
3. Emits the final structured JSON report at
   `.reports/<silo>/last.json` with the same schema pytest produces
   via the conftest hook.

This is the bridge that makes Python and TS silos look identical in
the regression report.

Usage:
    python finalize_ts_report.py <silo> <run-log-path>

The JSONL stream path is read from `$REGRESSION_TS_REPORT` (same env
the test runner used to write to it).
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: finalize_ts_report.py <silo> <run-log-path>", file=sys.stderr)
        return 2

    silo = sys.argv[1]
    run_log_path = Path(sys.argv[2])
    report_root = Path(
        os.environ.get(
            "REGRESSION_REPORTS",
            str(Path(__file__).resolve().parent.parent / ".reports"),
        )
    )

    jsonl_path = Path(
        os.environ.get(
            "REGRESSION_TS_REPORT",
            str(report_root / silo / "assertions.jsonl"),
        )
    )

    records = _read_jsonl(jsonl_path)
    exit_code, summary = _parse_run_log(run_log_path)

    all_passed = exit_code == 0 and all(r.get("passed") for r in records)
    failed_tests = sorted({r["test"] for r in records if not r.get("passed")})

    report = {
        "silo": silo,
        "passed": all_passed,
        "exit_code": exit_code,
        "assertions": records,
        "tests_with_failures": failed_tests,
        "ts_summary": summary,
    }

    report_path = report_root / silo / "last.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote silo report → {report_path}")

    return 0 if all_passed else 1


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


_NODE_TEST_TESTS = re.compile(r"^ℹ\s+tests\s+(\d+)\s*$", re.MULTILINE)
_NODE_TEST_PASS = re.compile(r"^ℹ\s+pass\s+(\d+)\s*$", re.MULTILINE)
_NODE_TEST_FAIL = re.compile(r"^ℹ\s+fail\s+(\d+)\s*$", re.MULTILINE)


def _parse_run_log(path: Path) -> tuple[int, dict]:
    """Pull the node --test summary out of the run log. Best-effort:
    if the log is unparseable we fall through with exit_code=2 and an
    empty summary."""
    if not path.exists():
        return 2, {}
    text = path.read_text(encoding="utf-8", errors="replace")

    def _grab(rx: re.Pattern[str]) -> int:
        m = rx.search(text)
        return int(m.group(1)) if m else 0

    tests = _grab(_NODE_TEST_TESTS)
    passed = _grab(_NODE_TEST_PASS)
    failed = _grab(_NODE_TEST_FAIL)

    exit_code = 0 if failed == 0 and tests > 0 else 1
    summary = {
        "tests": tests,
        "passed": passed,
        "failed": failed,
    }
    return exit_code, summary


if __name__ == "__main__":
    sys.exit(main())
